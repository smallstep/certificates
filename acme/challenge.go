package acme

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-tpm/legacy/tpm2"

	"github.com/smallstep/go-attestation/attest"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/x509util"

	"github.com/smallstep/certificates/acme/wire"
	"github.com/smallstep/certificates/authority/provisioner"
	wireprovisioner "github.com/smallstep/certificates/authority/provisioner/wire"
	"github.com/smallstep/certificates/internal/cast"
)

type ChallengeType string

const (
	// HTTP01 is the http-01 ACME challenge type
	HTTP01 ChallengeType = "http-01"
	// DNS01 is the dns-01 ACME challenge type
	DNS01 ChallengeType = "dns-01"
	// TLSALPN01 is the tls-alpn-01 ACME challenge type
	TLSALPN01 ChallengeType = "tls-alpn-01"
	// DEVICEATTEST01 is the device-attest-01 ACME challenge type
	DEVICEATTEST01 ChallengeType = "device-attest-01"
	// WIREOIDC01 is the Wire OIDC challenge type
	WIREOIDC01 ChallengeType = "wire-oidc-01"
	// WIREDPOP01 is the Wire DPoP challenge type
	WIREDPOP01 ChallengeType = "wire-dpop-01"
)

var (
	// InsecurePortHTTP01 is the port used to verify http-01 challenges. If not set it
	// defaults to 80.
	InsecurePortHTTP01 int

	// InsecurePortTLSALPN01 is the port used to verify tls-alpn-01 challenges. If not
	// set it defaults to 443.
	//
	// This variable can be used for testing purposes.
	InsecurePortTLSALPN01 int

	// StrictFQDN allows to enforce a fully qualified domain name in the DNS
	// resolution. By default it allows domain resolution using a search list
	// defined in the resolv.conf or similar configuration.
	StrictFQDN bool
)

// Challenge represents an ACME response Challenge type.
type Challenge struct {
	ID              string        `json:"-"`
	AccountID       string        `json:"-"`
	AuthorizationID string        `json:"-"`
	Value           string        `json:"-"`
	Type            ChallengeType `json:"type"`
	Status          Status        `json:"status"`
	Token           string        `json:"token"`
	ValidatedAt     string        `json:"validated,omitempty"`
	URL             string        `json:"url"`
	Target          string        `json:"target,omitempty"`
	Error           *Error        `json:"error,omitempty"`
	Payload         []byte        `json:"-"`
	PayloadFormat   string        `json:"-"`
}

// ToLog enables response logging.
func (ch *Challenge) ToLog() (interface{}, error) {
	b, err := json.Marshal(ch)
	if err != nil {
		return nil, WrapErrorISE(err, "error marshaling challenge for logging")
	}
	return string(b), nil
}

// Validate attempts to validate the Challenge. Stores changes to the Challenge
// type using the DB interface. If the Challenge is validated, the 'status' and
// 'validated' attributes are updated.
func (ch *Challenge) Validate(ctx context.Context, db DB, jwk *jose.JSONWebKey, payload []byte) error {
	// If already valid or invalid then return without performing validation.
	if ch.Status != StatusPending {
		return nil
	}
	switch ch.Type {
	case HTTP01:
		return http01Validate(ctx, ch, db, jwk)
	case DNS01:
		return dns01Validate(ctx, ch, db, jwk)
	case TLSALPN01:
		return tlsalpn01Validate(ctx, ch, db, jwk)
	case DEVICEATTEST01:
		return deviceAttest01Validate(ctx, ch, db, jwk, payload)
	case WIREOIDC01:
		wireDB, ok := db.(WireDB)
		if !ok {
			return NewErrorISE("db %T is not a WireDB", db)
		}
		return wireOIDC01Validate(ctx, ch, wireDB, jwk, payload)
	case WIREDPOP01:
		wireDB, ok := db.(WireDB)
		if !ok {
			return NewErrorISE("db %T is not a WireDB", db)
		}
		return wireDPOP01Validate(ctx, ch, wireDB, jwk, payload)
	default:
		return NewErrorISE("unexpected challenge type %q", ch.Type)
	}
}

func http01Validate(ctx context.Context, ch *Challenge, db DB, jwk *jose.JSONWebKey) error {
	u := &url.URL{Scheme: "http", Host: ch.Value, Path: fmt.Sprintf("/.well-known/acme-challenge/%s", ch.Token)}
	challengeURL := &url.URL{Scheme: "http", Host: http01ChallengeHost(ch.Value), Path: fmt.Sprintf("/.well-known/acme-challenge/%s", ch.Token)}

	// Append insecure port if set.
	// Only used for testing purposes.
	if InsecurePortHTTP01 != 0 {
		insecurePort := strconv.Itoa(InsecurePortHTTP01)
		u.Host += ":" + insecurePort
		challengeURL.Host += ":" + insecurePort
	}

	vc := MustClientFromContext(ctx)
	resp, err := vc.Get(challengeURL.String())
	if err != nil {
		return storeError(ctx, db, ch, false, WrapError(ErrorConnectionType, err,
			"error doing http GET for url %s", u))
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return storeError(ctx, db, ch, false, NewError(ErrorConnectionType,
			"error doing http GET for url %s with status code %d", u, resp.StatusCode))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return WrapErrorISE(err, "error reading "+
			"response body for url %s", u)
	}
	keyAuth := strings.TrimSpace(string(body))

	expected, err := KeyAuthorization(ch.Token, jwk)
	if err != nil {
		return err
	}
	if keyAuth != expected {
		return storeError(ctx, db, ch, true, NewError(ErrorRejectedIdentifierType,
			"keyAuthorization does not match; expected %s, but got %s", expected, keyAuth))
	}

	// Update and store the challenge.
	ch.Status = StatusValid
	ch.Error = nil
	ch.ValidatedAt = clock.Now().Format(time.RFC3339)

	if err = db.UpdateChallenge(ctx, ch); err != nil {
		return WrapErrorISE(err, "error updating challenge")
	}
	return nil
}

// rootedName adds a trailing "." to a given domain name.
func rootedName(name string) string {
	if StrictFQDN {
		if name == "" || name[len(name)-1] != '.' {
			return name + "."
		}
	}
	return name
}

// http01ChallengeHost checks if a Challenge value is an IPv6 address
// and adds square brackets if that's the case, so that it can be used
// as a hostname. Returns the original Challenge value as the host to
// use in other cases.
func http01ChallengeHost(value string) string {
	if ip := net.ParseIP(value); ip != nil {
		if ip.To4() == nil {
			value = "[" + value + "]"
		}
		return value
	}
	return rootedName(value)
}

// tlsAlpn01ChallengeHost returns the rooted DNS used on TLS-ALPN-01
// validations.
func tlsAlpn01ChallengeHost(name string) string {
	if ip := net.ParseIP(name); ip != nil {
		return name
	}
	return rootedName(name)
}

// dns01ChallengeHost returns the TXT record used in DNS-01 validations.
func dns01ChallengeHost(domain string) string {
	return "_acme-challenge." + rootedName(domain)
}

func tlsAlert(err error) uint8 {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		v := reflect.ValueOf(opErr.Err)
		if v.Kind() == reflect.Uint8 {
			return cast.Uint8(v.Uint())
		}
	}
	return 0
}

func tlsalpn01Validate(ctx context.Context, ch *Challenge, db DB, jwk *jose.JSONWebKey) error {
	config := &tls.Config{
		NextProtos: []string{"acme-tls/1"},
		// https://tools.ietf.org/html/rfc8737#section-4
		// ACME servers that implement "acme-tls/1" MUST only negotiate TLS 1.2
		// [RFC5246] or higher when connecting to clients for validation.
		MinVersion:         tls.VersionTLS12,
		ServerName:         serverName(ch),
		InsecureSkipVerify: true, //nolint:gosec // we expect a self-signed challenge certificate
	}

	// Allow to change TLS port for testing purposes.
	hostPort := tlsAlpn01ChallengeHost(ch.Value)
	if port := InsecurePortTLSALPN01; port == 0 {
		hostPort = net.JoinHostPort(hostPort, "443")
	} else {
		hostPort = net.JoinHostPort(hostPort, strconv.Itoa(port))
	}

	vc := MustClientFromContext(ctx)
	conn, err := vc.TLSDial("tcp", hostPort, config)
	if err != nil {
		// With Go 1.17+ tls.Dial fails if there's no overlap between configured
		// client and server protocols. When this happens the connection is
		// closed with the error no_application_protocol(120) as required by
		// RFC7301. See https://golang.org/doc/go1.17#ALPN
		if tlsAlert(err) == 120 {
			return storeError(ctx, db, ch, true, NewError(ErrorRejectedIdentifierType,
				"cannot negotiate ALPN acme-tls/1 protocol for tls-alpn-01 challenge"))
		}
		return storeError(ctx, db, ch, false, WrapError(ErrorConnectionType, err,
			"error doing TLS dial for %s", ch.Value))
	}
	defer conn.Close()

	cs := conn.ConnectionState()
	certs := cs.PeerCertificates

	if len(certs) == 0 {
		return storeError(ctx, db, ch, true, NewError(ErrorRejectedIdentifierType,
			"%s challenge for %s resulted in no certificates", ch.Type, ch.Value))
	}

	if cs.NegotiatedProtocol != "acme-tls/1" {
		return storeError(ctx, db, ch, true, NewError(ErrorRejectedIdentifierType,
			"cannot negotiate ALPN acme-tls/1 protocol for tls-alpn-01 challenge"))
	}

	leafCert := certs[0]

	// if no DNS names present, look for IP address and verify that exactly one exists
	if len(leafCert.DNSNames) == 0 {
		if len(leafCert.IPAddresses) != 1 || !leafCert.IPAddresses[0].Equal(net.ParseIP(ch.Value)) {
			return storeError(ctx, db, ch, true, NewError(ErrorRejectedIdentifierType,
				"incorrect certificate for tls-alpn-01 challenge: leaf certificate must contain a single IP address or DNS name, %v", ch.Value))
		}
	} else {
		if len(leafCert.DNSNames) != 1 || !strings.EqualFold(leafCert.DNSNames[0], ch.Value) {
			return storeError(ctx, db, ch, true, NewError(ErrorRejectedIdentifierType,
				"incorrect certificate for tls-alpn-01 challenge: leaf certificate must contain a single IP address or DNS name, %v", ch.Value))
		}
	}

	idPeAcmeIdentifier := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}
	idPeAcmeIdentifierV1Obsolete := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 30, 1}
	foundIDPeAcmeIdentifierV1Obsolete := false

	keyAuth, err := KeyAuthorization(ch.Token, jwk)
	if err != nil {
		return err
	}
	hashedKeyAuth := sha256.Sum256([]byte(keyAuth))

	for _, ext := range leafCert.Extensions {
		if idPeAcmeIdentifier.Equal(ext.Id) {
			if !ext.Critical {
				return storeError(ctx, db, ch, true, NewError(ErrorRejectedIdentifierType,
					"incorrect certificate for tls-alpn-01 challenge: acmeValidationV1 extension not critical"))
			}

			var extValue []byte
			rest, err := asn1.Unmarshal(ext.Value, &extValue)

			if err != nil || len(rest) > 0 || len(hashedKeyAuth) != len(extValue) {
				return storeError(ctx, db, ch, true, NewError(ErrorRejectedIdentifierType,
					"incorrect certificate for tls-alpn-01 challenge: malformed acmeValidationV1 extension value"))
			}

			if subtle.ConstantTimeCompare(hashedKeyAuth[:], extValue) != 1 {
				return storeError(ctx, db, ch, true, NewError(ErrorRejectedIdentifierType,
					"incorrect certificate for tls-alpn-01 challenge: "+
						"expected acmeValidationV1 extension value %s for this challenge but got %s",
					hex.EncodeToString(hashedKeyAuth[:]), hex.EncodeToString(extValue)))
			}

			ch.Status = StatusValid
			ch.Error = nil
			ch.ValidatedAt = clock.Now().Format(time.RFC3339)

			if err = db.UpdateChallenge(ctx, ch); err != nil {
				return WrapErrorISE(err, "tlsalpn01ValidateChallenge - error updating challenge")
			}
			return nil
		}

		if idPeAcmeIdentifierV1Obsolete.Equal(ext.Id) {
			foundIDPeAcmeIdentifierV1Obsolete = true
		}
	}

	if foundIDPeAcmeIdentifierV1Obsolete {
		return storeError(ctx, db, ch, true, NewError(ErrorRejectedIdentifierType,
			"incorrect certificate for tls-alpn-01 challenge: obsolete id-pe-acmeIdentifier in acmeValidationV1 extension"))
	}

	return storeError(ctx, db, ch, true, NewError(ErrorRejectedIdentifierType,
		"incorrect certificate for tls-alpn-01 challenge: missing acmeValidationV1 extension"))
}

func dns01Validate(ctx context.Context, ch *Challenge, db DB, jwk *jose.JSONWebKey) error {
	// Normalize domain for wildcard DNS names
	// This is done to avoid making TXT lookups for domains like
	// _acme-challenge.*.example.com
	// Instead perform txt lookup for _acme-challenge.example.com
	domain := strings.TrimPrefix(ch.Value, "*.")

	vc := MustClientFromContext(ctx)
	txtRecords, err := vc.LookupTxt(dns01ChallengeHost(domain))
	if err != nil {
		return storeError(ctx, db, ch, false, WrapError(ErrorDNSType, err,
			"error looking up TXT records for domain %s", domain))
	}

	expectedKeyAuth, err := KeyAuthorization(ch.Token, jwk)
	if err != nil {
		return err
	}
	h := sha256.Sum256([]byte(expectedKeyAuth))
	expected := base64.RawURLEncoding.EncodeToString(h[:])
	var found bool
	for _, r := range txtRecords {
		if r == expected {
			found = true
			break
		}
	}
	if !found {
		return storeError(ctx, db, ch, false, NewError(ErrorRejectedIdentifierType,
			"keyAuthorization does not match; expected %s, but got %s", expectedKeyAuth, txtRecords))
	}

	// Update and store the challenge.
	ch.Status = StatusValid
	ch.Error = nil
	ch.ValidatedAt = clock.Now().Format(time.RFC3339)

	if err = db.UpdateChallenge(ctx, ch); err != nil {
		return WrapErrorISE(err, "error updating challenge")
	}
	return nil
}

type wireOidcPayload struct {
	// IDToken contains the OIDC identity token
	IDToken string `json:"id_token"`
}

func wireOIDC01Validate(ctx context.Context, ch *Challenge, db WireDB, jwk *jose.JSONWebKey, payload []byte) error {
	prov, ok := ProvisionerFromContext(ctx)
	if !ok {
		return NewErrorISE("missing provisioner")
	}
	wireOptions, err := prov.GetOptions().GetWireOptions()
	if err != nil {
		return WrapErrorISE(err, "failed getting Wire options")
	}
	linker, ok := LinkerFromContext(ctx)
	if !ok {
		return NewErrorISE("missing linker")
	}

	var oidcPayload wireOidcPayload
	if err := json.Unmarshal(payload, &oidcPayload); err != nil {
		return WrapError(ErrorMalformedType, err, "error unmarshalling Wire OIDC challenge payload")
	}

	wireID, err := wire.ParseUserID(ch.Value)
	if err != nil {
		return WrapErrorISE(err, "error unmarshalling challenge data")
	}

	oidcOptions := wireOptions.GetOIDCOptions()
	verifier, err := oidcOptions.GetVerifier(ctx)
	if err != nil {
		return WrapErrorISE(err, "no OIDC verifier available")
	}

	idToken, err := verifier.Verify(ctx, oidcPayload.IDToken)
	if err != nil {
		return storeError(ctx, db, ch, true, WrapError(ErrorRejectedIdentifierType, err,
			"error verifying ID token signature"))
	}

	var claims struct {
		Name         string `json:"preferred_username,omitempty"`
		Handle       string `json:"name"`
		Issuer       string `json:"iss,omitempty"`
		GivenName    string `json:"given_name,omitempty"`
		KeyAuth      string `json:"keyauth"`
		ACMEAudience string `json:"acme_aud,omitempty"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return storeError(ctx, db, ch, true, WrapError(ErrorRejectedIdentifierType, err,
			"error retrieving claims from ID token"))
	}

	// TODO(hs): move this into validation below?
	expectedKeyAuth, err := KeyAuthorization(ch.Token, jwk)
	if err != nil {
		return WrapErrorISE(err, "error determining key authorization")
	}
	if expectedKeyAuth != claims.KeyAuth {
		return storeError(ctx, db, ch, true, NewError(ErrorRejectedIdentifierType,
			"keyAuthorization does not match; expected %q, but got %q", expectedKeyAuth, claims.KeyAuth))
	}

	// audience is the full URL to the challenge
	acmeAudience := linker.GetLink(ctx, ChallengeLinkType, ch.AuthorizationID, ch.ID)
	if claims.ACMEAudience != acmeAudience {
		return storeError(ctx, db, ch, true, NewError(ErrorRejectedIdentifierType,
			"invalid 'acme_aud' %q", claims.ACMEAudience))
	}

	transformedIDToken, err := validateWireOIDCClaims(oidcOptions, idToken, wireID)
	if err != nil {
		return storeError(ctx, db, ch, true, WrapError(ErrorRejectedIdentifierType, err, "claims in OIDC ID token don't match"))
	}

	// Update and store the challenge.
	ch.Status = StatusValid
	ch.Error = nil
	ch.ValidatedAt = clock.Now().Format(time.RFC3339)

	if err = db.UpdateChallenge(ctx, ch); err != nil {
		return WrapErrorISE(err, "error updating challenge")
	}

	orders, err := db.GetAllOrdersByAccountID(ctx, ch.AccountID)
	if err != nil {
		return WrapErrorISE(err, "could not retrieve current order by account id")
	}
	if len(orders) == 0 {
		return NewErrorISE("there are not enough orders for this account for this custom OIDC challenge")
	}

	order := orders[len(orders)-1]
	if err := db.CreateOidcToken(ctx, order, transformedIDToken); err != nil {
		return WrapErrorISE(err, "failed storing OIDC id token")
	}

	return nil
}

func validateWireOIDCClaims(o *wireprovisioner.OIDCOptions, token *oidc.IDToken, wireID wire.UserID) (map[string]any, error) {
	var m map[string]any
	if err := token.Claims(&m); err != nil {
		return nil, fmt.Errorf("failed extracting OIDC ID token claims: %w", err)
	}
	transformed, err := o.Transform(m)
	if err != nil {
		return nil, fmt.Errorf("failed transforming OIDC ID token: %w", err)
	}

	name, ok := transformed["name"]
	if !ok {
		return nil, fmt.Errorf("transformed OIDC ID token does not contain 'name'")
	}
	if wireID.Name != name {
		return nil, fmt.Errorf("invalid 'name' %q after transformation", name)
	}

	preferredUsername, ok := transformed["preferred_username"]
	if !ok {
		return nil, fmt.Errorf("transformed OIDC ID token does not contain 'preferred_username'")
	}
	if wireID.Handle != preferredUsername {
		return nil, fmt.Errorf("invalid 'preferred_username' %q after transformation", preferredUsername)
	}

	return transformed, nil
}

type wireDpopPayload struct {
	// AccessToken is the token generated by wire-server
	AccessToken string `json:"access_token"`
}

func wireDPOP01Validate(ctx context.Context, ch *Challenge, db WireDB, accountJWK *jose.JSONWebKey, payload []byte) error {
	prov, ok := ProvisionerFromContext(ctx)
	if !ok {
		return NewErrorISE("missing provisioner")
	}
	wireOptions, err := prov.GetOptions().GetWireOptions()
	if err != nil {
		return WrapErrorISE(err, "failed getting Wire options")
	}
	linker, ok := LinkerFromContext(ctx)
	if !ok {
		return NewErrorISE("missing linker")
	}

	var dpopPayload wireDpopPayload
	if err := json.Unmarshal(payload, &dpopPayload); err != nil {
		return WrapError(ErrorMalformedType, err, "error unmarshalling Wire DPoP challenge payload")
	}

	wireID, err := wire.ParseDeviceID(ch.Value)
	if err != nil {
		return WrapErrorISE(err, "error unmarshalling challenge data")
	}

	clientID, err := wire.ParseClientID(wireID.ClientID)
	if err != nil {
		return WrapErrorISE(err, "error parsing device id")
	}

	dpopOptions := wireOptions.GetDPOPOptions()
	issuer, err := dpopOptions.EvaluateTarget(clientID.DeviceID)
	if err != nil {
		return WrapErrorISE(err, "invalid Go template registered for 'target'")
	}

	// audience is the full URL to the challenge
	audience := linker.GetLink(ctx, ChallengeLinkType, ch.AuthorizationID, ch.ID)

	params := wireVerifyParams{
		token:     dpopPayload.AccessToken,
		tokenKey:  dpopOptions.GetSigningKey(),
		dpopKey:   accountJWK.Public(),
		dpopKeyID: accountJWK.KeyID,
		issuer:    issuer,
		audience:  audience,
		wireID:    wireID,
		chToken:   ch.Token,
		t:         clock.Now().UTC(),
	}
	_, dpop, err := parseAndVerifyWireAccessToken(params)
	if err != nil {
		return storeError(ctx, db, ch, true, WrapError(ErrorRejectedIdentifierType, err,
			"failed validating Wire access token"))
	}

	// Update and store the challenge.
	ch.Status = StatusValid
	ch.Error = nil
	ch.ValidatedAt = clock.Now().Format(time.RFC3339)

	if err = db.UpdateChallenge(ctx, ch); err != nil {
		return WrapErrorISE(err, "error updating challenge")
	}

	orders, err := db.GetAllOrdersByAccountID(ctx, ch.AccountID)
	if err != nil {
		return WrapErrorISE(err, "could not find current order by account id")
	}
	if len(orders) == 0 {
		return NewErrorISE("there are not enough orders for this account for this custom OIDC challenge")
	}

	order := orders[len(orders)-1]
	if err := db.CreateDpopToken(ctx, order, map[string]any(*dpop)); err != nil {
		return WrapErrorISE(err, "failed storing DPoP token")
	}

	return nil
}

type wireCnf struct {
	Kid string `json:"kid"`
}

type wireAccessToken struct {
	jose.Claims
	Challenge  string  `json:"chal"`
	Nonce      string  `json:"nonce"`
	Cnf        wireCnf `json:"cnf"`
	Proof      string  `json:"proof"`
	ClientID   string  `json:"client_id"`
	APIVersion int     `json:"api_version"`
	Scope      string  `json:"scope"`
}

type wireDpopJwt struct {
	jose.Claims
	ClientID  string `json:"client_id"`
	Challenge string `json:"chal"`
	Nonce     string `json:"nonce"`
	HTU       string `json:"htu"`
}

type wireDpopToken map[string]any

type wireVerifyParams struct {
	token     string
	tokenKey  crypto.PublicKey
	dpopKey   crypto.PublicKey
	dpopKeyID string
	issuer    string
	audience  string
	wireID    wire.DeviceID
	chToken   string
	t         time.Time
}

func parseAndVerifyWireAccessToken(v wireVerifyParams) (*wireAccessToken, *wireDpopToken, error) {
	jwt, err := jose.ParseSigned(v.token)
	if err != nil {
		return nil, nil, fmt.Errorf("failed parsing token: %w", err)
	}

	if len(jwt.Headers) != 1 {
		return nil, nil, fmt.Errorf("token has wrong number of headers %d", len(jwt.Headers))
	}
	keyID, err := KeyToID(&jose.JSONWebKey{Key: v.tokenKey})
	if err != nil {
		return nil, nil, fmt.Errorf("failed calculating token key ID: %w", err)
	}
	jwtKeyID := jwt.Headers[0].KeyID
	if jwtKeyID == "" {
		if jwtKeyID, err = KeyToID(jwt.Headers[0].JSONWebKey); err != nil {
			return nil, nil, fmt.Errorf("failed extracting token key ID: %w", err)
		}
	}
	if jwtKeyID != keyID {
		return nil, nil, fmt.Errorf("invalid token key ID %q", jwtKeyID)
	}

	var accessToken wireAccessToken
	if err = jwt.Claims(v.tokenKey, &accessToken); err != nil {
		return nil, nil, fmt.Errorf("failed validating Wire DPoP token claims: %w", err)
	}

	if err := accessToken.ValidateWithLeeway(jose.Expected{
		Time:     v.t,
		Issuer:   v.issuer,
		Audience: jose.Audience{v.audience},
	}, 1*time.Minute); err != nil {
		return nil, nil, fmt.Errorf("failed validation: %w", err)
	}

	if accessToken.Challenge == "" {
		return nil, nil, errors.New("access token challenge 'chal' must not be empty")
	}
	if accessToken.Cnf.Kid == "" || accessToken.Cnf.Kid != v.dpopKeyID {
		return nil, nil, fmt.Errorf("expected 'kid' %q; got %q", v.dpopKeyID, accessToken.Cnf.Kid)
	}
	if accessToken.ClientID != v.wireID.ClientID {
		return nil, nil, fmt.Errorf("invalid Wire 'client_id' %q", accessToken.ClientID)
	}
	if accessToken.Expiry.Time().After(v.t.Add(time.Hour)) {
		return nil, nil, fmt.Errorf("token expiry 'exp' %s is too far into the future", accessToken.Expiry.Time().String())
	}
	if accessToken.Scope != "wire_client_id" {
		return nil, nil, fmt.Errorf("invalid Wire 'scope' %q", accessToken.Scope)
	}

	dpopJWT, err := jose.ParseSigned(accessToken.Proof)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid Wire DPoP token: %w", err)
	}
	if len(dpopJWT.Headers) != 1 {
		return nil, nil, fmt.Errorf("DPoP token has wrong number of headers %d", len(jwt.Headers))
	}
	dpopJwtKeyID := dpopJWT.Headers[0].KeyID
	if dpopJwtKeyID == "" {
		if dpopJwtKeyID, err = KeyToID(dpopJWT.Headers[0].JSONWebKey); err != nil {
			return nil, nil, fmt.Errorf("failed extracting DPoP token key ID: %w", err)
		}
	}
	if dpopJwtKeyID != v.dpopKeyID {
		return nil, nil, fmt.Errorf("invalid DPoP token key ID %q", dpopJWT.Headers[0].KeyID)
	}

	var wireDpop wireDpopJwt
	if err := dpopJWT.Claims(v.dpopKey, &wireDpop); err != nil {
		return nil, nil, fmt.Errorf("failed validating Wire DPoP token claims: %w", err)
	}

	if err := wireDpop.ValidateWithLeeway(jose.Expected{
		Time:     v.t,
		Audience: jose.Audience{v.audience},
	}, 1*time.Minute); err != nil {
		return nil, nil, fmt.Errorf("failed DPoP validation: %w", err)
	}
	if wireDpop.HTU == "" || wireDpop.HTU != v.issuer { // DPoP doesn't contains "iss" claim, but has it in the "htu" claim
		return nil, nil, fmt.Errorf("DPoP contains invalid issuer 'htu' %q", wireDpop.HTU)
	}
	if wireDpop.Expiry.Time().After(v.t.Add(time.Hour)) {
		return nil, nil, fmt.Errorf("'exp' %s is too far into the future", wireDpop.Expiry.Time().String())
	}
	if wireDpop.Subject != v.wireID.ClientID {
		return nil, nil, fmt.Errorf("DPoP contains invalid Wire client ID %q", wireDpop.ClientID)
	}
	if wireDpop.Nonce == "" || wireDpop.Nonce != accessToken.Nonce {
		return nil, nil, fmt.Errorf("DPoP contains invalid 'nonce' %q", wireDpop.Nonce)
	}
	if wireDpop.Challenge == "" || wireDpop.Challenge != accessToken.Challenge {
		return nil, nil, fmt.Errorf("DPoP contains invalid challenge 'chal' %q", wireDpop.Challenge)
	}

	// TODO(hs): can we use the wireDpopJwt and map that instead of doing Claims() twice?
	var dpopToken wireDpopToken
	if err := dpopJWT.Claims(v.dpopKey, &dpopToken); err != nil {
		return nil, nil, fmt.Errorf("failed validating Wire DPoP token claims: %w", err)
	}

	challenge, ok := dpopToken["chal"].(string)
	if !ok {
		return nil, nil, fmt.Errorf("invalid challenge 'chal' in Wire DPoP token")
	}
	if challenge == "" || challenge != v.chToken {
		return nil, nil, fmt.Errorf("invalid Wire DPoP challenge 'chal' %q", challenge)
	}

	handle, ok := dpopToken["handle"].(string)
	if !ok {
		return nil, nil, fmt.Errorf("invalid 'handle' in Wire DPoP token")
	}
	if handle == "" || handle != v.wireID.Handle {
		return nil, nil, fmt.Errorf("invalid Wire client 'handle' %q", handle)
	}

	name, ok := dpopToken["name"].(string)
	if !ok {
		return nil, nil, fmt.Errorf("invalid display 'name' in Wire DPoP token")
	}
	if name == "" || name != v.wireID.Name {
		return nil, nil, fmt.Errorf("invalid Wire client display 'name' %q", name)
	}

	return &accessToken, &dpopToken, nil
}

type payloadType struct {
	AttObj string `json:"attObj"`
	Error  string `json:"error"`
}

type attestationObject struct {
	Format       string                 `json:"fmt"`
	AttStatement map[string]interface{} `json:"attStmt,omitempty"`
}

// TODO(bweeks): move attestation verification to a shared package.
func deviceAttest01Validate(ctx context.Context, ch *Challenge, db DB, jwk *jose.JSONWebKey, payload []byte) error {
	// Update challenge with the payload
	ch.Payload = payload

	// Load authorization to store the key fingerprint.
	az, err := db.GetAuthorization(ctx, ch.AuthorizationID)
	if err != nil {
		return WrapErrorISE(err, "error loading authorization")
	}

	// Parse payload.
	var p payloadType
	if err := json.Unmarshal(payload, &p); err != nil {
		return WrapErrorISE(err, "error unmarshalling JSON")
	}
	if p.Error != "" {
		return storeError(ctx, db, ch, true, NewError(ErrorRejectedIdentifierType,
			"payload contained error: %v", p.Error))
	}

	attObj, err := base64.RawURLEncoding.DecodeString(p.AttObj)
	if err != nil {
		return storeError(ctx, db, ch, true, NewDetailedError(ErrorBadAttestationStatementType, "failed base64 decoding attObj %q", p.AttObj))
	}

	if len(attObj) == 0 || bytes.Equal(attObj, []byte("{}")) {
		return storeError(ctx, db, ch, true, NewDetailedError(ErrorBadAttestationStatementType, "attObj must not be empty"))
	}

	cborDecoderOptions := cbor.DecOptions{}
	cborDecoder, err := cborDecoderOptions.DecMode()
	if err != nil {
		return WrapErrorISE(err, "failed creating CBOR decoder")
	}

	if err := cborDecoder.Wellformed(attObj); err != nil {
		return storeError(ctx, db, ch, true, NewDetailedError(ErrorBadAttestationStatementType, "attObj is not well formed CBOR: %v", err))
	}

	att := attestationObject{}
	if err := cborDecoder.Unmarshal(attObj, &att); err != nil {
		return WrapErrorISE(err, "failed unmarshalling CBOR")
	}

	format := att.Format
	prov := MustProvisionerFromContext(ctx)
	if !prov.IsAttestationFormatEnabled(ctx, provisioner.ACMEAttestationFormat(format)) {
		if format != "apple" && format != "step" && format != "tpm" {
			return storeError(ctx, db, ch, true, NewDetailedError(ErrorBadAttestationStatementType, "unsupported attestation object format %q", format))
		}

		return storeError(ctx, db, ch, true,
			NewError(ErrorBadAttestationStatementType, "attestation format %q is not enabled", format))
	}

	switch format {
	case "apple":
		data, err := doAppleAttestationFormat(ctx, prov, ch, &att)
		if err != nil {
			var acmeError *Error
			if errors.As(err, &acmeError) {
				if acmeError.Status == 500 {
					return acmeError
				}
				return storeError(ctx, db, ch, true, acmeError)
			}
			return WrapErrorISE(err, "error validating attestation")
		}

		// Validate nonce with SHA-256 of the token.
		if len(data.Nonce) != 0 {
			sum := sha256.Sum256([]byte(ch.Token))
			if subtle.ConstantTimeCompare(data.Nonce, sum[:]) != 1 {
				return storeError(ctx, db, ch, true, NewDetailedError(ErrorBadAttestationStatementType, "challenge token does not match"))
			}
		}

		// Validate Apple's ClientIdentifier (Identifier.Value) with device
		// identifiers.
		//
		// Note: We might want to use an external service for this.
		if data.UDID != ch.Value && data.SerialNumber != ch.Value {
			subproblem := NewSubproblemWithIdentifier(
				ErrorRejectedIdentifierType,
				Identifier{Type: "permanent-identifier", Value: ch.Value},
				"challenge identifier %q doesn't match any of the attested hardware identifiers %q", ch.Value, []string{data.UDID, data.SerialNumber},
			)
			return storeError(ctx, db, ch, true, NewDetailedError(ErrorBadAttestationStatementType, "permanent identifier does not match").AddSubproblems(subproblem))
		}

		// Update attestation key fingerprint to compare against the CSR
		az.Fingerprint = data.Fingerprint
	case "step":
		data, err := doStepAttestationFormat(ctx, prov, ch, jwk, &att)
		if err != nil {
			var acmeError *Error
			if errors.As(err, &acmeError) {
				if acmeError.Status == 500 {
					return acmeError
				}
				return storeError(ctx, db, ch, true, acmeError)
			}
			return WrapErrorISE(err, "error validating attestation")
		}

		// Validate the YubiKey serial number from the attestation
		// certificate with the challenged Order value.
		//
		// Note: We might want to use an external service for this.
		if data.SerialNumber != ch.Value {
			subproblem := NewSubproblemWithIdentifier(
				ErrorRejectedIdentifierType,
				Identifier{Type: "permanent-identifier", Value: ch.Value},
				"challenge identifier %q doesn't match the attested hardware identifier %q", ch.Value, data.SerialNumber,
			)
			return storeError(ctx, db, ch, true, NewDetailedError(ErrorBadAttestationStatementType, "permanent identifier does not match").AddSubproblems(subproblem))
		}

		// Update attestation key fingerprint to compare against the CSR
		az.Fingerprint = data.Fingerprint

	case "tpm":
		data, err := doTPMAttestationFormat(ctx, prov, ch, jwk, &att)
		if err != nil {
			var acmeError *Error
			if errors.As(err, &acmeError) {
				if acmeError.Status == 500 {
					return acmeError
				}
				return storeError(ctx, db, ch, true, acmeError)
			}
			return WrapErrorISE(err, "error validating attestation")
		}

		// TODO(hs): currently this will allow a request for which no PermanentIdentifiers have been
		// extracted from the AK certificate. This is currently the case for AK certs from the CLI, as we
		// haven't implemented a way for AK certs requested by the CLI to always contain the requested
		// PermanentIdentifier. Omitting the check below doesn't allow just any request, as the Order can
		// still fail if the challenge value isn't equal to the CSR subject.
		if len(data.PermanentIdentifiers) > 0 && !slices.Contains(data.PermanentIdentifiers, ch.Value) { // TODO(hs): add support for HardwareModuleName
			subproblem := NewSubproblemWithIdentifier(
				ErrorRejectedIdentifierType,
				Identifier{Type: "permanent-identifier", Value: ch.Value},
				"challenge identifier %q doesn't match any of the attested hardware identifiers %q", ch.Value, data.PermanentIdentifiers,
			)
			return storeError(ctx, db, ch, true, NewDetailedError(ErrorBadAttestationStatementType, "permanent identifier does not match").AddSubproblems(subproblem))
		}

		// Update attestation key fingerprint to compare against the CSR
		az.Fingerprint = data.Fingerprint
	default:
		return storeError(ctx, db, ch, true, NewDetailedError(ErrorBadAttestationStatementType, "unsupported attestation object format %q", format))
	}

	// Update and store the challenge.
	ch.Status = StatusValid
	ch.Error = nil
	ch.ValidatedAt = clock.Now().Format(time.RFC3339)
	ch.PayloadFormat = format

	// Store the fingerprint in the authorization.
	//
	// TODO: add method to update authorization and challenge atomically.
	if az.Fingerprint != "" {
		if err := db.UpdateAuthorization(ctx, az); err != nil {
			return WrapErrorISE(err, "error updating authorization")
		}
	}

	if err := db.UpdateChallenge(ctx, ch); err != nil {
		return WrapErrorISE(err, "error updating challenge")
	}
	return nil
}

var (
	oidSubjectAlternativeName = asn1.ObjectIdentifier{2, 5, 29, 17}
)

type tpmAttestationData struct {
	Certificate          *x509.Certificate
	VerifiedChains       [][]*x509.Certificate
	PermanentIdentifiers []string
	Fingerprint          string
}

// coseAlgorithmIdentifier models a COSEAlgorithmIdentifier.
// Also see https://www.w3.org/TR/webauthn-2/#sctn-alg-identifier.
type coseAlgorithmIdentifier int32

const (
	coseAlgES256 = coseAlgorithmIdentifier(-7)
	coseAlgRS256 = coseAlgorithmIdentifier(-257)
	coseAlgRS1   = coseAlgorithmIdentifier(-65535) // deprecated, but (still) often used in TPMs
)

func doTPMAttestationFormat(_ context.Context, prov Provisioner, ch *Challenge, jwk *jose.JSONWebKey, att *attestationObject) (*tpmAttestationData, error) {
	ver, ok := att.AttStatement["ver"].(string)
	if !ok {
		return nil, NewDetailedError(ErrorBadAttestationStatementType, "ver not present")
	}
	if ver != "2.0" {
		return nil, NewDetailedError(ErrorBadAttestationStatementType, "version %q is not supported", ver)
	}

	x5c, ok := att.AttStatement["x5c"].([]interface{})
	if !ok {
		return nil, NewDetailedError(ErrorBadAttestationStatementType, "x5c not present")
	}
	if len(x5c) == 0 {
		return nil, NewDetailedError(ErrorBadAttestationStatementType, "x5c is empty")
	}

	akCertBytes, ok := x5c[0].([]byte)
	if !ok {
		return nil, NewDetailedError(ErrorBadAttestationStatementType, "x5c is malformed")
	}
	akCert, err := x509.ParseCertificate(akCertBytes)
	if err != nil {
		return nil, WrapDetailedError(ErrorBadAttestationStatementType, err, "x5c is malformed")
	}

	intermediates := x509.NewCertPool()
	for _, v := range x5c[1:] {
		intCertBytes, vok := v.([]byte)
		if !vok {
			return nil, NewDetailedError(ErrorBadAttestationStatementType, "x5c is malformed")
		}
		intCert, err := x509.ParseCertificate(intCertBytes)
		if err != nil {
			return nil, WrapDetailedError(ErrorBadAttestationStatementType, err, "x5c is malformed")
		}
		intermediates.AddCert(intCert)
	}

	// TODO(hs): this can be removed when permanent-identifier/hardware-module-name are handled correctly in
	// the stdlib in https://cs.opensource.google/go/go/+/refs/tags/go1.19:src/crypto/x509/parser.go;drc=b5b2cf519fe332891c165077f3723ee74932a647;l=362,
	// but I doubt that will happen.
	if len(akCert.UnhandledCriticalExtensions) > 0 {
		unhandledCriticalExtensions := akCert.UnhandledCriticalExtensions[:0]
		for _, extOID := range akCert.UnhandledCriticalExtensions {
			if !extOID.Equal(oidSubjectAlternativeName) {
				// critical extensions other than the Subject Alternative Name remain unhandled
				unhandledCriticalExtensions = append(unhandledCriticalExtensions, extOID)
			}
		}
		akCert.UnhandledCriticalExtensions = unhandledCriticalExtensions
	}

	roots, ok := prov.GetAttestationRoots()
	if !ok {
		return nil, NewErrorISE("no root CA bundle available to verify the attestation certificate")
	}

	// verify that the AK certificate was signed by a trusted root,
	// chained to by the intermediates provided by the client. As part
	// of building the verified certificate chain, the signature over the
	// AK certificate is checked to be a valid signature of one of the
	// provided intermediates. Signatures over the intermediates are in
	// turn also verified to be valid signatures from one of the trusted
	// roots.
	verifiedChains, err := akCert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now().Truncate(time.Second),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return nil, WrapDetailedError(ErrorBadAttestationStatementType, err, "x5c is not valid")
	}

	// validate additional AK certificate requirements
	if err := validateAKCertificate(akCert); err != nil {
		return nil, WrapDetailedError(ErrorBadAttestationStatementType, err, "AK certificate is not valid")
	}

	// TODO(hs): implement revocation check; Verify() doesn't perform CRL check nor OCSP lookup.

	sans, err := x509util.ParseSubjectAlternativeNames(akCert)
	if err != nil {
		return nil, WrapDetailedError(ErrorBadAttestationStatementType, err, "failed parsing AK certificate Subject Alternative Names")
	}

	permanentIdentifiers := make([]string, len(sans.PermanentIdentifiers))
	for i, pi := range sans.PermanentIdentifiers {
		permanentIdentifiers[i] = pi.Identifier
	}

	// extract and validate pubArea, sig, certInfo and alg properties from the request body
	pubArea, ok := att.AttStatement["pubArea"].([]byte)
	if !ok {
		return nil, NewDetailedError(ErrorBadAttestationStatementType, "invalid pubArea in attestation statement")
	}
	if len(pubArea) == 0 {
		return nil, NewDetailedError(ErrorBadAttestationStatementType, "pubArea is empty")
	}

	sig, ok := att.AttStatement["sig"].([]byte)
	if !ok {
		return nil, NewDetailedError(ErrorBadAttestationStatementType, "invalid sig in attestation statement")
	}
	if len(sig) == 0 {
		return nil, NewDetailedError(ErrorBadAttestationStatementType, "sig is empty")
	}

	certInfo, ok := att.AttStatement["certInfo"].([]byte)
	if !ok {
		return nil, NewDetailedError(ErrorBadAttestationStatementType, "invalid certInfo in attestation statement")
	}
	if len(certInfo) == 0 {
		return nil, NewDetailedError(ErrorBadAttestationStatementType, "certInfo is empty")
	}

	alg, ok := att.AttStatement["alg"].(int64)
	if !ok {
		return nil, NewDetailedError(ErrorBadAttestationStatementType, "invalid alg in attestation statement")
	}

	algI32, err := cast.SafeInt32(alg)
	if err != nil {
		return nil, WrapDetailedError(ErrorBadAttestationStatementType, err, "invalid alg %d in attestation statement", alg)
	}

	var hash crypto.Hash
	switch coseAlgorithmIdentifier(algI32) {
	case coseAlgRS256, coseAlgES256:
		hash = crypto.SHA256
	case coseAlgRS1:
		hash = crypto.SHA1
	default:
		return nil, NewDetailedError(ErrorBadAttestationStatementType, "invalid alg %d in attestation statement", alg)
	}

	// recreate the generated key certification parameter values and verify
	// the attested key using the public key of the AK.
	certificationParameters := &attest.CertificationParameters{
		Public:            pubArea,  // the public key that was attested
		CreateAttestation: certInfo, // the attested properties of the key
		CreateSignature:   sig,      // signature over the attested properties
	}
	verifyOpts := attest.VerifyOpts{
		Public: akCert.PublicKey, // public key of the AK that attested the key
		Hash:   hash,
	}
	if err = certificationParameters.Verify(verifyOpts); err != nil {
		return nil, WrapDetailedError(ErrorBadAttestationStatementType, err, "invalid certification parameters")
	}

	// decode the "certInfo" data. This won't fail, as it's also done as part of Verify().
	tpmCertInfo, err := tpm2.DecodeAttestationData(certInfo)
	if err != nil {
		return nil, WrapDetailedError(ErrorBadAttestationStatementType, err, "failed decoding attestation data")
	}

	keyAuth, err := KeyAuthorization(ch.Token, jwk)
	if err != nil {
		return nil, WrapErrorISE(err, "failed creating key auth digest")
	}
	hashedKeyAuth := sha256.Sum256([]byte(keyAuth))

	// verify the WebAuthn object contains the expect key authorization digest, which is carried
	// within the encoded `certInfo` property of the attestation statement.
	if subtle.ConstantTimeCompare(hashedKeyAuth[:], []byte(tpmCertInfo.ExtraData)) == 0 {
		return nil, NewDetailedError(ErrorBadAttestationStatementType, "key authorization invalid")
	}

	// decode the (attested) public key and determine its fingerprint.  This won't fail, as it's also done as part of Verify().
	pub, err := tpm2.DecodePublic(pubArea)
	if err != nil {
		return nil, WrapDetailedError(ErrorBadAttestationStatementType, err, "failed decoding pubArea")
	}

	publicKey, err := pub.Key()
	if err != nil {
		return nil, WrapDetailedError(ErrorBadAttestationStatementType, err, "failed getting public key")
	}

	data := &tpmAttestationData{
		Certificate:          akCert,
		VerifiedChains:       verifiedChains,
		PermanentIdentifiers: permanentIdentifiers,
	}

	if data.Fingerprint, err = keyutil.Fingerprint(publicKey); err != nil {
		return nil, WrapErrorISE(err, "error calculating key fingerprint")
	}

	// TODO(hs): pass more attestation data, so that that can be used/recorded too?
	return data, nil
}

var (
	oidExtensionExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidTCGKpAIKCertificate       = asn1.ObjectIdentifier{2, 23, 133, 8, 3}
)

// validateAKCertificate validates the X.509 AK certificate to be
// in accordance with the required properties. The requirements come from:
// https://www.w3.org/TR/webauthn-2/#sctn-tpm-cert-requirements.
//
//   - Version MUST be set to 3.
//   - Subject field MUST be set to empty.
//   - The Subject Alternative Name extension MUST be set as defined
//     in [TPMv2-EK-Profile] section 3.2.9.
//   - The Extended Key Usage extension MUST contain the OID 2.23.133.8.3
//     ("joint-iso-itu-t(2) international-organizations(23) 133 tcg-kp(8) tcg-kp-AIKCertificate(3)").
//   - The Basic Constraints extension MUST have the CA component set to false.
//   - An Authority Information Access (AIA) extension with entry id-ad-ocsp
//     and a CRL Distribution Point extension [RFC5280] are both OPTIONAL as
//     the status of many attestation certificates is available through metadata
//     services. See, for example, the FIDO Metadata Service.
func validateAKCertificate(c *x509.Certificate) error {
	if c.Version != 3 {
		return fmt.Errorf("AK certificate has invalid version %d; only version 3 is allowed", c.Version)
	}
	if c.Subject.String() != "" {
		return fmt.Errorf("AK certificate subject must be empty; got %q", c.Subject)
	}
	if c.IsCA {
		return errors.New("AK certificate must not be a CA")
	}
	if err := validateAKCertificateExtendedKeyUsage(c); err != nil {
		return err
	}
	return validateAKCertificateSubjectAlternativeNames(c)
}

// validateAKCertificateSubjectAlternativeNames checks if the AK certificate
// has TPM hardware details set.
func validateAKCertificateSubjectAlternativeNames(c *x509.Certificate) error {
	sans, err := x509util.ParseSubjectAlternativeNames(c)
	if err != nil {
		return fmt.Errorf("failed parsing AK certificate Subject Alternative Names: %w", err)
	}

	details := sans.TPMHardwareDetails
	manufacturer, model, version := details.Manufacturer, details.Model, details.Version

	switch {
	case manufacturer == "":
		return errors.New("missing TPM manufacturer")
	case model == "":
		return errors.New("missing TPM model")
	case version == "":
		return errors.New("missing TPM version")
	}

	return nil
}

// validateAKCertificateExtendedKeyUsage checks if the AK certificate
// has the "tcg-kp-AIKCertificate" Extended Key Usage set.
func validateAKCertificateExtendedKeyUsage(c *x509.Certificate) error {
	var (
		valid = false
		ekus  []asn1.ObjectIdentifier
	)
	for _, ext := range c.Extensions {
		if ext.Id.Equal(oidExtensionExtendedKeyUsage) {
			if _, err := asn1.Unmarshal(ext.Value, &ekus); err != nil || !ekus[0].Equal(oidTCGKpAIKCertificate) {
				return errors.New("AK certificate is missing Extended Key Usage value tcg-kp-AIKCertificate (2.23.133.8.3)")
			}
			valid = true
		}
	}

	if !valid {
		return errors.New("AK certificate is missing Extended Key Usage extension")
	}

	return nil
}

// Apple Enterprise Attestation Root CA from
// https://www.apple.com/certificateauthority/private/
const appleEnterpriseAttestationRootCA = `-----BEGIN CERTIFICATE-----
MIICJDCCAamgAwIBAgIUQsDCuyxyfFxeq/bxpm8frF15hzcwCgYIKoZIzj0EAwMw
UTEtMCsGA1UEAwwkQXBwbGUgRW50ZXJwcmlzZSBBdHRlc3RhdGlvbiBSb290IENB
MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzAeFw0yMjAyMTYxOTAx
MjRaFw00NzAyMjAwMDAwMDBaMFExLTArBgNVBAMMJEFwcGxlIEVudGVycHJpc2Ug
QXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UE
BhMCVVMwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT6Jigq+Ps9Q4CoT8t8q+UnOe2p
oT9nRaUfGhBTbgvqSGXPjVkbYlIWYO+1zPk2Sz9hQ5ozzmLrPmTBgEWRcHjA2/y7
7GEicps9wn2tj+G89l3INNDKETdxSPPIZpPj8VmjQjBAMA8GA1UdEwEB/wQFMAMB
Af8wHQYDVR0OBBYEFPNqTQGd8muBpV5du+UIbVbi+d66MA4GA1UdDwEB/wQEAwIB
BjAKBggqhkjOPQQDAwNpADBmAjEA1xpWmTLSpr1VH4f8Ypk8f3jMUKYz4QPG8mL5
8m9sX/b2+eXpTv2pH4RZgJjucnbcAjEA4ZSB6S45FlPuS/u4pTnzoz632rA+xW/T
ZwFEh9bhKjJ+5VQ9/Do1os0u3LEkgN/r
-----END CERTIFICATE-----`

var (
	oidAppleSerialNumber                    = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 9, 1}
	oidAppleUniqueDeviceIdentifier          = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 9, 2}
	oidAppleSecureEnclaveProcessorOSVersion = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 10, 2}
	oidAppleNonce                           = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 11, 1}
)

type appleAttestationData struct {
	Nonce        []byte
	SerialNumber string
	UDID         string
	SEPVersion   string
	Certificate  *x509.Certificate
	Fingerprint  string
}

func doAppleAttestationFormat(_ context.Context, prov Provisioner, _ *Challenge, att *attestationObject) (*appleAttestationData, error) {
	// Use configured or default attestation roots if none is configured.
	roots, ok := prov.GetAttestationRoots()
	if !ok {
		root, err := pemutil.ParseCertificate([]byte(appleEnterpriseAttestationRootCA))
		if err != nil {
			return nil, WrapErrorISE(err, "error parsing apple enterprise ca")
		}
		roots = x509.NewCertPool()
		roots.AddCert(root)
	}

	x5c, ok := att.AttStatement["x5c"].([]interface{})
	if !ok {
		return nil, NewDetailedError(ErrorBadAttestationStatementType, "x5c not present")
	}
	if len(x5c) == 0 {
		return nil, NewDetailedError(ErrorBadAttestationStatementType, "x5c is empty")
	}

	der, ok := x5c[0].([]byte)
	if !ok {
		return nil, NewDetailedError(ErrorBadAttestationStatementType, "x5c is malformed")
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, WrapDetailedError(ErrorBadAttestationStatementType, err, "x5c is malformed")
	}

	intermediates := x509.NewCertPool()
	for _, v := range x5c[1:] {
		der, ok = v.([]byte)
		if !ok {
			return nil, NewDetailedError(ErrorBadAttestationStatementType, "x5c is malformed")
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, WrapDetailedError(ErrorBadAttestationStatementType, err, "x5c is malformed")
		}
		intermediates.AddCert(cert)
	}

	if _, err := leaf.Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
		CurrentTime:   time.Now().Truncate(time.Second),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, WrapDetailedError(ErrorBadAttestationStatementType, err, "x5c is not valid")
	}

	data := &appleAttestationData{
		Certificate: leaf,
	}
	if data.Fingerprint, err = keyutil.Fingerprint(leaf.PublicKey); err != nil {
		return nil, WrapErrorISE(err, "error calculating key fingerprint")
	}
	for _, ext := range leaf.Extensions {
		switch {
		case ext.Id.Equal(oidAppleSerialNumber):
			data.SerialNumber = string(ext.Value)
		case ext.Id.Equal(oidAppleUniqueDeviceIdentifier):
			data.UDID = string(ext.Value)
		case ext.Id.Equal(oidAppleSecureEnclaveProcessorOSVersion):
			data.SEPVersion = string(ext.Value)
		case ext.Id.Equal(oidAppleNonce):
			data.Nonce = ext.Value
		}
	}

	return data, nil
}

// Yubico PIV Root CA Serial 263751
// https://developers.yubico.com/PIV/Introduction/piv-attestation-ca.pem
const yubicoPIVRootCA = `-----BEGIN CERTIFICATE-----
MIIDFzCCAf+gAwIBAgIDBAZHMA0GCSqGSIb3DQEBCwUAMCsxKTAnBgNVBAMMIFl1
YmljbyBQSVYgUm9vdCBDQSBTZXJpYWwgMjYzNzUxMCAXDTE2MDMxNDAwMDAwMFoY
DzIwNTIwNDE3MDAwMDAwWjArMSkwJwYDVQQDDCBZdWJpY28gUElWIFJvb3QgQ0Eg
U2VyaWFsIDI2Mzc1MTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMN2
cMTNR6YCdcTFRxuPy31PabRn5m6pJ+nSE0HRWpoaM8fc8wHC+Tmb98jmNvhWNE2E
ilU85uYKfEFP9d6Q2GmytqBnxZsAa3KqZiCCx2LwQ4iYEOb1llgotVr/whEpdVOq
joU0P5e1j1y7OfwOvky/+AXIN/9Xp0VFlYRk2tQ9GcdYKDmqU+db9iKwpAzid4oH
BVLIhmD3pvkWaRA2H3DA9t7H/HNq5v3OiO1jyLZeKqZoMbPObrxqDg+9fOdShzgf
wCqgT3XVmTeiwvBSTctyi9mHQfYd2DwkaqxRnLbNVyK9zl+DzjSGp9IhVPiVtGet
X02dxhQnGS7K6BO0Qe8CAwEAAaNCMEAwHQYDVR0OBBYEFMpfyvLEojGc6SJf8ez0
1d8Cv4O/MA8GA1UdEwQIMAYBAf8CAQEwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3
DQEBCwUAA4IBAQBc7Ih8Bc1fkC+FyN1fhjWioBCMr3vjneh7MLbA6kSoyWF70N3s
XhbXvT4eRh0hvxqvMZNjPU/VlRn6gLVtoEikDLrYFXN6Hh6Wmyy1GTnspnOvMvz2
lLKuym9KYdYLDgnj3BeAvzIhVzzYSeU77/Cupofj093OuAswW0jYvXsGTyix6B3d
bW5yWvyS9zNXaqGaUmP3U9/b6DlHdDogMLu3VLpBB9bm5bjaKWWJYgWltCVgUbFq
Fqyi4+JE014cSgR57Jcu3dZiehB6UtAPgad9L5cNvua/IWRmm+ANy3O2LH++Pyl8
SREzU8onbBsjMg9QDiSf5oJLKvd/Ren+zGY7
-----END CERTIFICATE-----`

// Yubico Attestation Root 1 (YubiKey 5.7.4+)
// https://developers.yubico.com/PKI/yubico-ca-1.pem
const yubicoAttestationRootCA = `-----BEGIN CERTIFICATE-----
MIIDPjCCAiagAwIBAgIUXzeiEDJEOTt14F5n0o6Zf/bBwiUwDQYJKoZIhvcNAQEN
BQAwJDEiMCAGA1UEAwwZWXViaWNvIEF0dGVzdGF0aW9uIFJvb3QgMTAgFw0yNDEy
MDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1OVowJDEiMCAGA1UEAwwZWXViaWNvIEF0
dGVzdGF0aW9uIFJvb3QgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AMZ6/TxM8rIT+EaoPvG81ontMOo/2mQ2RBwJHS0QZcxVaNXvl12LUhBZ5LmiBScI
Zd1Rnx1od585h+/dhK7hEm7JAALkKKts1fO53KGNLZujz5h3wGncr4hyKF0G74b/
U3K9hE5mGND6zqYchCRAHfrYMYRDF4YL0X4D5nGdxvppAy6nkEmtWmMnwO3i0TAu
csrbE485HvGM4r0VpgVdJpvgQjiTJCTIq+D35hwtT8QDIv+nGvpcyi5wcIfCkzyC
imJukhYy6KoqNMKQEdpNiSOvWyDMTMt1bwCvEzpw91u+msUt4rj0efnO9s0ZOwdw
MRDnH4xgUl5ZLwrrPkfC1/0CAwEAAaNmMGQwHQYDVR0OBBYEFNLu71oijTptXCOX
PfKF1SbxJXuSMB8GA1UdIwQYMBaAFNLu71oijTptXCOXPfKF1SbxJXuSMBIGA1Ud
EwEB/wQIMAYBAf8CAQMwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBDQUAA4IB
AQC3IW/sgB9pZ8apJNjxuGoX+FkILks0wMNrdXL/coUvsrhzsvl6mePMrbGJByJ1
XnquB5sgcRENFxdQFma3mio8Upf1owM1ZreXrJ0mADG2BplqbJnxiyYa+R11reIF
TWeIhMNcZKsDZrFAyPuFjCWSQvJmNWe9mFRYFgNhXJKkXIb5H1XgEDlwiedYRM7V
olBNlld6pRFKlX8ust6OTMOeADl2xNF0m1LThSdeuXvDyC1g9+ILfz3S6OIYgc3i
roRcFD354g7rKfu67qFAw9gC4yi0xBTPrY95rh4/HqaUYCA/L8ldRk6H7Xk35D+W
Vpmq2Sh/xT5HiFuhf4wJb0bK
-----END CERTIFICATE-----`

var (
	// serial number of the YubiKey, encoded as an integer.
	// https://developers.yubico.com/PIV/Introduction/PIV_attestation.html
	oidYubicoSerialNumber = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 7}

	// custom Smallstep managed device extension carrying a device ID or serial number
	oidStepManagedDevice = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64, 4}
)

type stepAttestationData struct {
	Certificate  *x509.Certificate
	SerialNumber string
	Fingerprint  string
}

func doStepAttestationFormat(_ context.Context, prov Provisioner, ch *Challenge, jwk *jose.JSONWebKey, att *attestationObject) (*stepAttestationData, error) {
	// Use configured or default attestation roots if none is configured.
	roots, ok := prov.GetAttestationRoots()
	if !ok {
		pivRoot, err := pemutil.ParseCertificate([]byte(yubicoPIVRootCA))
		if err != nil {
			return nil, WrapErrorISE(err, "error parsing root ca")
		}
		attRoot, err := pemutil.ParseCertificate([]byte(yubicoAttestationRootCA))
		if err != nil {
			return nil, WrapErrorISE(err, "error parsing root ca")
		}
		roots = x509.NewCertPool()
		roots.AddCert(pivRoot)
		roots.AddCert(attRoot)
	}

	// Extract x5c and verify certificate
	x5c, ok := att.AttStatement["x5c"].([]interface{})
	if !ok {
		return nil, NewDetailedError(ErrorBadAttestationStatementType, "x5c not present")
	}
	if len(x5c) == 0 {
		return nil, NewDetailedError(ErrorRejectedIdentifierType, "x5c is empty")
	}
	der, ok := x5c[0].([]byte)
	if !ok {
		return nil, NewDetailedError(ErrorBadAttestationStatementType, "x5c is malformed")
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, WrapDetailedError(ErrorBadAttestationStatementType, err, "x5c is malformed")
	}
	intermediates := x509.NewCertPool()
	for _, v := range x5c[1:] {
		der, ok = v.([]byte)
		if !ok {
			return nil, NewDetailedError(ErrorBadAttestationStatementType, "x5c is malformed")
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, WrapDetailedError(ErrorBadAttestationStatementType, err, "x5c is malformed")
		}
		intermediates.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
		CurrentTime:   time.Now().Truncate(time.Second),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, WrapDetailedError(ErrorBadAttestationStatementType, err, "x5c is not valid")
	}

	// Verify proof of possession of private key validating the key
	// authorization. Per recommendation at
	// https://w3c.github.io/webauthn/#sctn-signature-attestation-types the
	// signature is CBOR-encoded.
	var sig []byte
	csig, ok := att.AttStatement["sig"].([]byte)
	if !ok {
		return nil, NewDetailedError(ErrorBadAttestationStatementType, "sig not present")
	}
	if err := cbor.Unmarshal(csig, &sig); err != nil {
		return nil, NewDetailedError(ErrorBadAttestationStatementType, "sig is malformed")
	}
	keyAuth, err := KeyAuthorization(ch.Token, jwk)
	if err != nil {
		return nil, err
	}

	switch pub := leaf.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if pub.Curve != elliptic.P256() {
			return nil, WrapDetailedError(ErrorBadAttestationStatementType, err, "unsupported elliptic curve %s", pub.Curve)
		}
		sum := sha256.Sum256([]byte(keyAuth))
		if !ecdsa.VerifyASN1(pub, sum[:], sig) {
			return nil, NewDetailedError(ErrorBadAttestationStatementType, "failed to validate signature")
		}
	case *rsa.PublicKey:
		sum := sha256.Sum256([]byte(keyAuth))
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
			return nil, NewDetailedError(ErrorBadAttestationStatementType, "failed to validate signature")
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(pub, []byte(keyAuth), sig) {
			return nil, NewDetailedError(ErrorBadAttestationStatementType, "failed to validate signature")
		}
	default:
		return nil, NewDetailedError(ErrorBadAttestationStatementType, "unsupported public key type %T", pub)
	}

	// Parse attestation data:
	// TODO(mariano): add support for other extensions.
	data := &stepAttestationData{
		Certificate: leaf,
	}

	if data.Fingerprint, err = keyutil.Fingerprint(leaf.PublicKey); err != nil {
		return nil, WrapErrorISE(err, "error calculating key fingerprint")
	}

	if data.SerialNumber, err = searchSerialNumber(leaf); err != nil {
		return nil, WrapErrorISE(err, "error finding serial number")
	}

	return data, nil
}

// searchSerialNumber searches the certificate extensions, looking for a serial
// number encoded in one of them. It is not guaranteed that a certificate contains
// an extension carrying a serial number, so the result can be empty.
func searchSerialNumber(cert *x509.Certificate) (string, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidYubicoSerialNumber) {
			var serialNumber int
			rest, err := asn1.Unmarshal(ext.Value, &serialNumber)
			if err != nil || len(rest) > 0 {
				return "", WrapError(ErrorBadAttestationStatementType, err, "error parsing serial number")
			}
			return strconv.Itoa(serialNumber), nil
		}
		if ext.Id.Equal(oidStepManagedDevice) {
			type stepManagedDevice struct {
				DeviceID string
			}
			var md stepManagedDevice
			rest, err := asn1.Unmarshal(ext.Value, &md)
			if err != nil || len(rest) > 0 {
				return "", WrapError(ErrorBadAttestationStatementType, err, "error parsing serial number")
			}
			return md.DeviceID, nil
		}
	}

	return "", nil
}

// serverName determines the SNI HostName to set based on an acme.Challenge
// for TLS-ALPN-01 challenges RFC8738 states that, if HostName is an IP, it
// should be the ARPA address https://datatracker.ietf.org/doc/html/rfc8738#section-6.
// It also references TLS Extensions [RFC6066].
func serverName(ch *Challenge) string {
	if ip := net.ParseIP(ch.Value); ip != nil {
		return reverseAddr(ip)
	}
	return ch.Value
}

// reverseaddr returns the in-addr.arpa. or ip6.arpa. hostname of the IP
// address addr suitable for rDNS (PTR) record lookup or an error if it fails
// to parse the IP address.
// Implementation taken and adapted from https://golang.org/src/net/dnsclient.go?s=780:834#L20
func reverseAddr(ip net.IP) (arpa string) {
	if ip.To4() != nil {
		return uitoa(uint(ip[15])) + "." + uitoa(uint(ip[14])) + "." + uitoa(uint(ip[13])) + "." + uitoa(uint(ip[12])) + ".in-addr.arpa."
	}
	// Must be IPv6
	buf := make([]byte, 0, len(ip)*4+len("ip6.arpa."))
	// Add it, in reverse, to the buffer
	for i := len(ip) - 1; i >= 0; i-- {
		v := ip[i]
		buf = append(buf, hexit[v&0xF],
			'.',
			hexit[v>>4],
			'.')
	}
	// Append "ip6.arpa." and return (buf already has the final .)
	buf = append(buf, "ip6.arpa."...)
	return string(buf)
}

// Convert unsigned integer to decimal string.
// Implementation taken from https://golang.org/src/net/parse.go
func uitoa(val uint) string {
	if val == 0 { // avoid string allocation
		return "0"
	}
	var buf [20]byte // big enough for 64bit value base 10
	i := len(buf) - 1
	for val >= 10 {
		v := val / 10
		buf[i] = byte('0' + val - v*10)
		i--
		val = v
	}
	// val < 10
	buf[i] = byte('0' + val)
	return string(buf[i:])
}

const hexit = "0123456789abcdef"

// KeyAuthorization creates the ACME key authorization value from a token
// and a jwk.
func KeyAuthorization(token string, jwk *jose.JSONWebKey) (string, error) {
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", WrapErrorISE(err, "error generating JWK thumbprint")
	}
	encPrint := base64.RawURLEncoding.EncodeToString(thumbprint)
	return fmt.Sprintf("%s.%s", token, encPrint), nil
}

// storeError the given error to an ACME error and saves using the DB interface.
func storeError(ctx context.Context, db DB, ch *Challenge, markInvalid bool, err *Error) error {
	ch.Error = err
	if markInvalid {
		ch.Status = StatusInvalid
	}
	if err := db.UpdateChallenge(ctx, ch); err != nil {
		return WrapErrorISE(err, "failure saving error to acme challenge")
	}
	return nil
}
