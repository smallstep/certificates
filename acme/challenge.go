package acme

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	"go.step.sm/crypto/jose"
)

type ChallengeType string

const (
	// HTTP01 is the http-01 ACME challenge type
	HTTP01 ChallengeType = "http-01"
	// DNS01 is the dns-01 ACME challenge type
	DNS01 ChallengeType = "dns-01"
	// TLSALPN01 is the tls-alpn-01 ACME challenge type
	TLSALPN01 ChallengeType = "tls-alpn-01"
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
	Error           *Error        `json:"error,omitempty"`
}

// ToLog enables response logging.
func (ch *Challenge) ToLog() (interface{}, error) {
	b, err := json.Marshal(ch)
	if err != nil {
		return nil, WrapErrorISE(err, "error marshaling challenge for logging")
	}
	return string(b), nil
}

// Validate attempts to validate the challenge. Stores changes to the Challenge
// type using the DB interface.
// satisfactorily validated, the 'status' and 'validated' attributes are
// updated.
func (ch *Challenge) Validate(ctx context.Context, db DB, jwk *jose.JSONWebKey, vo *ValidateChallengeOptions) error {
	// If already valid or invalid then return without performing validation.
	if ch.Status != StatusPending {
		return nil
	}
	switch ch.Type {
	case HTTP01:
		return http01Validate(ctx, ch, db, jwk, vo)
	case DNS01:
		return dns01Validate(ctx, ch, db, jwk, vo)
	case TLSALPN01:
		return tlsalpn01Validate(ctx, ch, db, jwk, vo)
	default:
		return NewErrorISE("unexpected challenge type '%s'", ch.Type)
	}
}

func http01Validate(ctx context.Context, ch *Challenge, db DB, jwk *jose.JSONWebKey, vo *ValidateChallengeOptions) error {
	u := &url.URL{Scheme: "http", Host: http01ChallengeHost(ch.Value), Path: fmt.Sprintf("/.well-known/acme-challenge/%s", ch.Token)}

	resp, err := vo.HTTPGet(u.String())
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

// http01ChallengeHost checks if a Challenge value is an IPv6 address
// and adds square brackets if that's the case, so that it can be used
// as a hostname. Returns the original Challenge value as the host to
// use in other cases.
func http01ChallengeHost(value string) string {
	if ip := net.ParseIP(value); ip != nil && ip.To4() == nil {
		value = "[" + value + "]"
	}
	return value
}

func tlsAlert(err error) uint8 {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		v := reflect.ValueOf(opErr.Err)
		if v.Kind() == reflect.Uint8 {
			return uint8(v.Uint())
		}
	}
	return 0
}

func tlsalpn01Validate(ctx context.Context, ch *Challenge, db DB, jwk *jose.JSONWebKey, vo *ValidateChallengeOptions) error {
	config := &tls.Config{
		NextProtos: []string{"acme-tls/1"},
		// https://tools.ietf.org/html/rfc8737#section-4
		// ACME servers that implement "acme-tls/1" MUST only negotiate TLS 1.2
		// [RFC5246] or higher when connecting to clients for validation.
		MinVersion:         tls.VersionTLS12,
		ServerName:         serverName(ch),
		InsecureSkipVerify: true, // we expect a self-signed challenge certificate
	}

	hostPort := net.JoinHostPort(ch.Value, "443")

	conn, err := vo.TLSDial("tcp", hostPort, config)
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
			"error doing TLS dial for %s", hostPort))
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

func dns01Validate(ctx context.Context, ch *Challenge, db DB, jwk *jose.JSONWebKey, vo *ValidateChallengeOptions) error {
	// Normalize domain for wildcard DNS names
	// This is done to avoid making TXT lookups for domains like
	// _acme-challenge.*.example.com
	// Instead perform txt lookup for _acme-challenge.example.com
	domain := strings.TrimPrefix(ch.Value, "*.")

	txtRecords, err := vo.LookupTxt("_acme-challenge." + domain)
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

// serverName determines the SNI HostName to set based on an acme.Challenge
// for TLS-ALPN-01 challenges RFC8738 states that, if HostName is an IP, it
// should be the ARPA address https://datatracker.ietf.org/doc/html/rfc8738#section-6.
// It also references TLS Extensions [RFC6066].
func serverName(ch *Challenge) string {
	var serverName string
	ip := net.ParseIP(ch.Value)
	if ip != nil {
		serverName = reverseAddr(ip)
	} else {
		serverName = ch.Value
	}
	return serverName
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
		q := val / 10
		buf[i] = byte('0' + val - q*10)
		i--
		val = q
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

type httpGetter func(string) (*http.Response, error)
type lookupTxt func(string) ([]string, error)
type tlsDialer func(network, addr string, config *tls.Config) (*tls.Conn, error)

// ValidateChallengeOptions are ACME challenge validator functions.
type ValidateChallengeOptions struct {
	HTTPGet   httpGetter
	LookupTxt lookupTxt
	TLSDial   tlsDialer
}
