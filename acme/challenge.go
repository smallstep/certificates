package acme

import (
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
	"strconv"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/smallstep/certificates/authority/provisioner"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/pemutil"
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
	default:
		return NewErrorISE("unexpected challenge type '%s'", ch.Type)
	}
}

func http01Validate(ctx context.Context, ch *Challenge, db DB, jwk *jose.JSONWebKey) error {
	u := &url.URL{Scheme: "http", Host: http01ChallengeHost(ch.Value), Path: fmt.Sprintf("/.well-known/acme-challenge/%s", ch.Token)}

	// Append insecure port if set.
	// Only used for testing purposes.
	if InsecurePortHTTP01 != 0 {
		u.Host += ":" + strconv.Itoa(InsecurePortHTTP01)
	}

	vc := MustClientFromContext(ctx)
	resp, err := vc.Get(u.String())
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

	var hostPort string

	// Allow to change TLS port for testing purposes.
	if port := InsecurePortTLSALPN01; port == 0 {
		hostPort = net.JoinHostPort(ch.Value, "443")
	} else {
		hostPort = net.JoinHostPort(ch.Value, strconv.Itoa(port))
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

func dns01Validate(ctx context.Context, ch *Challenge, db DB, jwk *jose.JSONWebKey) error {
	// Normalize domain for wildcard DNS names
	// This is done to avoid making TXT lookups for domains like
	// _acme-challenge.*.example.com
	// Instead perform txt lookup for _acme-challenge.example.com
	domain := strings.TrimPrefix(ch.Value, "*.")

	vc := MustClientFromContext(ctx)
	txtRecords, err := vc.LookupTxt("_acme-challenge." + domain)
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

type Payload struct {
	AttObj string `json:"attObj"`
	Error  string `json:"error"`
}

type AttestationObject struct {
	Format       string                 `json:"fmt"`
	AttStatement map[string]interface{} `json:"attStmt,omitempty"`
}

// TODO(bweeks): move attestation verification to a shared package.
// TODO(bweeks): define new error type for failed attestation validation.
func deviceAttest01Validate(ctx context.Context, ch *Challenge, db DB, jwk *jose.JSONWebKey, payload []byte) error {
	var p Payload
	if err := json.Unmarshal(payload, &p); err != nil {
		return WrapErrorISE(err, "error unmarshalling JSON")
	}
	if p.Error != "" {
		return storeError(ctx, db, ch, true, NewError(ErrorRejectedIdentifierType,
			"payload contained error: %v", p.Error))
	}

	attObj, err := base64.RawURLEncoding.DecodeString(p.AttObj)
	if err != nil {
		return WrapErrorISE(err, "error base64 decoding attObj")
	}

	att := AttestationObject{}
	if err := cbor.Unmarshal(attObj, &att); err != nil {
		return WrapErrorISE(err, "error unmarshalling CBOR")
	}

	prov := MustProvisionerFromContext(ctx)
	if !prov.IsAttestationFormatEnabled(ctx, provisioner.ACMEAttestationFormat(att.Format)) {
		return storeError(ctx, db, ch, true,
			NewError(ErrorBadAttestationStatementType, "attestation format %q is not enabled", att.Format))
	}

	switch att.Format {
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
				return storeError(ctx, db, ch, true, NewError(ErrorBadAttestationStatementType, "challenge token does not match"))
			}
		}

		// Validate Apple's ClientIdentifier (Identifier.Value) with device
		// identifiers.
		//
		// Note: We might want to use an external service for this.
		if data.UDID != ch.Value && data.SerialNumber != ch.Value {
			return storeError(ctx, db, ch, true, NewError(ErrorBadAttestationStatementType, "permanent identifier does not match"))
		}
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

		// Validate Apple's ClientIdentifier (Identifier.Value) with device
		// identifiers.
		//
		// Note: We might want to use an external service for this.
		if data.SerialNumber != ch.Value {
			return storeError(ctx, db, ch, true, NewError(ErrorBadAttestationStatementType, "permanent identifier does not match"))
		}
	default:
		return storeError(ctx, db, ch, true, NewError(ErrorBadAttestationStatementType, "unexpected attestation object format"))
	}

	// Update and store the challenge.
	ch.Status = StatusValid
	ch.Error = nil
	ch.ValidatedAt = clock.Now().Format(time.RFC3339)

	if err := db.UpdateChallenge(ctx, ch); err != nil {
		return WrapErrorISE(err, "error updating challenge")
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
}

func doAppleAttestationFormat(ctx context.Context, prov Provisioner, ch *Challenge, att *AttestationObject) (*appleAttestationData, error) {
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
		return nil, NewError(ErrorBadAttestationStatementType, "x5c not present")
	}
	if len(x5c) == 0 {
		return nil, NewError(ErrorRejectedIdentifierType, "x5c is empty")
	}

	der, ok := x5c[0].([]byte)
	if !ok {
		return nil, NewError(ErrorBadAttestationStatementType, "x5c is malformed")
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, WrapError(ErrorBadAttestationStatementType, err, "x5c is malformed")
	}

	intermediates := x509.NewCertPool()
	for _, v := range x5c[1:] {
		der, ok = v.([]byte)
		if !ok {
			return nil, NewError(ErrorBadAttestationStatementType, "x5c is malformed")
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, WrapError(ErrorBadAttestationStatementType, err, "x5c is malformed")
		}
		intermediates.AddCert(cert)
	}

	if _, err := leaf.Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
		CurrentTime:   time.Now().Truncate(time.Second),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, WrapError(ErrorBadAttestationStatementType, err, "x5c is not valid")
	}

	data := &appleAttestationData{
		Certificate: leaf,
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

// Serial number of the YubiKey, encoded as an integer.
// https://developers.yubico.com/PIV/Introduction/PIV_attestation.html
var oidYubicoSerialNumber = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 7}

type stepAttestationData struct {
	Certificate  *x509.Certificate
	SerialNumber string
}

func doStepAttestationFormat(ctx context.Context, prov Provisioner, ch *Challenge, jwk *jose.JSONWebKey, att *AttestationObject) (*stepAttestationData, error) {
	// Use configured or default attestation roots if none is configured.
	roots, ok := prov.GetAttestationRoots()
	if !ok {
		root, err := pemutil.ParseCertificate([]byte(yubicoPIVRootCA))
		if err != nil {
			return nil, WrapErrorISE(err, "error parsing root ca")
		}
		roots = x509.NewCertPool()
		roots.AddCert(root)
	}

	// Extract x5c and verify certificate
	x5c, ok := att.AttStatement["x5c"].([]interface{})
	if !ok {
		return nil, NewError(ErrorBadAttestationStatementType, "x5c not present")
	}
	if len(x5c) == 0 {
		return nil, NewError(ErrorRejectedIdentifierType, "x5c is empty")
	}
	der, ok := x5c[0].([]byte)
	if !ok {
		return nil, NewError(ErrorBadAttestationStatementType, "x5c is malformed")
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, WrapError(ErrorBadAttestationStatementType, err, "x5c is malformed")
	}
	intermediates := x509.NewCertPool()
	for _, v := range x5c[1:] {
		der, ok = v.([]byte)
		if !ok {
			return nil, NewError(ErrorBadAttestationStatementType, "x5c is malformed")
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, WrapError(ErrorBadAttestationStatementType, err, "x5c is malformed")
		}
		intermediates.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
		CurrentTime:   time.Now().Truncate(time.Second),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, WrapError(ErrorBadAttestationStatementType, err, "x5c is not valid")
	}

	// Verify proof of possession of private key validating the key
	// authorization. Per recommendation at
	// https://w3c.github.io/webauthn/#sctn-signature-attestation-types the
	// signature is CBOR-encoded.
	var sig []byte
	csig, ok := att.AttStatement["sig"].([]byte)
	if !ok {
		return nil, NewError(ErrorBadAttestationStatementType, "sig not present")
	}
	if err := cbor.Unmarshal(csig, &sig); err != nil {
		return nil, NewError(ErrorBadAttestationStatementType, "sig is malformed")
	}
	keyAuth, err := KeyAuthorization(ch.Token, jwk)
	if err != nil {
		return nil, err
	}

	switch pub := leaf.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if pub.Curve != elliptic.P256() {
			return nil, WrapError(ErrorBadAttestationStatementType, err, "unsupported elliptic curve %s", pub.Curve)
		}
		sum := sha256.Sum256([]byte(keyAuth))
		if !ecdsa.VerifyASN1(pub, sum[:], sig) {
			return nil, NewError(ErrorBadAttestationStatementType, "failed to validate signature")
		}
	case *rsa.PublicKey:
		sum := sha256.Sum256([]byte(keyAuth))
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
			return nil, NewError(ErrorBadAttestationStatementType, "failed to validate signature")
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(pub, []byte(keyAuth), sig) {
			return nil, NewError(ErrorBadAttestationStatementType, "failed to validate signature")
		}
	default:
		return nil, NewError(ErrorBadAttestationStatementType, "unsupported public key type %T", pub)
	}

	// Parse attestation data:
	// TODO(mariano): add support for other extensions.
	data := &stepAttestationData{
		Certificate: leaf,
	}
	for _, ext := range leaf.Extensions {
		if !ext.Id.Equal(oidYubicoSerialNumber) {
			continue
		}
		var serialNumber int
		rest, err := asn1.Unmarshal(ext.Value, &serialNumber)
		if err != nil || len(rest) > 0 {
			return nil, WrapError(ErrorBadAttestationStatementType, err, "error parsing serial number")
		}
		data.SerialNumber = strconv.Itoa(serialNumber)
		break
	}

	return data, nil
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
