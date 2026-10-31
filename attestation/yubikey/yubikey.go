// Package yubikey verifies attestation statements of the "step" format of
// ACME device-attest-01 challenges, made by the PIV attestation of YubiKeys
// and by Smallstep managed devices.
package yubikey

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/fxamacker/cbor/v2"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/pemutil"

	"github.com/smallstep/certificates/attestation"
	"github.com/smallstep/certificates/attestation/internal/keyauth"
)

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

var (
	// ErrEmptyX5C is matched by the error of an attestation statement whose
	// x5c holds no certificates.
	ErrEmptyX5C = errors.New("x5c is empty")

	// ErrSerialNumber is matched by the error of an attestation certificate
	// whose serial number extension cannot be parsed.
	ErrSerialNumber = errors.New("error parsing serial number")
)

// Data is what a verified "step" attestation statement attests.
type Data struct {
	// Certificate is the attestation certificate, the leaf of the x5c chain,
	// which holds the attested key.
	Certificate *x509.Certificate
	// SerialNumber is the serial number of the YubiKey, or the device ID of
	// the managed device. It is empty if the attestation certificate carries
	// neither.
	SerialNumber string
	// Fingerprint is the fingerprint of the attested key.
	Fingerprint string
}

// Verify verifies a "step" attestation statement: its x5c chain against roots,
// or against Yubico's PIV and attestation roots if roots is nil, and its
// signature over keyAuth, the key authorization of the challenge, with the
// attested key. It returns what the attestation certificate attests. Errors of
// the statement match attestation.ErrInvalidEvidence.
func Verify(attStmt map[string]any, roots *x509.CertPool, keyAuth []byte) (*Data, error) {
	// Use the default attestation roots if none is configured.
	if roots == nil {
		pivRoot, err := pemutil.ParseCertificate([]byte(yubicoPIVRootCA))
		if err != nil {
			return nil, fmt.Errorf("error parsing root ca: %w", err)
		}
		attRoot, err := pemutil.ParseCertificate([]byte(yubicoAttestationRootCA))
		if err != nil {
			return nil, fmt.Errorf("error parsing root ca: %w", err)
		}
		roots = x509.NewCertPool()
		roots.AddCert(pivRoot)
		roots.AddCert(attRoot)
	}

	// Extract x5c and verify certificate
	x5c, ok := attStmt["x5c"].([]any)
	if !ok {
		return nil, attestation.Invalidf("x5c not present")
	}
	if len(x5c) == 0 {
		return nil, attestation.Invalid(ErrEmptyX5C)
	}
	der, ok := x5c[0].([]byte)
	if !ok {
		return nil, attestation.Invalidf("x5c is malformed")
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, attestation.Invalidf("x5c is malformed: %w", err)
	}
	intermediates := x509.NewCertPool()
	for _, v := range x5c[1:] {
		der, ok = v.([]byte)
		if !ok {
			return nil, attestation.Invalidf("x5c is malformed")
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, attestation.Invalidf("x5c is malformed: %w", err)
		}
		intermediates.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
		CurrentTime:   time.Now().Truncate(time.Second),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, attestation.Invalidf("x5c is not valid: %w", err)
	}

	// Verify proof of possession of private key validating the key
	// authorization. Per recommendation at
	// https://w3c.github.io/webauthn/#sctn-signature-attestation-types the
	// signature is CBOR-encoded.
	var sig []byte
	csig, ok := attStmt["sig"].([]byte)
	if !ok {
		return nil, attestation.Invalidf("sig not present")
	}
	if err := cbor.Unmarshal(csig, &sig); err != nil {
		return nil, attestation.Invalidf("sig is malformed")
	}

	// Verify attestation statement sig
	if err := keyauth.Verify(leaf, keyAuth, sig); err != nil {
		return nil, err
	}

	// Parse attestation data:
	// TODO(mariano): add support for other extensions.
	data := &Data{
		Certificate: leaf,
	}

	if data.Fingerprint, err = keyutil.Fingerprint(leaf.PublicKey); err != nil {
		return nil, fmt.Errorf("error calculating key fingerprint: %w", err)
	}

	if data.SerialNumber, err = searchSerialNumber(leaf); err != nil {
		return nil, attestation.Invalid(fmt.Errorf("error finding serial number: %w", err))
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
			if err := unmarshalExtension(ext.Value, &serialNumber); err != nil {
				return "", err
			}
			return strconv.Itoa(serialNumber), nil
		}
		if ext.Id.Equal(oidStepManagedDevice) {
			type stepManagedDevice struct {
				DeviceID string
			}
			var md stepManagedDevice
			if err := unmarshalExtension(ext.Value, &md); err != nil {
				return "", err
			}
			return md.DeviceID, nil
		}
	}

	return "", nil
}

// unmarshalExtension parses the value of a serial number extension into v. Its
// errors match ErrSerialNumber.
func unmarshalExtension(value []byte, v any) error {
	rest, err := asn1.Unmarshal(value, v)
	if err == nil && len(rest) > 0 {
		err = asn1.SyntaxError{Msg: "trailing data"}
	}
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSerialNumber, err)
	}
	return nil
}
