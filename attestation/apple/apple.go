// Package apple verifies attestation statements of the "apple" format of ACME
// device-attest-01 challenges, made by Apple's Managed Device Attestation.
package apple

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"time"

	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/pemutil"

	"github.com/smallstep/certificates/attestation"
)

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

// Data is what a verified "apple" attestation statement attests.
type Data struct {
	// Nonce is the freshness nonce the attestation certificate binds, if any.
	Nonce []byte
	// SerialNumber is the serial number of the device.
	SerialNumber string
	// UDID is the unique device identifier of the device.
	UDID string
	// SEPVersion is the version of the operating system of the device's
	// Secure Enclave Processor.
	SEPVersion string
	// Certificate is the attestation certificate, the leaf of the x5c chain,
	// which holds the attested key.
	Certificate *x509.Certificate
	// Fingerprint is the fingerprint of the attested key.
	Fingerprint string
}

// Verify verifies the x5c chain of an "apple" attestation statement against
// roots, or against Apple's Enterprise Attestation Root CA if roots is nil,
// and returns what its attestation certificate attests. Errors of the
// statement match attestation.ErrInvalidEvidence.
func Verify(attStmt map[string]any, roots *x509.CertPool) (*Data, error) {
	// Use the default attestation root if none is configured.
	if roots == nil {
		root, err := pemutil.ParseCertificate([]byte(appleEnterpriseAttestationRootCA))
		if err != nil {
			return nil, fmt.Errorf("error parsing apple enterprise ca: %w", err)
		}
		roots = x509.NewCertPool()
		roots.AddCert(root)
	}

	x5c, ok := attStmt["x5c"].([]any)
	if !ok {
		return nil, attestation.Invalidf("x5c not present")
	}
	if len(x5c) == 0 {
		return nil, attestation.Invalidf("x5c is empty")
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

	data := &Data{
		Certificate: leaf,
	}
	if data.Fingerprint, err = keyutil.Fingerprint(leaf.PublicKey); err != nil {
		return nil, fmt.Errorf("error calculating key fingerprint: %w", err)
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
