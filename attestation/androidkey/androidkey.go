// Package androidkey verifies attestation statements of the "android-key"
// format of ACME device-attest-01 challenges, made by Android Key Attestation.
package androidkey

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
	"time"

	keyattestation "github.com/smallstep/android-attestation"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/pemutil"

	"github.com/smallstep/certificates/attestation"
	"github.com/smallstep/certificates/attestation/internal/keyauth"
)

// Android RSA Root CA
// https://developer.android.com/privacy-and-security/security-key-attestation#root_certificate
const androidRSARootCA = `-----BEGIN CERTIFICATE-----
MIIFHDCCAwSgAwIBAgIJAPHBcqaZ6vUdMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV
BAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMjIwMzIwMTgwNzQ4WhcNNDIwMzE1MTgw
NzQ4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B
AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS
Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7
tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj
nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq
C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ
oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O
JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg
sTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi
igHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M
RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E
aDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5Um
AGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1Ud
IwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYD
VR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQB8cMqTllHc8U+qCrOlg3H7
174lmaCsbo/bJ0C17JEgMLb4kvrqsXZs01U3mB/qABg/1t5Pd5AORHARs1hhqGIC
W/nKMav574f9rZN4PC2ZlufGXb7sIdJpGiO9ctRhiLuYuly10JccUZGEHpHSYM2G
tkgYbZba6lsCPYAAP83cyDV+1aOkTf1RCp/lM0PKvmxYN10RYsK631jrleGdcdkx
oSK//mSQbgcWnmAEZrzHoF1/0gso1HZgIn0YLzVhLSA/iXCX4QT2h3J5z3znluKG
1nv8NQdxei2DIIhASWfu804CA96cQKTTlaae2fweqXjdN1/v2nqOhngNyz1361mF
mr4XmaKH/ItTwOe72NI9ZcwS1lVaCvsIkTDCEXdm9rCNPAY10iTunIHFXRh+7KPz
lHGewCq/8TOohBRn0/NNfh7uRslOSZ/xKbN9tMBtw37Z8d2vvnXq/YWdsm1+JLVw
n6yYD/yacNJBlwpddla8eaVMjsF6nBnIgQOf9zKSe06nSTqvgwUHosgOECZJZ1Eu
zbH4yswbt02tKtKEFhx+v+OTge/06V+jGsqTWLsfrOCNLuA8H++z+pUENmpqnnHo
vaI47gC+TNpkgYGkkBT6B/m/U01BuOBBTzhIlMEZq9qkDWuM2cA5kW5V3FJUcfHn
w1IdYIg2Wxg7yHcQZemFQg==
-----END CERTIFICATE-----`

// Android ECDSA (secp384r1) Root CA
const androidECDSARootCA = `-----BEGIN CERTIFICATE-----
MIICIjCCAaigAwIBAgIRAISp0Cl7DrWK5/8OgN52BgUwCgYIKoZIzj0EAwMwUjEc
MBoGA1UEAwwTS2V5IEF0dGVzdGF0aW9uIENBMTEQMA4GA1UECwwHQW5kcm9pZDET
MBEGA1UECgwKR29vZ2xlIExMQzELMAkGA1UEBhMCVVMwHhcNMjUwNzE3MjIzMjE4
WhcNMzUwNzE1MjIzMjE4WjBSMRwwGgYDVQQDDBNLZXkgQXR0ZXN0YXRpb24gQ0Ex
MRAwDgYDVQQLDAdBbmRyb2lkMRMwEQYDVQQKDApHb29nbGUgTExDMQswCQYDVQQG
EwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABCPaI3FO3z5bBQo8cuiEas4HjqCt
G/mLFfRT0MsIssPBEEU5Cfbt6sH5yOAxqEi5QagpU1yX4HwnGb7OtBYpDTB57uH5
Eczm34A5FNijV3s0/f0UPl7zbJcTx6xwqMIRq6NCMEAwDwYDVR0TAQH/BAUwAwEB
/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFFIyuyz7RkOb3NaBqQ5lZuA0QepA
MAoGCCqGSM49BAMDA2gAMGUCMETfjPO/HwqReR2CS7p0ZWoD/LHs6hDi422opifH
EUaYLxwGlT9SLdjkVpz0UUOR5wIxAIoGyxGKRHVTpqpGRFiJtQEOOTp/+s1GcxeY
uR2zh/80lQyu9vAFCj6E4AXc+osmRg==
-----END CERTIFICATE-----`

// OID for Android Key Attestation
// https://source.android.com/docs/security/features/keystore/attestation#id-attestation
var oidAndroidAttestation = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

var (
	// ErrEmptyX5C is matched by the error of an attestation statement whose
	// x5c holds no certificates.
	ErrEmptyX5C = errors.New("x5c is empty")

	// ErrKeyDescription is matched by the error of a key attestation
	// extension that cannot be parsed.
	ErrKeyDescription = errors.New("error parsing attestation")
)

// RevocationChecker reports whether a certificate of an x5c chain is revoked.
type RevocationChecker func(ctx context.Context, cert *x509.Certificate) (bool, error)

// Data is what a verified "android-key" attestation statement attests.
type Data struct {
	// Certificate is the attestation certificate, the certificate closest to
	// the root that carries a key attestation extension. It holds the
	// attested key.
	Certificate *x509.Certificate
	// Fingerprint is the fingerprint of the attested key.
	Fingerprint string
	// KeyDescription is the key attestation extension of the attestation
	// certificate.
	KeyDescription *keyattestation.KeyDescription
}

// findAndroidAttestationCert traverses the slice of [*x509.Certificate] from
// end to start (root -> intermediate -> leaf) to locate the certificate closest
// to the root carrying an Android Key Attestation extension.
//
// TODO(hs): implement the optional step of locating the provisioning information
// extension? That should immediately precede the cert with the key attestation
// extension.
func findAndroidAttestationCert(certs []*x509.Certificate) *x509.Certificate {
	for _, cert := range slices.Backward(certs) {
		for _, ext := range cert.Extensions {
			if ext.Id.Equal(oidAndroidAttestation) {
				return cert
			}
		}
	}

	return nil
}

// Verify verifies an "android-key" attestation statement, following
// https://developer.android.com/privacy-and-security/security-key-attestation,
// against roots, or against Google's roots if roots is nil, and keyAuth, the
// key authorization of the challenge. It performs the below steps:
//   - Verifies that the root public certificate is trustworthy and that each certificate signs
//     the next certificate in the chain.
//   - Checks each certificate's revocation status with isRevoked to ensure that none of the
//     certificates have been revoked.
//   - Finds the nearest certificate to the root that contains the key attestation certificate
//     extension, and verifies the statement's signature over keyAuth with its key.
//   - Checks that the attestation challenge of the extension is keyAuth.
//
// It returns the attestation certificate and its key description, whose
// values the caller compares with the ones it expects the hardware-backed key
// to have. Errors of the statement match attestation.ErrInvalidEvidence; errors
// of isRevoked do not.
func Verify(ctx context.Context, attStmt map[string]any, roots *x509.CertPool, keyAuth []byte, isRevoked RevocationChecker) (*Data, error) {
	if isRevoked == nil {
		return nil, errors.New("android-key attestation requires a revocation checker")
	}

	if roots == nil {
		rsaRoot, err := pemutil.ParseCertificate([]byte(androidRSARootCA))
		if err != nil {
			return nil, fmt.Errorf("error parsing Android RSA root CA: %w", err)
		}
		ecdsaRoot, err := pemutil.ParseCertificate([]byte(androidECDSARootCA))
		if err != nil {
			return nil, fmt.Errorf("error parsing Android ECDSA root CA: %w", err)
		}
		roots = x509.NewCertPool()
		roots.AddCert(rsaRoot)
		roots.AddCert(ecdsaRoot)
	}

	// extract x5c and verify certificate
	x5c, ok := attStmt["x5c"].([]any)
	if !ok {
		return nil, attestation.Invalidf("x5c not present")
	}
	if len(x5c) == 0 {
		return nil, attestation.Invalid(ErrEmptyX5C)
	}

	// Parse leaf, intermediates and root
	intermediates := x509.NewCertPool()
	var leaf, root *x509.Certificate
	for i, v := range x5c {
		der, dok := v.([]byte)
		if !dok {
			return nil, attestation.Invalidf("x5c element is malformed")
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, attestation.Invalidf("failed parsing certificate at index %d: %w", i, err)
		}

		// Verify certificate serial number against CRL
		revoked, err := isRevoked(ctx, cert)
		if err != nil {
			return nil, fmt.Errorf("failed checking certificate revocation status: %w", err)
		}
		if revoked {
			return nil, attestation.Invalidf("x5c element contains a revoked certificate")
		}

		switch i {
		case 0: // leaf
			leaf = cert
		case len(x5c) - 1: // root
			root = cert
		default: // intermediates
			intermediates.AddCert(cert)
		}
	}

	// Require a leaf in the chain
	if leaf == nil {
		return nil, attestation.Invalidf("missing leaf certificate in x5c chain")
	}

	// Require a root in the chain
	if root == nil {
		return nil, attestation.Invalidf("missing root certificate in x5c chain")
	}

	// Verify the root is one of the trusted roots
	_, err := root.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: time.Now().Truncate(time.Second),
	})
	if err != nil {
		return nil, attestation.Invalidf("root certificate in chain is not trusted")
	}

	// Validate the full chain including root as trust anchor
	chains, err := leaf.Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
		CurrentTime:   time.Now().Truncate(time.Second),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return nil, attestation.Invalidf("x5c chain verification failed: %w", err)
	}

	switch {
	case len(chains) == 0:
		return nil, attestation.Invalidf("x5c does not contain a valid certificate chain")
	case len(chains) > 1:
		// currently we strictly prohibit multiple valid signing chains
		return nil, attestation.Invalidf("x5c contains multiple (%d) valid certificate chains", len(chains))
	}

	// Get signature
	sig, ok := attStmt["sig"].([]byte)
	if !ok {
		return nil, attestation.Invalidf("sig not present")
	}

	// Find the attestation certificate
	attCert := findAndroidAttestationCert(chains[0])
	if attCert == nil {
		return nil, attestation.Invalidf("no attestation certificate with OID 1.3.6.1.4.1.11129.2.1.17 found in the cert chain")
	}

	// Verify attestation statement sig
	if err := keyauth.Verify(attCert, keyAuth, sig); err != nil {
		return nil, err
	}

	data := &Data{
		Certificate: attCert,
	}
	if data.Fingerprint, err = keyutil.Fingerprint(attCert.PublicKey); err != nil {
		return nil, fmt.Errorf("error calculating key fingerprint: %w", err)
	}

	for _, ext := range attCert.Extensions {
		if !ext.Id.Equal(oidAndroidAttestation) {
			continue
		}
		keyDesc, err := keyattestation.ParseExtension(ext.Value)
		if err != nil {
			return nil, attestation.Invalid(fmt.Errorf("%w: %w", ErrKeyDescription, err))
		}
		data.KeyDescription = keyDesc
		break
	}

	// Validate key authorization
	if !bytes.Equal(data.KeyDescription.AttestationChallenge, keyAuth) {
		return nil, attestation.Invalidf("challenge mismatch; expected %q, got %q", keyAuth, data.KeyDescription.AttestationChallenge)
	}

	return data, nil
}
