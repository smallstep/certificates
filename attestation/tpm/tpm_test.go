package tpm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/minica"
	"go.step.sm/crypto/x509util"
)

var (
	oidTPMManufacturer = asn1.ObjectIdentifier{2, 23, 133, 2, 1}
	oidTPMModel        = asn1.ObjectIdentifier{2, 23, 133, 2, 2}
	oidTPMVersion      = asn1.ObjectIdentifier{2, 23, 133, 2, 3}
)

func generateValidAKCertificate(t *testing.T) *x509.Certificate {
	t.Helper()
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		PublicKey:          signer.Public(),
		Version:            3,
		IsCA:               false,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{oidTCGKpAIKCertificate},
	}
	asn1Value := []byte(fmt.Sprintf(`{"extraNames":[{"type": %q, "value": %q},{"type": %q, "value": %q},{"type": %q, "value": %q}]}`, oidTPMManufacturer, "1414747215", oidTPMModel, "SLB 9670 TPM2.0", oidTPMVersion, "7.55"))
	sans := []x509util.SubjectAlternativeName{
		{Type: x509util.DirectoryNameType,
			ASN1Value: asn1Value},
	}
	ext, err := createSubjectAltNameExtension(nil, nil, nil, nil, sans, true)
	require.NoError(t, err)
	ext.Set(template)
	ca, err := minica.New()
	require.NoError(t, err)
	cert, err := ca.Sign(template)
	require.NoError(t, err)

	return cert
}

func Test_validateAKCertificate(t *testing.T) {
	cert := generateValidAKCertificate(t)
	tests := []struct {
		name   string
		c      *x509.Certificate
		expErr error
	}{
		{
			name:   "ok",
			c:      cert,
			expErr: nil,
		},
		{
			name: "fail/version",
			c: &x509.Certificate{
				Version: 1,
			},
			expErr: errors.New("AK certificate has invalid version 1; only version 3 is allowed"),
		},
		{
			name: "fail/subject",
			c: &x509.Certificate{
				Version: 3,
				Subject: pkix.Name{CommonName: "fail!"},
			},
			expErr: errors.New(`AK certificate subject must be empty; got "CN=fail!"`),
		},
		{
			name: "fail/isCA",
			c: &x509.Certificate{
				Version: 3,
				IsCA:    true,
			},
			expErr: errors.New("AK certificate must not be a CA"),
		},
		{
			name: "fail/extendedKeyUsage",
			c: &x509.Certificate{
				Version: 3,
			},
			expErr: errors.New("AK certificate is missing Extended Key Usage extension"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAKCertificate(tt.c)
			if tt.expErr != nil {
				if assert.Error(t, err) {
					assert.EqualError(t, err, tt.expErr.Error())
				}
				return
			}

			assert.NoError(t, err)
		})
	}
}

func Test_validateAKCertificateSubjectAlternativeNames(t *testing.T) {
	ok := generateValidAKCertificate(t)
	t.Helper()
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	getBase := func() *x509.Certificate {
		return &x509.Certificate{
			PublicKey:          signer.Public(),
			Version:            3,
			IsCA:               false,
			UnknownExtKeyUsage: []asn1.ObjectIdentifier{oidTCGKpAIKCertificate},
		}
	}

	ca, err := minica.New()
	require.NoError(t, err)
	missingManufacturerASN1 := []byte(fmt.Sprintf(`{"extraNames":[{"type": %q, "value": %q},{"type": %q, "value": %q}]}`, oidTPMModel, "SLB 9670 TPM2.0", oidTPMVersion, "7.55"))
	sans := []x509util.SubjectAlternativeName{
		{Type: x509util.DirectoryNameType,
			ASN1Value: missingManufacturerASN1},
	}
	ext, err := createSubjectAltNameExtension(nil, nil, nil, nil, sans, true)
	require.NoError(t, err)
	missingManufacturer := getBase()
	ext.Set(missingManufacturer)

	missingManufacturer, err = ca.Sign(missingManufacturer)
	require.NoError(t, err)

	missingModelASN1 := []byte(fmt.Sprintf(`{"extraNames":[{"type": %q, "value": %q},{"type": %q, "value": %q}]}`, oidTPMManufacturer, "1414747215", oidTPMVersion, "7.55"))
	sans = []x509util.SubjectAlternativeName{
		{Type: x509util.DirectoryNameType,
			ASN1Value: missingModelASN1},
	}
	ext, err = createSubjectAltNameExtension(nil, nil, nil, nil, sans, true)
	require.NoError(t, err)
	missingModel := getBase()
	ext.Set(missingModel)

	missingModel, err = ca.Sign(missingModel)
	require.NoError(t, err)

	missingFirmwareVersionASN1 := []byte(fmt.Sprintf(`{"extraNames":[{"type": %q, "value": %q},{"type": %q, "value": %q}]}`, oidTPMManufacturer, "1414747215", oidTPMModel, "SLB 9670 TPM2.0"))
	sans = []x509util.SubjectAlternativeName{
		{Type: x509util.DirectoryNameType,
			ASN1Value: missingFirmwareVersionASN1},
	}
	ext, err = createSubjectAltNameExtension(nil, nil, nil, nil, sans, true)
	require.NoError(t, err)
	missingFirmwareVersion := getBase()
	ext.Set(missingFirmwareVersion)

	missingFirmwareVersion, err = ca.Sign(missingFirmwareVersion)
	require.NoError(t, err)

	tests := []struct {
		name   string
		c      *x509.Certificate
		expErr error
	}{
		{"ok", ok, nil},
		{"fail/missing-manufacturer", missingManufacturer, errors.New("missing TPM manufacturer")},
		{"fail/missing-model", missingModel, errors.New("missing TPM model")},
		{"fail/missing-firmware-version", missingFirmwareVersion, errors.New("missing TPM version")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAKCertificateSubjectAlternativeNames(tt.c)
			if tt.expErr != nil {
				if assert.Error(t, err) {
					assert.EqualError(t, err, tt.expErr.Error())
				}
				return
			}

			assert.NoError(t, err)
		})
	}
}

func Test_validateAKCertificateExtendedKeyUsage(t *testing.T) {
	ok := generateValidAKCertificate(t)
	missingEKU := &x509.Certificate{}
	t.Helper()
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		PublicKey:   signer.Public(),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	ca, err := minica.New()
	require.NoError(t, err)
	wrongEKU, err := ca.Sign(template)
	require.NoError(t, err)
	emptyEKU, err := ca.Sign(&x509.Certificate{
		PublicKey: signer.Public(),
		ExtraExtensions: []pkix.Extension{{
			Id:    oidExtensionExtendedKeyUsage,
			Value: []byte{0x30, 0x00}, // DER: empty SEQUENCE
		}},
	})
	require.NoError(t, err)

	tests := []struct {
		name   string
		c      *x509.Certificate
		expErr error
	}{
		{"ok", ok, nil},
		{"fail/wrong-eku", wrongEKU, errors.New("AK certificate is missing Extended Key Usage value tcg-kp-AIKCertificate (2.23.133.8.3)")},
		{"fail/empty-eku", emptyEKU, errors.New("AK certificate is missing Extended Key Usage value tcg-kp-AIKCertificate (2.23.133.8.3)")},
		{"fail/missing-eku", missingEKU, errors.New("AK certificate is missing Extended Key Usage extension")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAKCertificateExtendedKeyUsage(tt.c)
			if tt.expErr != nil {
				if assert.Error(t, err) {
					assert.EqualError(t, err, tt.expErr.Error())
				}
				return
			}

			assert.NoError(t, err)
		})
	}
}

// createSubjectAltNameExtension will construct an Extension containing all
// SubjectAlternativeNames held in a Certificate. It implements more types than
// the golang x509 library, so it is used whenever OtherName or RegisteredID
// type SANs are present in the certificate.
//
// See also https://datatracker.ietf.org/doc/html/rfc5280.html#section-4.2.1.6
//
// TODO(hs): this was copied from go.step.sm/crypto/x509util to make it easier
// to create the SAN extension for testing purposes. Should it be exposed instead?
func createSubjectAltNameExtension(dnsNames, emailAddresses x509util.MultiString, ipAddresses x509util.MultiIP, uris x509util.MultiURL, sans []x509util.SubjectAlternativeName, subjectIsEmpty bool) (x509util.Extension, error) {
	var zero x509util.Extension

	var rawValues []asn1.RawValue
	for _, dnsName := range dnsNames {
		rawValue, err := x509util.SubjectAlternativeName{
			Type: x509util.DNSType, Value: dnsName,
		}.RawValue()
		if err != nil {
			return zero, err
		}

		rawValues = append(rawValues, rawValue)
	}

	for _, emailAddress := range emailAddresses {
		rawValue, err := x509util.SubjectAlternativeName{
			Type: x509util.EmailType, Value: emailAddress,
		}.RawValue()
		if err != nil {
			return zero, err
		}

		rawValues = append(rawValues, rawValue)
	}

	for _, ip := range ipAddresses {
		rawValue, err := x509util.SubjectAlternativeName{
			Type: x509util.IPType, Value: ip.String(),
		}.RawValue()
		if err != nil {
			return zero, err
		}

		rawValues = append(rawValues, rawValue)
	}

	for _, uri := range uris {
		rawValue, err := x509util.SubjectAlternativeName{
			Type: x509util.URIType, Value: uri.String(),
		}.RawValue()
		if err != nil {
			return zero, err
		}

		rawValues = append(rawValues, rawValue)
	}

	for _, san := range sans {
		rawValue, err := san.RawValue()
		if err != nil {
			return zero, err
		}

		rawValues = append(rawValues, rawValue)
	}

	// Now marshal the rawValues into the ASN1 sequence, and create an Extension object to hold the extension
	rawBytes, err := asn1.Marshal(rawValues)
	if err != nil {
		return zero, fmt.Errorf("error marshaling SubjectAlternativeName extension to ASN1: %w", err)
	}

	return x509util.Extension{
		ID:       x509util.ObjectIdentifier(oidSubjectAlternativeName),
		Critical: subjectIsEmpty,
		Value:    rawBytes,
	}, nil
}
