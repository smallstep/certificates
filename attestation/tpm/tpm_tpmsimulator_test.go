//go:build tpmsimulator

package tpm

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"testing"

	"github.com/smallstep/go-attestation/attest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/minica"
	steptpm "go.step.sm/crypto/tpm"
	"go.step.sm/crypto/tpm/simulator"
	tpmstorage "go.step.sm/crypto/tpm/storage"
	"go.step.sm/crypto/x509util"

	"github.com/smallstep/certificates/attestation"
)

// keyAuth is the key authorization the attested key certifies.
var keyAuth = []byte("token.thumbprint")

func invalidEvidence(msg string) error {
	return attestation.Invalidf("%s", msg)
}

func newSimulatedTPM(t *testing.T) *steptpm.TPM {
	t.Helper()
	tmpDir := t.TempDir()
	tpm, err := steptpm.New(withSimulator(t), steptpm.WithStore(tpmstorage.NewDirstore(tmpDir))) // TODO: provide in-memory storage implementation instead
	require.NoError(t, err)
	return tpm
}

func withSimulator(t *testing.T) steptpm.NewTPMOption {
	t.Helper()
	var sim simulator.Simulator
	t.Cleanup(func() {
		if sim == nil {
			return
		}
		err := sim.Close()
		require.NoError(t, err)
	})
	sim, err := simulator.New()
	require.NoError(t, err)
	err = sim.Open()
	require.NoError(t, err)
	return steptpm.WithSimulator(sim)
}

func generateKeyID(t *testing.T, pub crypto.PublicKey) []byte {
	t.Helper()
	b, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	hash := sha256.Sum256(b)
	return hash[:]
}

func TestVerify(t *testing.T) {
	aca, err := minica.New(
		minica.WithName("TPM Testing"),
		minica.WithGetSignerFunc(
			func() (crypto.Signer, error) {
				return keyutil.GenerateSigner("RSA", "", 2048)
			},
		),
	)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(aca.Root)

	// prepare simulated TPM and create an AK
	stpm := newSimulatedTPM(t)
	eks, err := stpm.GetEKs(context.Background())
	require.NoError(t, err)
	ak, err := stpm.CreateAK(context.Background(), "first-ak")
	require.NoError(t, err)
	require.NotNil(t, ak)

	// extract the AK public key // TODO(hs): replace this when there's a simpler method to get the AK public key (e.g. ak.Public())
	ap, err := ak.AttestationParameters(context.Background())
	require.NoError(t, err)
	akp, err := attest.ParseAKPublic(attest.TPMVersion20, ap.Public)
	require.NoError(t, err)

	// create template and sign certificate for the AK public key
	keyID := generateKeyID(t, eks[0].Public())
	template := &x509.Certificate{
		PublicKey:          akp.Public,
		IsCA:               false,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{oidTCGKpAIKCertificate},
	}
	sans := []x509util.SubjectAlternativeName{}
	uris := []*url.URL{{Scheme: "urn", Opaque: "ek:sha256:" + base64.StdEncoding.EncodeToString(keyID)}}
	asn1Value := []byte(fmt.Sprintf(`{"extraNames":[{"type": %q, "value": %q},{"type": %q, "value": %q},{"type": %q, "value": %q}]}`, oidTPMManufacturer, "1414747215", oidTPMModel, "SLB 9670 TPM2.0", oidTPMVersion, "7.55"))
	sans = append(sans, x509util.SubjectAlternativeName{
		Type:      x509util.DirectoryNameType,
		ASN1Value: asn1Value,
	})
	ext, err := createSubjectAltNameExtension(nil, nil, nil, uris, sans, true)
	require.NoError(t, err)
	ext.Set(template)
	akCert, err := aca.Sign(template)
	require.NoError(t, err)
	require.NotNil(t, akCert)

	invalidTemplate := &x509.Certificate{
		PublicKey:          akp.Public,
		IsCA:               false,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{oidTCGKpAIKCertificate},
	}
	invalidAKCert, err := aca.Sign(invalidTemplate)
	require.NoError(t, err)
	require.NotNil(t, invalidAKCert)

	// create a new key attested by the AK, while including
	// the key authorization bytes as qualifying data.
	keyAuthSum := sha256.Sum256(keyAuth)
	config := steptpm.AttestKeyConfig{
		Algorithm:      "RSA",
		Size:           2048,
		QualifyingData: keyAuthSum[:],
	}
	key, err := stpm.AttestKey(context.Background(), "first-ak", "first-key", config)
	require.NoError(t, err)
	require.NotNil(t, key)
	params, err := key.CertificationParameters(context.Background())
	require.NoError(t, err)

	signer, err := key.Signer(context.Background())
	require.NoError(t, err)
	fingerprint, err := keyutil.Fingerprint(signer.Public())
	require.NoError(t, err)

	// attest another key and get its certification parameters
	anotherKey, err := stpm.AttestKey(context.Background(), "first-ak", "another-key", config)
	require.NoError(t, err)
	require.NotNil(t, key)
	anotherKeyParams, err := anotherKey.CertificationParameters(context.Background())
	require.NoError(t, err)

	type args struct {
		roots   *x509.CertPool
		keyAuth []byte
		attStmt map[string]any
	}
	tests := []struct {
		name   string
		args   args
		want   *Data
		expErr error
	}{
		{"ok", args{roots, keyAuth, map[string]any{
			"ver":      "2.0",
			"x5c":      []any{akCert.Raw, aca.Intermediate.Raw},
			"alg":      int64(-257), // RS256
			"sig":      params.CreateSignature,
			"certInfo": params.CreateAttestation,
			"pubArea":  params.Public,
		}}, nil, nil},
		{"fail ver not present", args{roots, keyAuth, map[string]any{
			"x5c":      []any{akCert.Raw, aca.Intermediate.Raw},
			"alg":      int64(-257), // RS256
			"sig":      params.CreateSignature,
			"certInfo": params.CreateAttestation,
			"pubArea":  params.Public,
		}}, nil, invalidEvidence("ver not present")},
		{"fail ver type", args{roots, keyAuth, map[string]any{
			"ver":      []any{},
			"x5c":      []any{akCert.Raw, aca.Intermediate.Raw},
			"alg":      int64(-257), // RS256
			"sig":      params.CreateSignature,
			"certInfo": params.CreateAttestation,
			"pubArea":  params.Public,
		}}, nil, invalidEvidence("ver not present")},
		{"fail bogus ver", args{roots, keyAuth, map[string]any{
			"ver":      "bogus",
			"x5c":      []any{akCert.Raw, aca.Intermediate.Raw},
			"alg":      int64(-257), // RS256
			"sig":      params.CreateSignature,
			"certInfo": params.CreateAttestation,
			"pubArea":  params.Public,
		}}, nil, invalidEvidence(`version "bogus" is not supported`)},
		{"fail x5c not present", args{roots, keyAuth, map[string]any{
			"ver":      "2.0",
			"alg":      int64(-257), // RS256
			"sig":      params.CreateSignature,
			"certInfo": params.CreateAttestation,
			"pubArea":  params.Public,
		}}, nil, invalidEvidence("x5c not present")},
		{"fail x5c type", args{roots, keyAuth, map[string]any{
			"ver":      "2.0",
			"x5c":      [][]byte{akCert.Raw, aca.Intermediate.Raw},
			"alg":      int64(-257), // RS256
			"sig":      params.CreateSignature,
			"certInfo": params.CreateAttestation,
			"pubArea":  params.Public,
		}}, nil, invalidEvidence("x5c not present")},
		{"fail x5c empty", args{roots, keyAuth, map[string]any{
			"ver":      "2.0",
			"x5c":      []any{},
			"alg":      int64(-257), // RS256
			"sig":      params.CreateSignature,
			"certInfo": params.CreateAttestation,
			"pubArea":  params.Public,
		}}, nil, invalidEvidence("x5c is empty")},
		{"fail leaf type", args{roots, keyAuth, map[string]any{
			"ver":      "2.0",
			"x5c":      []any{"leaf", aca.Intermediate.Raw},
			"alg":      int64(-257), // RS256
			"sig":      params.CreateSignature,
			"certInfo": params.CreateAttestation,
			"pubArea":  params.Public,
		}}, nil, invalidEvidence("x5c is malformed")},
		{"fail leaf parse", args{roots, keyAuth, map[string]any{
			"ver":      "2.0",
			"x5c":      []any{akCert.Raw[:100], aca.Intermediate.Raw},
			"alg":      int64(-257), // RS256
			"sig":      params.CreateSignature,
			"certInfo": params.CreateAttestation,
			"pubArea":  params.Public,
		}}, nil, invalidEvidence("x5c is malformed: x509: malformed certificate")},
		{"fail intermediate type", args{roots, keyAuth, map[string]any{
			"ver":      "2.0",
			"x5c":      []any{akCert.Raw, "intermediate"},
			"alg":      int64(-257), // RS256
			"sig":      params.CreateSignature,
			"certInfo": params.CreateAttestation,
			"pubArea":  params.Public,
		}}, nil, invalidEvidence("x5c is malformed")},
		{"fail intermediate parse", args{roots, keyAuth, map[string]any{
			"ver":      "2.0",
			"x5c":      []any{akCert.Raw, aca.Intermediate.Raw[:100]},
			"alg":      int64(-257), // RS256
			"sig":      params.CreateSignature,
			"certInfo": params.CreateAttestation,
			"pubArea":  params.Public,
		}}, nil, invalidEvidence("x5c is malformed: x509: malformed certificate")},
		{"fail roots", args{nil, keyAuth, map[string]any{
			"ver":      "2.0",
			"x5c":      []any{akCert.Raw, aca.Intermediate.Raw},
			"alg":      int64(-257), // RS256
			"sig":      params.CreateSignature,
			"certInfo": params.CreateAttestation,
			"pubArea":  params.Public,
		}}, nil, errors.New("no root CA bundle available to verify the attestation certificate")},
		{"fail verify", args{roots, keyAuth, map[string]any{
			"ver":      "2.0",
			"x5c":      []any{akCert.Raw},
			"alg":      int64(-257), // RS256
			"sig":      params.CreateSignature,
			"certInfo": params.CreateAttestation,
			"pubArea":  params.Public,
		}}, nil, invalidEvidence("x5c is not valid: x509: certificate signed by unknown authority")},
		{"fail validateAKCertificate", args{roots, keyAuth, map[string]any{
			"ver":      "2.0",
			"x5c":      []any{invalidAKCert.Raw, aca.Intermediate.Raw},
			"alg":      int64(-257), // RS256
			"sig":      params.CreateSignature,
			"certInfo": params.CreateAttestation,
			"pubArea":  params.Public,
		}}, nil, invalidEvidence("AK certificate is not valid: missing TPM manufacturer")},
		{"fail pubArea not present", args{roots, keyAuth, map[string]any{
			"ver":      "2.0",
			"x5c":      []any{akCert.Raw, aca.Intermediate.Raw},
			"alg":      int64(-257), // RS256
			"sig":      params.CreateSignature,
			"certInfo": params.CreateAttestation,
		}}, nil, invalidEvidence("invalid pubArea in attestation statement")},
		{"fail pubArea type", args{roots, keyAuth, map[string]any{
			"ver":      "2.0",
			"x5c":      []any{akCert.Raw, aca.Intermediate.Raw},
			"alg":      int64(-257), // RS256
			"sig":      params.CreateSignature,
			"certInfo": params.CreateAttestation,
			"pubArea":  []any{},
		}}, nil, invalidEvidence("invalid pubArea in attestation statement")},
		{"fail pubArea empty", args{roots, keyAuth, map[string]any{
			"ver":      "2.0",
			"x5c":      []any{akCert.Raw, aca.Intermediate.Raw},
			"alg":      int64(-257), // RS256
			"sig":      params.CreateSignature,
			"certInfo": params.CreateAttestation,
			"pubArea":  []byte{},
		}}, nil, invalidEvidence("pubArea is empty")},
		{"fail sig not present", args{roots, keyAuth, map[string]any{
			"ver":      "2.0",
			"x5c":      []any{akCert.Raw, aca.Intermediate.Raw},
			"alg":      int64(-257), // RS256
			"certInfo": params.CreateAttestation,
			"pubArea":  params.Public,
		}}, nil, invalidEvidence("invalid sig in attestation statement")},
		{"fail sig type", args{roots, keyAuth, map[string]any{
			"ver":      "2.0",
			"x5c":      []any{akCert.Raw, aca.Intermediate.Raw},
			"alg":      int64(-257), // RS256
			"sig":      []any{},
			"certInfo": params.CreateAttestation,
			"pubArea":  params.Public,
		}}, nil, invalidEvidence("invalid sig in attestation statement")},
		{"fail sig empty", args{roots, keyAuth, map[string]any{
			"ver":      "2.0",
			"x5c":      []any{akCert.Raw, aca.Intermediate.Raw},
			"alg":      int64(-257), // RS256
			"sig":      []byte{},
			"certInfo": params.CreateAttestation,
			"pubArea":  params.Public,
		}}, nil, invalidEvidence("sig is empty")},
		{"fail certInfo not present", args{roots, keyAuth, map[string]any{
			"ver":     "2.0",
			"x5c":     []any{akCert.Raw, aca.Intermediate.Raw},
			"alg":     int64(-257), // RS256
			"sig":     params.CreateSignature,
			"pubArea": params.Public,
		}}, nil, invalidEvidence("invalid certInfo in attestation statement")},
		{"fail certInfo type", args{roots, keyAuth, map[string]any{
			"ver":      "2.0",
			"x5c":      []any{akCert.Raw, aca.Intermediate.Raw},
			"alg":      int64(-257), // RS256
			"sig":      params.CreateSignature,
			"certInfo": []any{},
			"pubArea":  params.Public,
		}}, nil, invalidEvidence("invalid certInfo in attestation statement")},
		{"fail certInfo empty", args{roots, keyAuth, map[string]any{
			"ver":      "2.0",
			"x5c":      []any{akCert.Raw, aca.Intermediate.Raw},
			"alg":      int64(-257), // RS256
			"sig":      params.CreateSignature,
			"certInfo": []byte{},
			"pubArea":  params.Public,
		}}, nil, invalidEvidence("certInfo is empty")},
		{"fail alg not present", args{roots, keyAuth, map[string]any{
			"ver":      "2.0",
			"x5c":      []any{akCert.Raw, aca.Intermediate.Raw},
			"sig":      params.CreateSignature,
			"certInfo": params.CreateAttestation,
			"pubArea":  params.Public,
		}}, nil, invalidEvidence("invalid alg in attestation statement")},
		{"fail alg type", args{roots, keyAuth, map[string]any{
			"ver":      "2.0",
			"x5c":      []any{akCert.Raw, aca.Intermediate.Raw},
			"alg":      int64(0), // invalid alg
			"sig":      params.CreateSignature,
			"certInfo": params.CreateAttestation,
			"pubArea":  params.Public,
		}}, nil, invalidEvidence("invalid alg 0 in attestation statement")},
		{"fail attestation verification", args{roots, keyAuth, map[string]any{
			"ver":      "2.0",
			"x5c":      []any{akCert.Raw, aca.Intermediate.Raw},
			"alg":      int64(-257), // RS256
			"sig":      params.CreateSignature,
			"certInfo": params.CreateAttestation,
			"pubArea":  anotherKeyParams.Public,
		}}, nil, invalidEvidence("invalid certification parameters: certification refers to a different key")},
		{"fail different keyAuthorization", args{roots, []byte("aDifferentToken.thumbprint"), map[string]any{
			"ver":      "2.0",
			"x5c":      []any{akCert.Raw, aca.Intermediate.Raw},
			"alg":      int64(-257), //
			"sig":      params.CreateSignature,
			"certInfo": params.CreateAttestation,
			"pubArea":  params.Public,
		}}, nil, invalidEvidence("key authorization invalid")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Verify(tt.args.attStmt, tt.args.roots, tt.args.keyAuth)
			if tt.expErr != nil {
				assert.EqualError(t, err, tt.expErr.Error())
				assert.Equal(t, errors.Is(tt.expErr, attestation.ErrInvalidEvidence), errors.Is(err, attestation.ErrInvalidEvidence))
				assert.Nil(t, got)
				return
			}

			assert.NoError(t, err)
			if assert.NotNil(t, got) {
				assert.Equal(t, akCert, got.Certificate)
				assert.Equal(t, [][]*x509.Certificate{
					{
						akCert, aca.Intermediate, aca.Root,
					},
				}, got.VerifiedChains)
				assert.Equal(t, fingerprint, got.Fingerprint)
				assert.Empty(t, got.PermanentIdentifiers) // currently expected to be always empty
			}
		})
	}
}
