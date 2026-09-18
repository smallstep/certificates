package acme_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/minica"
)

// These are deliberately external-package tests: no ACME database, Challenge,
// context provisioner, or private format helper is available to the caller.
func TestVerifyDeviceAttestation(t *testing.T) {
	ca, err := minica.New()
	require.NoError(t, err)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	account, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
	require.NoError(t, err)
	params := acme.DeviceAttestationParams{Token: "one-time-token", Identifier: "1234", AccountKey: account}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Root)
	prov := &acme.MockProvisioner{MgetAttestationRoots: func() (*x509.CertPool, bool) { return roots, true }}
	serial, err := asn1.Marshal(1234)
	require.NoError(t, err)
	leaf, err := ca.Sign(&x509.Certificate{
		Subject: pkix.Name{CommonName: "test attestation"}, PublicKey: key.Public(),
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 7}, Value: serial}},
	})
	require.NoError(t, err)
	keyAuth, err := acme.KeyAuthorization(params.Token, account)
	require.NoError(t, err)
	digest := sha256.Sum256([]byte(keyAuth))
	signature, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	cborSignature, err := cbor.Marshal(signature)
	require.NoError(t, err)
	statement := map[string]any{"x5c": []any{leaf.Raw, ca.Intermediate.Raw}, "sig": cborSignature}
	marshal := func(format string, stmt map[string]any) []byte {
		b, err := cbor.Marshal(map[string]any{"fmt": format, "attStmt": stmt})
		require.NoError(t, err)
		return b
	}
	object := marshal("step", statement)
	wantFP, err := keyutil.Fingerprint(key.Public())
	require.NoError(t, err)
	t.Run("valid statement binds key challenge and identifier", func(t *testing.T) {
		result, err := acme.VerifyDeviceAttestation(context.Background(), prov, params, object)
		require.NoError(t, err)
		require.Equal(t, &acme.DeviceAttestationResult{
			Format: "step", Fingerprint: wantFP, ChallengeBound: true, IdentifierBound: true,
		}, result)
	})
	for _, tc := range []struct {
		name   string
		change func(*acme.DeviceAttestationParams)
	}{
		{"wrong challenge", func(p *acme.DeviceAttestationParams) { p.Token = "another-token" }},
		{"wrong identifier", func(p *acme.DeviceAttestationParams) { p.Identifier = "5678" }},
		{"missing account key", func(p *acme.DeviceAttestationParams) { p.AccountKey = nil }},
		{"wrong account key", func(p *acme.DeviceAttestationParams) {
			other, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			require.NoError(t, err)
			p.AccountKey = other
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := params
			tc.change(&p)
			result, err := acme.VerifyDeviceAttestation(context.Background(), prov, p, object)
			require.Error(t, err)
			require.Nil(t, result)
		})
	}
	t.Run("untrusted chain", func(t *testing.T) {
		untrusted := &acme.MockProvisioner{MgetAttestationRoots: func() (*x509.CertPool, bool) { return x509.NewCertPool(), true }}
		result, err := acme.VerifyDeviceAttestation(context.Background(), untrusted, params, object)
		require.ErrorContains(t, err, "x5c is not valid")
		require.Nil(t, result)
	})
	t.Run("disabled format", func(t *testing.T) {
		disabled := &acme.MockProvisioner{MisAttFormatEnabled: func(context.Context, provisioner.ACMEAttestationFormat) bool { return false }}
		result, err := acme.VerifyDeviceAttestation(context.Background(), disabled, params, object)
		require.ErrorContains(t, err, "not enabled")
		require.Nil(t, result)
	})
	t.Run("missing provisioner", func(t *testing.T) {
		result, err := acme.VerifyDeviceAttestation(context.Background(), nil, params, object)
		require.ErrorContains(t, err, "attestation provisioner is required")
		require.Nil(t, result)
	})
	for name, data := range map[string][]byte{
		"empty": nil, "malformed": object[:len(object)-1], "unknown format": marshal("unknown", statement),
		"tampered signature": marshal("step", map[string]any{"x5c": statement["x5c"], "sig": []byte{0x41, 0}}),
	} {
		t.Run(name, func(t *testing.T) {
			result, err := acme.VerifyDeviceAttestation(context.Background(), prov, params, data)
			require.Error(t, err)
			require.Nil(t, result)
		})
	}
	for _, noncePresent := range []bool{true, false} {
		name := "Apple with nonce"
		if !noncePresent {
			name = "legacy Apple without nonce reports missing binding"
		}
		t.Run(name, func(t *testing.T) {
			extensions := []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 9, 1}, Value: []byte(params.Identifier)}}
			if noncePresent {
				nonce := sha256.Sum256([]byte(params.Token))
				extensions = append(extensions, pkix.Extension{Id: asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 11, 1}, Value: nonce[:]})
			}
			cert, err := ca.Sign(&x509.Certificate{Subject: pkix.Name{CommonName: "Apple test"}, PublicKey: key.Public(), ExtraExtensions: extensions})
			require.NoError(t, err)
			apple := marshal("apple", map[string]any{"x5c": []any{cert.Raw, ca.Intermediate.Raw}})
			result, err := acme.VerifyDeviceAttestation(context.Background(), prov, params, apple)
			require.NoError(t, err)
			require.Equal(t, noncePresent, result.ChallengeBound)
			require.True(t, result.IdentifierBound)
			require.Equal(t, wantFP, result.Fingerprint)
			// Apple permits matching an absent UDID against an empty expected
			// identifier. Report that compatibility case without claiming a binding.
			empty := params
			empty.Identifier = ""
			unbound, err := acme.VerifyDeviceAttestation(context.Background(), prov, empty, apple)
			require.NoError(t, err)
			require.False(t, unbound.IdentifierBound)
			if noncePresent {
				wrong := params
				wrong.Token = "wrong"
				_, err = acme.VerifyDeviceAttestation(context.Background(), prov, wrong, apple)
				require.ErrorContains(t, err, "challenge token does not match")
			}
		})
	}
}
