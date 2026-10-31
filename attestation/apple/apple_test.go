package apple

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/minica"

	"github.com/smallstep/certificates/attestation"
)

func TestVerify(t *testing.T) {
	ca, err := minica.New()
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(ca.Root)

	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leaf, err := ca.Sign(&x509.Certificate{
		Subject:   pkix.Name{CommonName: "attestation cert"},
		PublicKey: signer.Public(),
		ExtraExtensions: []pkix.Extension{
			{Id: oidAppleSerialNumber, Value: []byte("serial-number")},
			{Id: oidAppleUniqueDeviceIdentifier, Value: []byte("udid")},
			{Id: oidAppleSecureEnclaveProcessorOSVersion, Value: []byte("16.0")},
			{Id: oidAppleNonce, Value: []byte("nonce")},
		},
	})
	require.NoError(t, err)
	fingerprint, err := keyutil.Fingerprint(signer.Public())
	require.NoError(t, err)

	tests := []struct {
		name    string
		attStmt map[string]any
		roots   *x509.CertPool
		want    *Data
		wantErr bool
	}{
		{"ok", map[string]any{
			"x5c": []any{leaf.Raw, ca.Intermediate.Raw},
		}, roots, &Data{
			Nonce:        []byte("nonce"),
			SerialNumber: "serial-number",
			UDID:         "udid",
			SEPVersion:   "16.0",
			Certificate:  leaf,
			Fingerprint:  fingerprint,
		}, false},
		{"fail apple issuer", map[string]any{
			"x5c": []any{leaf.Raw, ca.Intermediate.Raw},
		}, nil, nil, true},
		{"fail missing x5c", map[string]any{
			"foo": "bar",
		}, roots, nil, true},
		{"fail empty issuer", map[string]any{
			"x5c": []any{},
		}, roots, nil, true},
		{"fail leaf type", map[string]any{
			"x5c": []any{"leaf", ca.Intermediate.Raw},
		}, roots, nil, true},
		{"fail leaf parse", map[string]any{
			"x5c": []any{leaf.Raw[:100], ca.Intermediate.Raw},
		}, roots, nil, true},
		{"fail intermediate type", map[string]any{
			"x5c": []any{leaf.Raw, "intermediate"},
		}, roots, nil, true},
		{"fail intermediate parse", map[string]any{
			"x5c": []any{leaf.Raw, ca.Intermediate.Raw[:100]},
		}, roots, nil, true},
		{"fail verify", map[string]any{
			"x5c": []any{leaf.Raw},
		}, roots, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Verify(tt.attStmt, tt.roots)
			if tt.wantErr {
				assert.ErrorIs(t, err, attestation.ErrInvalidEvidence)
				assert.Nil(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
