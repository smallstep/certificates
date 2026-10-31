package androidkey

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"

	keyattestation "github.com/smallstep/android-attestation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/minica"

	"github.com/smallstep/certificates/attestation"
)

// keyAuth is the key authorization the attestation statements sign.
var keyAuth = []byte("token.thumbprint")

func notRevoked(context.Context, *x509.Certificate) (bool, error) {
	return false, nil
}

func TestVerify(t *testing.T) {
	ca, err := minica.New()
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(ca.Root)

	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	fingerprint, err := keyutil.Fingerprint(signer.Public())
	require.NoError(t, err)

	keyDescription, err := keyattestation.CreateKeyDescription(&keyattestation.KeyDescription{
		AttestationVersion:       300,
		AttestationSecurityLevel: 1,
		AttestationChallenge:     keyAuth,
		TeeEnforced: keyattestation.AuthorizationList{
			AttestationIdSerial: []byte("serial-number"),
		},
	})
	require.NoError(t, err)

	makeLeaf := func(exts ...pkix.Extension) *x509.Certificate {
		leaf, err := ca.Sign(&x509.Certificate{
			Subject:         pkix.Name{CommonName: "attestation cert"},
			PublicKey:       signer.Public(),
			ExtraExtensions: exts,
		})
		require.NoError(t, err)
		return leaf
	}
	leaf := makeLeaf(pkix.Extension{Id: oidAndroidAttestation, Value: keyDescription})
	leafWithoutExtension := makeLeaf()
	leafWithBadExtension := makeLeaf(pkix.Extension{Id: oidAndroidAttestation, Value: []byte("bad")})

	keyAuthSum := sha256.Sum256(keyAuth)
	sig, err := signer.Sign(rand.Reader, keyAuthSum[:], crypto.SHA256)
	require.NoError(t, err)

	otherSigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	otherSig, err := otherSigner.Sign(rand.Reader, keyAuthSum[:], crypto.SHA256)
	require.NoError(t, err)

	otherKeyAuth := []byte("other.thumbprint")
	otherKeyAuthSum := sha256.Sum256(otherKeyAuth)
	otherKeyAuthSig, err := signer.Sign(rand.Reader, otherKeyAuthSum[:], crypto.SHA256)
	require.NoError(t, err)

	x5c := []any{leaf.Raw, ca.Intermediate.Raw, ca.Root.Raw}
	errCRL := errors.New("crl unavailable")

	t.Run("ok", func(t *testing.T) {
		got, err := Verify(context.Background(), map[string]any{"x5c": x5c, "sig": sig}, roots, keyAuth, notRevoked)
		require.NoError(t, err)
		assert.Equal(t, leaf, got.Certificate)
		assert.Equal(t, fingerprint, got.Fingerprint)
		if assert.NotNil(t, got.KeyDescription) {
			assert.Equal(t, keyAuth, got.KeyDescription.AttestationChallenge)
			assert.Equal(t, keyattestation.SecurityLevel(1), got.KeyDescription.AttestationSecurityLevel)
			assert.Equal(t, []byte("serial-number"), got.KeyDescription.TeeEnforced.AttestationIdSerial)
		}
	})

	revokedRoot := func(_ context.Context, cert *x509.Certificate) (bool, error) {
		return cert.SerialNumber.Cmp(ca.Root.SerialNumber) == 0, nil
	}
	failingCRL := func(context.Context, *x509.Certificate) (bool, error) {
		return true, errCRL
	}

	type args struct {
		attStmt   map[string]any
		roots     *x509.CertPool
		keyAuth   []byte
		isRevoked RevocationChecker
	}
	tests := []struct {
		name    string
		args    args
		invalid bool
		wantErr error
		msg     string
	}{
		{"fail no revocation checker", args{map[string]any{"x5c": x5c, "sig": sig}, roots, keyAuth, nil},
			false, nil, "requires a revocation checker"},
		{"fail google roots", args{map[string]any{"x5c": x5c, "sig": sig}, nil, keyAuth, notRevoked},
			true, nil, "root certificate in chain is not trusted"},
		{"fail x5c not present", args{map[string]any{"sig": sig}, roots, keyAuth, notRevoked},
			true, nil, "x5c not present"},
		{"fail x5c empty", args{map[string]any{"x5c": []any{}, "sig": sig}, roots, keyAuth, notRevoked},
			true, ErrEmptyX5C, "x5c is empty"},
		{"fail x5c element type", args{map[string]any{"x5c": []any{"leaf", ca.Intermediate.Raw, ca.Root.Raw}, "sig": sig}, roots, keyAuth, notRevoked},
			true, nil, "x5c element is malformed"},
		{"fail x5c element parse", args{map[string]any{"x5c": []any{leaf.Raw[:100], ca.Intermediate.Raw, ca.Root.Raw}, "sig": sig}, roots, keyAuth, notRevoked},
			true, nil, "failed parsing certificate at index 0"},
		{"fail revoked", args{map[string]any{"x5c": x5c, "sig": sig}, roots, keyAuth, revokedRoot},
			true, nil, "x5c element contains a revoked certificate"},
		{"fail revocation check", args{map[string]any{"x5c": x5c, "sig": sig}, roots, keyAuth, failingCRL},
			false, errCRL, "failed checking certificate revocation status"},
		{"fail missing root", args{map[string]any{"x5c": []any{leaf.Raw}, "sig": sig}, roots, keyAuth, notRevoked},
			true, nil, "missing root certificate in x5c chain"},
		{"fail chain verification", args{map[string]any{"x5c": []any{leaf.Raw, ca.Root.Raw}, "sig": sig}, roots, keyAuth, notRevoked},
			true, nil, "x5c chain verification failed"},
		{"fail sig not present", args{map[string]any{"x5c": x5c}, roots, keyAuth, notRevoked},
			true, nil, "sig not present"},
		{"fail sig verify", args{map[string]any{"x5c": x5c, "sig": otherSig}, roots, keyAuth, notRevoked},
			true, nil, "failed validating signature"},
		{"fail no attestation certificate", args{map[string]any{"x5c": []any{leafWithoutExtension.Raw, ca.Intermediate.Raw, ca.Root.Raw}, "sig": sig}, roots, keyAuth, notRevoked},
			true, nil, "no attestation certificate with OID 1.3.6.1.4.1.11129.2.1.17 found"},
		{"fail key description", args{map[string]any{"x5c": []any{leafWithBadExtension.Raw, ca.Intermediate.Raw, ca.Root.Raw}, "sig": sig}, roots, keyAuth, notRevoked},
			true, ErrKeyDescription, "error parsing attestation"},
		{"fail challenge mismatch", args{map[string]any{"x5c": x5c, "sig": otherKeyAuthSig}, roots, otherKeyAuth, notRevoked},
			true, nil, `challenge mismatch; expected "other.thumbprint", got "token.thumbprint"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Verify(context.Background(), tt.args.attStmt, tt.args.roots, tt.args.keyAuth, tt.args.isRevoked)
			require.Error(t, err)
			assert.ErrorContains(t, err, tt.msg)
			assert.Equal(t, tt.invalid, errors.Is(err, attestation.ErrInvalidEvidence), "errors.Is(%v, attestation.ErrInvalidEvidence)", err)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			}
			assert.Nil(t, got)
		})
	}
}
