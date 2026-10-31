package yubikey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"slices"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/minica"

	"github.com/smallstep/certificates/attestation"
)

type stepManagedDevice struct {
	DeviceID string
}

// keyAuth is the key authorization the attestation statements sign.
var keyAuth = []byte("token.thumbprint")

func TestVerify(t *testing.T) {
	ca, err := minica.New()
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(ca.Root)

	makeLeaf := func(signer crypto.Signer, serialNumber []byte) *x509.Certificate {
		leaf, err := ca.Sign(&x509.Certificate{
			Subject:   pkix.Name{CommonName: "attestation cert"},
			PublicKey: signer.Public(),
			ExtraExtensions: []pkix.Extension{
				{Id: oidYubicoSerialNumber, Value: serialNumber},
			},
		})
		require.NoError(t, err)
		return leaf
	}

	makeLeafWithStepManagedDeviceID := func(signer crypto.Signer, serialNumber string) *x509.Certificate {
		v, err := asn1.Marshal(stepManagedDevice{DeviceID: serialNumber})
		require.NoError(t, err)
		leaf, err := ca.Sign(&x509.Certificate{
			Subject:   pkix.Name{CommonName: "attestation cert"},
			PublicKey: signer.Public(),
			ExtraExtensions: []pkix.Extension{
				{Id: oidStepManagedDevice, Value: v},
			},
		})
		require.NoError(t, err)
		return leaf
	}

	mustSigner := func(kty, crv string, size int) crypto.Signer {
		s, err := keyutil.GenerateSigner(kty, crv, size)
		require.NoError(t, err)
		return s
	}

	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	fingerprint, err := keyutil.Fingerprint(signer.Public())
	require.NoError(t, err)

	serialNumber, err := asn1.Marshal(1234)
	require.NoError(t, err)

	leaf := makeLeaf(signer, serialNumber)
	leafWithStepManagedDeviceID := makeLeafWithStepManagedDeviceID(signer, "1234")

	keyAuthSum := sha256.Sum256(keyAuth)
	sig, err := signer.Sign(rand.Reader, keyAuthSum[:], crypto.SHA256)
	require.NoError(t, err)

	cborSig, err := cbor.Marshal(sig)
	require.NoError(t, err)

	otherSigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	otherSig, err := otherSigner.Sign(rand.Reader, keyAuthSum[:], crypto.SHA256)
	require.NoError(t, err)

	otherCBORSig, err := cbor.Marshal(otherSig)
	require.NoError(t, err)

	tests := []struct {
		name    string
		attStmt map[string]any
		roots   *x509.CertPool
		want    *Data
		wantErr error
	}{
		{"ok", map[string]any{
			"x5c": []any{leaf.Raw, ca.Intermediate.Raw},
			"alg": -7,
			"sig": cborSig,
		}, roots, &Data{
			SerialNumber: "1234",
			Certificate:  leaf,
			Fingerprint:  fingerprint,
		}, nil},
		{"ok/step-managed-device-id", map[string]any{
			"x5c": []any{leafWithStepManagedDeviceID.Raw, ca.Intermediate.Raw},
			"alg": -7,
			"sig": cborSig,
		}, roots, &Data{
			SerialNumber: "1234",
			Certificate:  leafWithStepManagedDeviceID,
			Fingerprint:  fingerprint,
		}, nil},
		{"fail yubico issuer", map[string]any{
			"x5c": []any{leaf.Raw, ca.Intermediate.Raw},
			"alg": -7,
			"sig": cborSig,
		}, nil, nil, attestation.ErrInvalidEvidence},
		{"fail x5c type", map[string]any{
			"x5c": [][]byte{leaf.Raw, ca.Intermediate.Raw},
			"alg": -7,
			"sig": cborSig,
		}, roots, nil, attestation.ErrInvalidEvidence},
		{"fail x5c empty", map[string]any{
			"x5c": []any{},
			"alg": -7,
			"sig": cborSig,
		}, roots, nil, ErrEmptyX5C},
		{"fail leaf type", map[string]any{
			"x5c": []any{"leaf", ca.Intermediate.Raw},
			"alg": -7,
			"sig": cborSig,
		}, roots, nil, attestation.ErrInvalidEvidence},
		{"fail leaf parse", map[string]any{
			"x5c": []any{leaf.Raw[:100], ca.Intermediate.Raw},
			"alg": -7,
			"sig": cborSig,
		}, roots, nil, attestation.ErrInvalidEvidence},
		{"fail intermediate type", map[string]any{
			"x5c": []any{leaf.Raw, "intermediate"},
			"alg": -7,
			"sig": cborSig,
		}, roots, nil, attestation.ErrInvalidEvidence},
		{"fail intermediate parse", map[string]any{
			"x5c": []any{leaf.Raw, ca.Intermediate.Raw[:100]},
			"alg": -7,
			"sig": cborSig,
		}, roots, nil, attestation.ErrInvalidEvidence},
		{"fail verify", map[string]any{
			"x5c": []any{leaf.Raw},
			"alg": -7,
			"sig": cborSig,
		}, roots, nil, attestation.ErrInvalidEvidence},
		{"fail sig type", map[string]any{
			"x5c": []any{leaf.Raw, ca.Intermediate.Raw},
			"alg": -7,
			"sig": string(cborSig),
		}, roots, nil, attestation.ErrInvalidEvidence},
		{"fail sig unmarshal", map[string]any{
			"x5c": []any{leaf.Raw, ca.Intermediate.Raw},
			"alg": -7,
			"sig": []byte("bad-sig"),
		}, roots, nil, attestation.ErrInvalidEvidence},
		{"fail sig verify P-256", map[string]any{
			"x5c": []any{leaf.Raw, ca.Intermediate.Raw},
			"alg": -7,
			"sig": otherCBORSig,
		}, roots, nil, attestation.ErrInvalidEvidence},
		{"fail sig verify P-384", map[string]any{
			"x5c": []any{makeLeaf(mustSigner("EC", "P-384", 0), serialNumber).Raw, ca.Intermediate.Raw},
			"alg": -7,
			"sig": cborSig,
		}, roots, nil, attestation.ErrInvalidEvidence},
		{"fail sig verify RSA", map[string]any{
			"x5c": []any{makeLeaf(mustSigner("RSA", "", 2048), serialNumber).Raw, ca.Intermediate.Raw},
			"alg": -7,
			"sig": cborSig,
		}, roots, nil, attestation.ErrInvalidEvidence},
		{"fail sig verify Ed25519", map[string]any{
			"x5c": []any{makeLeaf(mustSigner("OKP", "Ed25519", 0), serialNumber).Raw, ca.Intermediate.Raw},
			"alg": -7,
			"sig": cborSig,
		}, roots, nil, attestation.ErrInvalidEvidence},
		{"fail unmarshal serial number", map[string]any{
			"x5c": []any{makeLeaf(signer, []byte("bad-serial")).Raw, ca.Intermediate.Raw},
			"alg": -7,
			"sig": cborSig,
		}, roots, nil, ErrSerialNumber},
		{"fail serial number trailing data", map[string]any{
			"x5c": []any{makeLeaf(signer, slices.Concat(serialNumber, []byte{0})).Raw, ca.Intermediate.Raw},
			"alg": -7,
			"sig": cborSig,
		}, roots, nil, ErrSerialNumber},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Verify(tt.attStmt, tt.roots, keyAuth)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, attestation.ErrInvalidEvidence)
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Nil(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestVerify_noCAIntermediate(t *testing.T) {
	// This CA simulates a YubiKey v5.2.4, where the attestation intermediate in
	// the CA does not have the basic constraint extension. With the current
	// validation of the certificate the test case below returns an error. If
	// we change the validation to support this use case, the test case below
	// should change.
	//
	// See https://github.com/Yubico/yubikey-manager/issues/522
	ca, err := minica.New(minica.WithIntermediateTemplate(`{"subject": {{ toJson .Subject }}}`))
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(ca.Root)

	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serialNumber, err := asn1.Marshal(1234)
	require.NoError(t, err)
	leaf, err := ca.Sign(&x509.Certificate{
		Subject:   pkix.Name{CommonName: "attestation cert"},
		PublicKey: signer.Public(),
		ExtraExtensions: []pkix.Extension{
			{Id: oidYubicoSerialNumber, Value: serialNumber},
		},
	})
	require.NoError(t, err)

	keyAuthSum := sha256.Sum256(keyAuth)
	sig, err := signer.Sign(rand.Reader, keyAuthSum[:], crypto.SHA256)
	require.NoError(t, err)
	cborSig, err := cbor.Marshal(sig)
	require.NoError(t, err)

	got, err := Verify(map[string]any{
		"x5c": []any{leaf.Raw, ca.Intermediate.Raw},
		"alg": -7,
		"sig": cborSig,
	}, roots, keyAuth)
	assert.ErrorIs(t, err, attestation.ErrInvalidEvidence)
	assert.Nil(t, got)
}
