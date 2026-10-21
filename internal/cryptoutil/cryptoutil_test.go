package cryptoutil

import (
	"crypto"
	"crypto/dsa" //nolint:staticcheck // DSA is only used to build an unsupported key
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/mldsa"
)

func TestIsSupportedPublicKey(t *testing.T) {
	tests := []struct {
		name string
		pub  crypto.PublicKey
		want bool
	}{
		{"rsa", &rsa.PublicKey{}, true},
		{"ecdsa", &ecdsa.PublicKey{}, true},
		{"ed25519", ed25519.PublicKey{}, true},
		{"mldsa", &mldsa.PublicKey{}, true},
		{"dsa", &dsa.PublicKey{}, false},
		{"rsa value", rsa.PublicKey{}, false},
		{"ecdsa value", ecdsa.PublicKey{}, false},
		{"ed25519 pointer", &ed25519.PublicKey{}, false},
		{"private key", &rsa.PrivateKey{}, false},
		{"bytes", []byte("not a key"), false},
		{"nil", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsSupportedPublicKey(tt.pub))
		})
	}
}

func TestIsSupportedPrivateKey(t *testing.T) {
	tests := []struct {
		name string
		priv crypto.PrivateKey
		want bool
	}{
		{"rsa", &rsa.PrivateKey{}, true},
		{"ecdsa", &ecdsa.PrivateKey{}, true},
		{"ed25519", ed25519.PrivateKey{}, true},
		{"mldsa", &mldsa.PrivateKey{}, true},
		{"dsa", &dsa.PrivateKey{}, false},
		{"rsa value", rsa.PrivateKey{}, false},
		{"ecdsa value", ecdsa.PrivateKey{}, false},
		{"ed25519 pointer", &ed25519.PrivateKey{}, false},
		{"public key", &rsa.PublicKey{}, false},
		{"bytes", []byte("not a key"), false},
		{"nil", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsSupportedPrivateKey(tt.priv))
		})
	}
}

func TestPEMEncode(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	cert := mustCertificate(t, ecdsaKey)
	csr := mustCertificateRequest(t, ecdsaKey)

	type test struct {
		name    string
		key     any
		want    *pem.Block
		wantErr string
	}
	tests := []test{
		{"rsa public key", rsaKey.Public(), &pem.Block{
			Type: "PUBLIC KEY", Bytes: mustPKIX(t, rsaKey.Public()),
		}, ""},
		{"ecdsa public key", ecdsaKey.Public(), &pem.Block{
			Type: "PUBLIC KEY", Bytes: mustPKIX(t, ecdsaKey.Public()),
		}, ""},
		{"ed25519 public key", ed25519Key.Public(), &pem.Block{
			Type: "PUBLIC KEY", Bytes: mustPKIX(t, ed25519Key.Public()),
		}, ""},
		{"rsa private key", rsaKey, &pem.Block{
			Type: "PRIVATE KEY", Bytes: mustPKCS8(t, rsaKey),
		}, ""},
		{"ecdsa private key", ecdsaKey, &pem.Block{
			Type: "PRIVATE KEY", Bytes: mustPKCS8(t, ecdsaKey),
		}, ""},
		{"ed25519 private key", ed25519Key, &pem.Block{
			Type: "PRIVATE KEY", Bytes: mustPKCS8(t, ed25519Key),
		}, ""},
		{"certificate", cert, &pem.Block{
			Type: "CERTIFICATE", Bytes: cert.Raw,
		}, ""},
		{"certificate request", csr, &pem.Block{
			Type: "CERTIFICATE REQUEST", Bytes: csr.Raw,
		}, ""},
		{"fail public key", &ecdsa.PublicKey{}, nil, "error marshaling public key"},
		{"fail private key", &ecdsa.PrivateKey{}, nil, "error marshaling private key"},
		{"fail dsa public key", &dsa.PublicKey{}, nil, "unsupported type *dsa.PublicKey"},
		{"fail bytes", []byte("not a key"), nil, "unsupported type []uint8"},
		{"fail nil", nil, nil, "unsupported type <nil>"},
	}

	// ML-DSA is only available on Go 1.27 and later. On older toolchains the
	// mldsa package is a stub that cannot generate keys, so there is nothing
	// to encode.
	if mldsa.Supported {
		mldsaKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
		require.NoError(t, err)
		tests = append(tests,
			test{"mldsa public key", mldsaKey.Public(), &pem.Block{
				Type: "PUBLIC KEY", Bytes: mustPKIX(t, mldsaKey.Public()),
			}, ""},
			test{"mldsa private key", mldsaKey, &pem.Block{
				Type: "PRIVATE KEY", Bytes: mustPKCS8(t, mldsaKey),
			}, ""},
		)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PEMEncode(tt.key)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				assert.Nil(t, got)
				return
			}

			require.NoError(t, err)
			block, rest := pem.Decode(got)
			require.NotNil(t, block)
			assert.Empty(t, rest)
			assert.Equal(t, tt.want.Type, block.Type)
			assert.Equal(t, tt.want.Bytes, block.Bytes)
			assert.Empty(t, block.Headers)
		})
	}
}

func mustPKIX(t *testing.T, pub crypto.PublicKey) []byte {
	t.Helper()
	b, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	return b
}

func mustPKCS8(t *testing.T, priv crypto.PrivateKey) []byte {
	t.Helper()
	b, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	return b
}

func mustCertificate(t *testing.T, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1234),
		Subject:      pkix.Name{CommonName: "test.smallstep.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func mustCertificateRequest(t *testing.T, signer crypto.Signer) *x509.CertificateRequest {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test.smallstep.com"},
	}, signer)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(der)
	require.NoError(t, err)
	return csr
}
