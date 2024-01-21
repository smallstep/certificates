package scep

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/smallstep/pkcs7"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/minica"
	"go.step.sm/crypto/randutil"
)

func generateContent(t *testing.T, size int) []byte {
	t.Helper()
	b, err := randutil.Bytes(size)
	require.NoError(t, err)
	return b
}

func generateRecipients(t *testing.T) []*x509.Certificate {
	ca, err := minica.New()
	require.NoError(t, err)
	s, err := keyutil.GenerateSigner("RSA", "", 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		PublicKey: s.Public(),
		Subject:   pkix.Name{CommonName: "Test PKCS#7 Encryption"},
	}
	cert, err := ca.Sign(tmpl)
	require.NoError(t, err)
	return []*x509.Certificate{cert}
}

func TestAuthority_encrypt(t *testing.T) {
	t.Parallel()
	a := &Authority{}
	recipients := generateRecipients(t)
	type args struct {
		content    []byte
		recipients []*x509.Certificate
		algorithm  int
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"alg-0", args{generateContent(t, 32), recipients, pkcs7.EncryptionAlgorithmDESCBC}, false},
		{"alg-1", args{generateContent(t, 32), recipients, pkcs7.EncryptionAlgorithmAES128CBC}, false},
		{"alg-2", args{generateContent(t, 32), recipients, pkcs7.EncryptionAlgorithmAES256CBC}, false},
		{"alg-3", args{generateContent(t, 32), recipients, pkcs7.EncryptionAlgorithmAES128GCM}, false},
		{"alg-4", args{generateContent(t, 32), recipients, pkcs7.EncryptionAlgorithmAES256GCM}, false},
		{"alg-unknown", args{generateContent(t, 32), recipients, 42}, true},
	}
	for _, tt := range tests {
		tc := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := a.encrypt(tc.args.content, tc.args.recipients, tc.args.algorithm)
			if tc.wantErr {
				assert.Error(t, err)
				assert.Nil(t, got)
				return
			}

			assert.NoError(t, err)
			assert.NotEmpty(t, got)
		})
	}
}
