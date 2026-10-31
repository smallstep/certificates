package confidentialspace

import (
	"crypto/sha1" //nolint:gosec // Google documents the root's SHA-1 fingerprint
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRoots checks the embedded root against the SHA-1 fingerprint Google
// documents and the SHA-256 fingerprint recorded with it, so that a changed
// file fails.
func TestRoots(t *testing.T) {
	block, rest := pem.Decode(rootPEM)
	require.NotNil(t, block)
	assert.Empty(t, rest)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	sha1Sum := sha1.Sum(cert.Raw) //nolint:gosec // see the import
	sha256Sum := sha256.Sum256(cert.Raw)
	assert.Equal(t, "b95120742c24e3aa34042e1c3ba3aad28b212321", hex.EncodeToString(sha1Sum[:]))
	assert.Equal(t, "148b293821bb0c6a317f413c8ba475814091cb22d49b9e3c94198db8e8f86c39", hex.EncodeToString(sha256Sum[:]))
	assert.Equal(t, "Confidential Space Root CA", cert.Subject.CommonName)
	assert.True(t, cert.IsCA)
	assert.True(t, cert.NotAfter.After(time.Date(2034, time.January, 1, 0, 0, 0, 0, time.UTC)))

	// The pool verifies the root itself.
	_, err = cert.Verify(x509.VerifyOptions{Roots: Roots(), CurrentTime: time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC)})
	assert.NoError(t, err)
}
