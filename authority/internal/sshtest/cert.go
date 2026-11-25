// Package sshtest provides helpers for creating SSH certificates in tests.
package sshtest

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"go.step.sm/crypto/jose"

	"github.com/smallstep/certificates/internal/cast"
)

// CreateCertificate signs cert with signer and returns it together with the
// JWK holding the private key for the certificate's public key.
func CreateCertificate(t testing.TB, cert *ssh.Certificate, signer ssh.Signer) (*ssh.Certificate, *jose.JSONWebKey) {
	t.Helper()

	jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "foo", 0)
	require.NoError(t, err)

	cert.Key, err = ssh.NewPublicKey(jwk.Public().Key)
	require.NoError(t, err)

	now := time.Now()
	if cert.ValidAfter == 0 {
		cert.ValidAfter = cast.Uint64(now.Unix())
	}
	if cert.ValidBefore == 0 {
		cert.ValidBefore = cast.Uint64(now.Add(time.Hour).Unix())
	}
	if len(cert.ValidPrincipals) == 0 {
		// set default principals; cert.SignCert fails without one set
		cert.ValidPrincipals = []string{"dummy.smallstep.com"}
	}

	require.NoError(t, cert.SignCert(rand.Reader, signer))

	return cert, jwk
}
