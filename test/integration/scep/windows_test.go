//go:build !go1.23

package sceptest

import (
	"crypto/x509"
	"net/http"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIssuesCertificateToEmulatedWindowsClient(t *testing.T) {
	c := newTestCA(t, "Step E2E | SCEP Regular w/ Windows Client")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := c.run()
		require.ErrorIs(t, err, http.ErrServerClosed)
	}()

	// instantiate a client for the CA running at the random address
	caClient := newCAClient(t, c.caURL, c.rootFilepath)
	requireHealthyCA(t, caClient)

	scepClient := createSCEPClient(t, c.caURL, c.root)
	cert, err := scepClient.requestCertificateEmulatingWindowsClient(t, "test.localhost", []string{"test.localhost"}, x509.ParseCertificate)
	require.NoError(t, err)
	require.NotNil(t, cert)

	assert.Equal(t, "test.localhost", cert.Subject.CommonName)
	assert.Equal(t, "Step E2E | SCEP Regular w/ Windows Client Intermediate CA", cert.Issuer.CommonName)

	// done testing; stop and wait for the server to quit
	err = c.stop()
	require.NoError(t, err)

	wg.Wait()
}
