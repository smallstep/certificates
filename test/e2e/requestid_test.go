package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"testing"

	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/ca/client"
	"github.com/smallstep/certificates/errs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/minica"
	"go.step.sm/crypto/pemutil"
)

// reserveAddress "reserves" a TCP address by opening a listener on a random
// port and immediately closing it. The address can then be assumed to be
// available for running a server on.
func reserveAddress(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if l, err = net.Listen("tcp6", "[::1]:0"); err != nil {
			require.NoError(t, err, "failed to listen on a port")
		}
	}

	address := l.Addr().String()
	err = l.Close()
	require.NoError(t, err)

	return address
}

func Test_reflectRequestID(t *testing.T) {
	dir := t.TempDir()
	m, err := minica.New(minica.WithName("Step E2E"))
	require.NoError(t, err)

	rootFilepath := filepath.Join(dir, "root.crt")
	_, err = pemutil.Serialize(m.Root, pemutil.WithFilename(rootFilepath))
	require.NoError(t, err)

	intermediateCertFilepath := filepath.Join(dir, "intermediate.crt")
	_, err = pemutil.Serialize(m.Intermediate, pemutil.WithFilename(intermediateCertFilepath))
	require.NoError(t, err)

	intermediateKeyFilepath := filepath.Join(dir, "intermediate.key")
	_, err = pemutil.Serialize(m.Signer, pemutil.WithFilename(intermediateKeyFilepath))
	require.NoError(t, err)

	// get a random address to listen on and connect to; currently no nicer way to get one before starting the server
	// TODO(hs): find/implement a nicer way to expose the CA URL, similar to how e.g. httptest.Server exposes it?
	address := reserveAddress(t)

	cfg := &config.Config{
		Root:             []string{rootFilepath},
		IntermediateCert: intermediateCertFilepath,
		IntermediateKey:  intermediateKeyFilepath,
		Address:          address, // reuse the address that was just "reserved"
		DNSNames:         []string{"127.0.0.1", "[::1]", "localhost"},
		AuthorityConfig: &config.AuthConfig{
			AuthorityID:    "stepca-test",
			DeploymentType: "standalone-test",
		},
		Logger: json.RawMessage(`{"format": "text"}`),
	}
	c, err := ca.New(cfg)
	require.NoError(t, err)

	// instantiate a client for the CA running at the random address
	caClient, err := ca.NewClient(
		fmt.Sprintf("https://%s", address),
		ca.WithRootFile(rootFilepath),
	)
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		err = c.Run()
		require.Error(t, err) // expect error when server is stopped
	}()

	// require OK health response as the baseline
	ctx := context.Background()
	healthResponse, err := caClient.HealthWithContext(ctx)
	assert.NoError(t, err)
	assert.Equal(t, "ok", healthResponse.Status)

	// expect an error when retrieving an invalid root
	rootResponse, err := caClient.RootWithContext(ctx, "invalid")
	if assert.Error(t, err) {
		apiErr := &errs.Error{}
		if assert.ErrorAs(t, err, &apiErr) {
			assert.Equal(t, 404, apiErr.StatusCode())
			assert.Equal(t, "The requested resource could not be found. Please see the certificate authority logs for more info.", apiErr.Err.Error())
			assert.NotEmpty(t, apiErr.RequestID)

			// TODO: include the below error in the JSON? It's currently only output to the CA logs. Also see https://github.com/smallstep/certificates/pull/759
			//assert.Equal(t, "/root/invalid was not found: certificate with fingerprint invalid was not found", apiErr.Msg)
		}
	}
	assert.Nil(t, rootResponse)

	// expect an error when retrieving an invalid root and provided request ID
	rootResponse, err = caClient.RootWithContext(client.WithRequestID(ctx, "reqID"), "invalid")
	if assert.Error(t, err) {
		apiErr := &errs.Error{}
		if assert.ErrorAs(t, err, &apiErr) {
			assert.Equal(t, 404, apiErr.StatusCode())
			assert.Equal(t, "The requested resource could not be found. Please see the certificate authority logs for more info.", apiErr.Err.Error())
			assert.Equal(t, "reqID", apiErr.RequestID)
		}
	}
	assert.Nil(t, rootResponse)

	// done testing; stop and wait for the server to quit
	err = c.Stop()
	require.NoError(t, err)

	wg.Wait()
}
