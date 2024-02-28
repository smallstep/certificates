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
	"github.com/smallstep/certificates/errs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/minica"
	"go.step.sm/crypto/pemutil"
)

func TestXxx(t *testing.T) {
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
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	randomAddress := l.Addr().String()
	err = l.Close()
	require.NoError(t, err)

	cfg := &config.Config{
		Root:             []string{rootFilepath},
		IntermediateCert: intermediateCertFilepath,
		IntermediateKey:  intermediateKeyFilepath,
		Address:          randomAddress, // reuse the address that was just "reserved"
		DNSNames:         []string{"127.0.0.1", "stepca.localhost"},
		AuthorityConfig: &config.AuthConfig{
			AuthorityID:    "stepca-test",
			DeploymentType: "standalone-test",
		},
		Logger: json.RawMessage(`{"format": "text"}`),
	}
	c, err := ca.New(cfg)
	require.NoError(t, err)

	// instantiate a client for the CA
	client, err := ca.NewClient(
		fmt.Sprintf("https://%s", randomAddress),
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
	healthResponse, err := client.HealthWithContext(ctx)
	assert.NoError(t, err)
	require.Equal(t, "ok", healthResponse.Status)

	// expect an error when retrieving an invalid root
	rootResponse, err := client.RootWithContext(ctx, "invalid")
	if assert.Error(t, err) {
		apiErr := &errs.Error{}
		if assert.ErrorAs(t, err, &apiErr) {
			assert.Equal(t, 404, apiErr.StatusCode())
			assert.Equal(t, "The requested resource could not be found. Please see the certificate authority logs for more info.", apiErr.Err.Error())
			assert.NotEmpty(t, apiErr.RequestID)

			// TODO: include the below error in the JSON? It's currently only output to the CA logs
			//assert.Equal(t, "/root/invalid was not found: certificate with fingerprint invalid was not found", apiErr.Msg)
		}
	}
	assert.Nil(t, rootResponse)

	// done testing; stop and wait for the server to quit
	err = c.Stop()
	require.NoError(t, err)

	wg.Wait()
}
