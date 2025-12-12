package sceptest

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/minica"
	"go.step.sm/crypto/pemutil"

	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/cas/apiv1"
)

func TestFailsIssuingCertificateUsingRegularSCEPWithUpstreamCAS(t *testing.T) {
	signer, err := keyutil.GenerateSigner("RSA", "", 2048)
	require.NoError(t, err)

	dir := t.TempDir()
	t.Setenv("STEPPATH", dir)

	m, err := minica.New(minica.WithName("Step E2E | SCEP Regular w/ Upstream CAS"), minica.WithGetSignerFunc(func() (crypto.Signer, error) {
		return signer, nil
	}))
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
	host, port := reservePort(t)

	prov := &provisioner.SCEP{
		ID:                            "scep",
		Name:                          "scep",
		Type:                          "SCEP",
		ForceCN:                       false,
		ChallengePassword:             "",
		EncryptionAlgorithmIdentifier: 2,
		MinimumPublicKeyLength:        2048,
		Claims:                        &config.GlobalProvisionerClaims,
	}

	err = prov.Init(provisioner.Config{})
	require.NoError(t, err)

	apiv1.Register("test-scep-cas", func(_ context.Context, opts apiv1.Options) (apiv1.CertificateAuthorityService, error) {
		return &testCAS{
			ca: m,
		}, nil
	})

	cfg := &config.Config{
		Address:  net.JoinHostPort(host, port), // reuse the address that was just "reserved"
		DNSNames: []string{"127.0.0.1", "[::1]", "localhost"},
		AuthorityConfig: &config.AuthConfig{
			Options: &apiv1.Options{
				AuthorityID:          "stepca-test-scep",
				Type:                 "test-scep-cas",
				CertificateAuthority: "test-cas",
			},
			AuthorityID:    "stepca-test-scep",
			DeploymentType: "standalone-test",
			Provisioners:   provisioner.List{prov},
		},
		Logger: json.RawMessage(`{"format": "text"}`),
	}
	c, err := ca.New(cfg)
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		err = c.Run()
		require.ErrorIs(t, err, http.ErrServerClosed)
	}()

	// instantiate a client for the CA running at the random address
	caClient := newCAClient(t, fmt.Sprintf("https://localhost:%s", port), rootFilepath)
	requireHealthyCA(t, caClient)

	// issuance is expected to fail when an upstream CAS is configured, as the current
	// CAS interfaces do not support providing a decrypter.
	scepClient := createSCEPClient(t, fmt.Sprintf("https://localhost:%s/scep/scep", port), m.Root)
	cert, err := scepClient.requestCertificate(t, "test.localhost", []string{"test.localhost"})
	assert.Error(t, err)
	assert.Nil(t, cert)

	// done testing; stop and wait for the server to quit
	err = c.Stop()
	require.NoError(t, err)

	wg.Wait()
}
