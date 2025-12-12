package sceptest

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

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

func TestIssuesCertificateUsingSCEPWithDecrypterAndUpstreamCAS(t *testing.T) {
	signer, err := keyutil.GenerateSigner("EC", "P-256", 0)
	require.NoError(t, err)

	dir := t.TempDir()
	t.Setenv("STEPPATH", dir)

	m, err := minica.New(minica.WithName("Step E2E | SCEP Decrypter w/ Upstream CAS"), minica.WithGetSignerFunc(func() (crypto.Signer, error) {
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

	decrypterKey, err := keyutil.GenerateKey("RSA", "", 2048)
	require.NoError(t, err)

	decrypter, ok := decrypterKey.(crypto.Decrypter)
	require.True(t, ok)

	decrypterCertifiate, err := m.Sign(&x509.Certificate{
		Subject:      pkix.Name{CommonName: "decrypter"},
		PublicKey:    decrypter.Public(),
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		DNSNames:     []string{"decrypter"},
	})
	require.NoError(t, err)

	b, err := pemutil.Serialize(decrypterCertifiate)
	require.NoError(t, err)
	decrypterCertificatePEMBytes := pem.EncodeToMemory(b)

	b, err = pemutil.Serialize(decrypter, pemutil.WithPassword([]byte("1234")))
	require.NoError(t, err)
	decrypterKeyPEMBytes := pem.EncodeToMemory(b)

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
		DecrypterCertificate:          decrypterCertificatePEMBytes,
		DecrypterKeyPEM:               decrypterKeyPEMBytes,
		DecrypterKeyPassword:          "1234",
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

	scepClient := createSCEPClient(t, fmt.Sprintf("https://localhost:%s/scep/scep", port), m.Root)
	cert, err := scepClient.requestCertificate(t, "test.localhost", []string{"test.localhost"})
	assert.NoError(t, err)
	require.NotNil(t, cert)

	assert.Equal(t, "test.localhost", cert.Subject.CommonName)
	assert.Equal(t, "Step E2E | SCEP Decrypter w/ Upstream CAS Intermediate CA", cert.Issuer.CommonName)

	// done testing; stop and wait for the server to quit
	err = c.Stop()
	require.NoError(t, err)

	wg.Wait()
}
