package pki

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/smallstep/linkedca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/pemutil"

	"github.com/smallstep/certificates/cas/apiv1"
	"github.com/smallstep/certificates/cas/softcas"
)

func TestIssuerValidityWarnings(t *testing.T) {
	for _, scenario := range []struct {
		name         string
		mode         apiv1.IssuerValidityLimit
		rootLifetime time.Duration
		wantWarning  bool
		wantError    bool
	}{
		{name: "short parent warns", rootLifetime: 36 * time.Hour, wantWarning: true},
		{name: "long parent silent", rootLifetime: 20 * 365 * 24 * time.Hour},
		{name: "reject does not report success", mode: apiv1.IssuerValidityLimitReject, rootLifetime: 36 * time.Hour, wantError: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			service, err := softcas.New(context.Background(), apiv1.Options{IsCreator: true, IssuerValidityLimit: scenario.mode})
			require.NoError(t, err)
			parent, err := service.CreateCertificateAuthority(&apiv1.CreateCertificateAuthorityRequest{
				Type: apiv1.RootCA, Lifetime: scenario.rootLifetime,
				Template: &x509.Certificate{Subject: pkix.Name{CommonName: "PKI Warning Root"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign},
			})
			require.NoError(t, err)
			assert.Empty(t, parent.Warnings)
			p := &PKI{Configuration: linkedca.Configuration{Files: make(map[string][]byte)}, caCreator: service, options: &options{}}
			p.Intermediate = filepath.Join(t.TempDir(), "intermediate.crt")
			p.IntermediateKey = filepath.Join(t.TempDir(), "intermediate.key")
			var output bytes.Buffer
			previous := log.Writer()
			log.SetOutput(&output)
			t.Cleanup(func() { log.SetOutput(previous) })
			password := []byte("temporary test password")
			err = p.GenerateIntermediateCertificate("Warning", "Test", "test", parent, password)
			if scenario.wantError {
				var policyError *apiv1.IssuerValidityError
				require.True(t, errors.As(err, &policyError))
				assert.NotContains(t, p.Files, p.Intermediate)
				assert.NotContains(t, p.Files, p.IntermediateKey)
				assert.Empty(t, output.String())
				return
			}
			require.NoError(t, err)
			block, _ := pem.Decode(p.Files[p.Intermediate])
			require.NotNil(t, block)
			certificate, err := x509.ParseCertificate(block.Bytes)
			require.NoError(t, err)
			require.NoError(t, certificate.CheckSignatureFrom(parent.Certificate))
			key, err := pemutil.Parse(p.Files[p.IntermediateKey], pemutil.WithPassword(password))
			require.NoError(t, err)
			signer, ok := key.(crypto.Signer)
			require.True(t, ok)
			assert.Equal(t, signer.Public(), certificate.PublicKey)
			if scenario.wantWarning {
				assert.Equal(t, parent.Certificate.NotAfter, certificate.NotAfter)
				assert.Equal(t, 1, strings.Count(output.String(), "WARNING:"))
				assert.Contains(t, output.String(), "issuer_validity_truncated")
			} else {
				assert.True(t, certificate.NotAfter.Before(parent.Certificate.NotAfter))
				assert.Empty(t, output.String())
			}
		})
	}
}
