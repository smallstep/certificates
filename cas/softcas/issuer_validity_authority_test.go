package softcas

import (
	"context"
	"crypto"
	"crypto/x509"
	"testing"
	"time"

	"github.com/smallstep/certificates/cas/apiv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/kms"
	kmsapi "go.step.sm/crypto/kms/apiv1"
)

type issuerValidityKeyManager struct {
	kms.KeyManager
	keys, signers         int
	keyError, signerError error
}

func (m *issuerValidityKeyManager) CreateKey(req *kmsapi.CreateKeyRequest) (*kmsapi.CreateKeyResponse, error) {
	m.keys++
	if m.keyError != nil {
		return nil, m.keyError
	}
	return m.KeyManager.CreateKey(req)
}

func (m *issuerValidityKeyManager) CreateSigner(req *kmsapi.CreateSignerRequest) (crypto.Signer, error) {
	m.signers++
	if m.signerError != nil {
		return nil, m.signerError
	}
	return m.KeyManager.CreateSigner(req)
}

func issuerValidityKMS(t *testing.T) *issuerValidityKeyManager {
	t.Helper()
	manager, err := kms.New(context.Background(), kmsapi.Options{Type: kmsapi.DefaultKMS})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, manager.Close()) })
	return &issuerValidityKeyManager{KeyManager: manager}
}

func issuerValidityCATemplate() *x509.Certificate {
	template := *testIntermediateTemplate
	template.NotBefore, template.NotAfter = time.Time{}, time.Time{}
	template.SignatureAlgorithm = 0
	return &template
}

func TestIssuerValidityLimitCertificateAuthority(t *testing.T) {
	mockNow(t)
	current := testNow.UTC().Truncate(time.Second)
	root, parent, parentKey := issuerValidityPath(t, current.Add(2*time.Hour), current.Add(4*time.Hour))
	unrelated, _, _ := issuerValidityPath(t, current.Add(time.Minute), current.Add(time.Minute))
	for _, lifetime := range []time.Duration{5 * time.Hour, 2 * time.Hour, time.Hour} {
		t.Run(lifetime.String(), func(t *testing.T) {
			manager := issuerValidityKMS(t)
			parentSigner := &issuerValiditySigner{Signer: parentKey}
			callbacks := 0
			service := &SoftCAS{KeyManager: manager, RootCertificates: []*x509.Certificate{unrelated}, CertificateSigner: func() ([]*x509.Certificate, crypto.Signer, error) {
				callbacks++
				return nil, nil, errTest
			}}
			resp, err := service.CreateCertificateAuthority(&apiv1.CreateCertificateAuthorityRequest{
				Type: apiv1.IntermediateCA, Template: issuerValidityCATemplate(), Lifetime: lifetime, Backdate: time.Minute,
				Parent: &apiv1.CreateCertificateAuthorityResponse{Certificate: parent, CertificateChain: []*x509.Certificate{root}, Signer: parentSigner},
			})
			require.NoError(t, err)
			require.NoError(t, resp.Certificate.CheckSignatureFrom(parent))
			assert.Equal(t, current.Add(-time.Minute), resp.Certificate.NotBefore)
			assert.Equal(t, resp.Signer.Public(), resp.Certificate.PublicKey)
			assert.Equal(t, testIntermediateTemplate.KeyUsage, resp.Certificate.KeyUsage)
			assert.True(t, resp.Certificate.IsCA)
			assert.Equal(t, []*x509.Certificate{parent, root}, resp.CertificateChain)
			assert.Equal(t, 0, callbacks)
			assert.Equal(t, 1, manager.keys)
			assert.Equal(t, 1, manager.signers)
			assert.Equal(t, int64(1), parentSigner.calls.Load())
			if lifetime > 2*time.Hour {
				assert.Equal(t, root.NotAfter, resp.Certificate.NotAfter)
				assertIssuerValidityWarning(t, resp.Warnings, current.Add(lifetime), root.NotAfter, root)
			} else {
				assert.Equal(t, current.Add(lifetime), resp.Certificate.NotAfter)
				assert.Nil(t, resp.Warnings)
			}
		})
	}

	t.Run("explicit subordinate dates", func(t *testing.T) {
		service := &SoftCAS{KeyManager: issuerValidityKMS(t)}
		template := issuerValidityCATemplate()
		template.NotBefore = current.Add(time.Minute)
		template.NotAfter = current.Add(5*time.Hour + 500*time.Millisecond)
		resp, err := service.CreateCertificateAuthority(&apiv1.CreateCertificateAuthorityRequest{Type: apiv1.IntermediateCA, Template: template, Lifetime: time.Hour, Parent: &apiv1.CreateCertificateAuthorityResponse{Certificate: parent, CertificateChain: []*x509.Certificate{root}, Signer: parentKey}})
		require.NoError(t, err)
		require.NoError(t, resp.Certificate.CheckSignatureFrom(parent))
		assert.Equal(t, template.NotBefore, resp.Certificate.NotBefore)
		assertIssuerValidityWarning(t, resp.Warnings, current.Add(5*time.Hour), root.NotAfter, root)
	})

	t.Run("root self signing has no parent limit", func(t *testing.T) {
		manager := issuerValidityKMS(t)
		service := &SoftCAS{KeyManager: manager, CertificateChain: []*x509.Certificate{unrelated}, RootCertificates: []*x509.Certificate{unrelated}, IssuerValidityLimit: apiv1.IssuerValidityLimitReject}
		template := *testRootTemplate
		template.NotBefore, template.NotAfter = time.Time{}, time.Time{}
		template.SignatureAlgorithm = 0
		// The generated KMS key, not the shared Ed25519 fixture, is the root key.
		template.PublicKey = nil
		resp, err := service.CreateCertificateAuthority(&apiv1.CreateCertificateAuthorityRequest{Type: apiv1.RootCA, Template: &template, Lifetime: 5 * time.Hour})
		require.NoError(t, err)
		require.NoError(t, resp.Certificate.CheckSignatureFrom(resp.Certificate))
		assert.Equal(t, current.Add(5*time.Hour), resp.Certificate.NotAfter)
		assert.Nil(t, resp.CertificateChain)
		assert.Nil(t, resp.Warnings)
		assert.Equal(t, 1, manager.keys)
		assert.Equal(t, 1, manager.signers)
	})
}

func TestIssuerValidityLimitCertificateAuthorityRejectBeforeKey(t *testing.T) {
	mockNow(t)
	current := testNow.UTC().Truncate(time.Second)
	root, parent, parentKey := issuerValidityPath(t, current.Add(2*time.Hour), current.Add(4*time.Hour))
	expiredRoot, expiredParent, expiredKey := issuerValidityPath(t, current.Add(-time.Second), current.Add(time.Hour))
	wrongRoot := issuerValidityCA(t, root.Subject.CommonName, issuerValidityKey(t), nil, nil, current.Add(-time.Hour), current.Add(time.Hour))
	cases := []struct {
		name   string
		mode   apiv1.IssuerValidityLimit
		parent *x509.Certificate
		chain  []*x509.Certificate
		key    crypto.Signer
		start  time.Time
		reason string
	}{
		{"strict overrun", apiv1.IssuerValidityLimitReject, parent, []*x509.Certificate{root}, parentKey, time.Time{}, "exceeds_limit"},
		{"expired parent path", "", expiredParent, []*x509.Certificate{expiredRoot}, expiredKey, time.Time{}, "no_remaining_validity"},
		{"future start at cap", "", parent, []*x509.Certificate{root}, parentKey, root.NotAfter, "no_remaining_validity"},
		{"nil ancestor", "", parent, []*x509.Certificate{nil}, parentKey, time.Time{}, ""},
		{"invalid adjacent signature", "", parent, []*x509.Certificate{wrongRoot}, parentKey, time.Time{}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			manager := issuerValidityKMS(t)
			signer := &issuerValiditySigner{Signer: tc.key}
			service := &SoftCAS{KeyManager: manager, IssuerValidityLimit: tc.mode}
			template := issuerValidityCATemplate()
			template.NotBefore = tc.start
			resp, err := service.CreateCertificateAuthority(&apiv1.CreateCertificateAuthorityRequest{Type: apiv1.IntermediateCA, Template: template, Lifetime: 5 * time.Hour, Backdate: time.Minute, Parent: &apiv1.CreateCertificateAuthorityResponse{Certificate: tc.parent, CertificateChain: tc.chain, Signer: signer}})
			require.Error(t, err)
			assert.Nil(t, resp)
			assert.Equal(t, 0, manager.keys)
			assert.Equal(t, 0, manager.signers)
			assert.Equal(t, int64(0), signer.calls.Load())
			if tc.reason != "" {
				var policy *apiv1.IssuerValidityError
				require.ErrorAs(t, err, &policy)
				assert.Equal(t, tc.reason, policy.Reason)
			}
		})
	}
}

func TestIssuerValidityWarningsCertificateAuthorityFailure(t *testing.T) {
	mockNow(t)
	current := testNow.UTC().Truncate(time.Second)
	root, parent, parentKey := issuerValidityPath(t, current.Add(2*time.Hour), current.Add(4*time.Hour))
	for _, stage := range []string{"key", "signer", "signature"} {
		t.Run(stage, func(t *testing.T) {
			manager := issuerValidityKMS(t)
			signer := &issuerValiditySigner{Signer: parentKey}
			switch stage {
			case "key":
				manager.keyError = errTest
			case "signer":
				manager.signerError = errTest
			case "signature":
				signer.err = errTest
			}
			service := &SoftCAS{KeyManager: manager}
			resp, err := service.CreateCertificateAuthority(&apiv1.CreateCertificateAuthorityRequest{Type: apiv1.IntermediateCA, Template: issuerValidityCATemplate(), Lifetime: 5 * time.Hour, Parent: &apiv1.CreateCertificateAuthorityResponse{Certificate: parent, CertificateChain: []*x509.Certificate{root}, Signer: signer}})
			require.Error(t, err)
			assert.Nil(t, resp)
		})
	}
}
