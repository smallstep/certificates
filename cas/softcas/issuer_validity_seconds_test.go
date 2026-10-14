package softcas

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/smallstep/certificates/cas/apiv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIssuerValidityLimitSecondPrecision(t *testing.T) {
	mockNow(t)
	current := testNow.UTC().Truncate(time.Second)
	root, issuer, signer := issuerValidityPath(t, current.Add(time.Second), current.Add(time.Hour))
	clock := current.Add(750 * time.Millisecond).In(time.FixedZone("fixture", 3600))
	calls := 0
	now = func() time.Time { calls++; return clock }
	service := &SoftCAS{CertificateChain: []*x509.Certificate{issuer}, Signer: signer, RootCertificates: []*x509.Certificate{root}}
	lifetime, backdate := 1250*time.Millisecond, 500*time.Millisecond

	created, err := service.CreateCertificate(&apiv1.CreateCertificateRequest{Template: issuerValidityTemplate(), Lifetime: lifetime, Backdate: backdate})
	require.NoError(t, err)
	require.NoError(t, created.Certificate.CheckSignatureFrom(issuer))
	assert.Equal(t, current, created.Certificate.NotBefore)
	assert.Equal(t, current.Add(time.Second), created.Certificate.NotAfter)
	assertIssuerValidityWarning(t, created.Warnings, current.Add(2*time.Second), root.NotAfter, root)
	assert.Equal(t, 1, calls)

	renewed, err := service.RenewCertificate(&apiv1.RenewCertificateRequest{Template: issuerValidityTemplate(), Lifetime: lifetime, Backdate: backdate})
	require.NoError(t, err)
	require.NoError(t, renewed.Certificate.CheckSignatureFrom(issuer))
	assert.Equal(t, current, renewed.Certificate.NotBefore)
	assert.Equal(t, current.Add(time.Second), renewed.Certificate.NotAfter)
	assertIssuerValidityWarning(t, renewed.Warnings, current.Add(2*time.Second), root.NotAfter, root)
	assert.Equal(t, 2, calls)

	service.KeyManager = issuerValidityKMS(t)
	child, err := service.CreateCertificateAuthority(&apiv1.CreateCertificateAuthorityRequest{Type: apiv1.IntermediateCA, Template: issuerValidityCATemplate(), Lifetime: lifetime, Backdate: backdate, Parent: &apiv1.CreateCertificateAuthorityResponse{Certificate: issuer, CertificateChain: []*x509.Certificate{root}, Signer: signer}})
	require.NoError(t, err)
	require.NoError(t, child.Certificate.CheckSignatureFrom(issuer))
	assert.Equal(t, current, child.Certificate.NotBefore)
	assert.Equal(t, current.Add(time.Second), child.Certificate.NotAfter)
	assertIssuerValidityWarning(t, child.Warnings, current.Add(2*time.Second), root.NotAfter, root)
	assert.Equal(t, 3, calls)
}
