package softcas

import (
	"crypto"
	"crypto/x509"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/smallstep/certificates/cas/apiv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/x509util"
)

func TestIssuerValidityWarnings(t *testing.T) {
	mockNow(t)
	current := testNow.UTC().Truncate(time.Second)
	root, issuer, signer := issuerValidityPath(t, current.Add(2*time.Hour), current.Add(3*time.Hour))
	oldTemplate := issuerValidityTemplate()
	oldTemplate.NotBefore, oldTemplate.NotAfter = current.Add(-time.Hour), current.Add(3*time.Hour)
	old, err := x509util.CreateCertificate(oldTemplate, issuer, oldTemplate.PublicKey, signer)
	require.NoError(t, err)
	for _, rekey := range []bool{false, true} {
		t.Run(map[bool]string{false: "renew", true: "rekey"}[rekey], func(t *testing.T) {
			template := *old
			if rekey {
				template.PublicKey = issuerValidityKey(t).Public()
			}
			service := &SoftCAS{CertificateChain: []*x509.Certificate{issuer}, Signer: signer, RootCertificates: []*x509.Certificate{root}}
			lifetime := old.NotAfter.Sub(old.NotBefore)
			resp, err := service.RenewCertificate(&apiv1.RenewCertificateRequest{Template: &template, Lifetime: lifetime, Backdate: time.Minute})
			require.NoError(t, err)
			require.NoError(t, resp.Certificate.CheckSignatureFrom(issuer))
			assert.Equal(t, root.NotAfter, resp.Certificate.NotAfter)
			assert.Equal(t, current.Add(-time.Minute), resp.Certificate.NotBefore)
			assert.Equal(t, template.PublicKey, resp.Certificate.PublicKey)
			assert.Equal(t, old.DNSNames, resp.Certificate.DNSNames)
			assert.Equal(t, []*x509.Certificate{issuer}, resp.CertificateChain)
			assertIssuerValidityWarning(t, resp.Warnings, current.Add(lifetime), root.NotAfter, root)

			// A following unshortened request must not inherit the prior warning.
			resp, err = service.RenewCertificate(&apiv1.RenewCertificateRequest{Template: issuerValidityTemplate(), Lifetime: time.Hour})
			require.NoError(t, err)
			require.NoError(t, resp.Certificate.CheckSignatureFrom(issuer))
			assert.Equal(t, current.Add(time.Hour), resp.Certificate.NotAfter)
			assert.Nil(t, resp.Warnings)
		})
	}
}

func TestIssuerValidityLimitRotation(t *testing.T) {
	mockNow(t)
	current := testNow.UTC().Truncate(time.Second)
	rootKey := issuerValidityKey(t)
	root := issuerValidityCA(t, "Root", rootKey, nil, nil, current.Add(-time.Hour), current.Add(6*time.Hour))
	firstKey, secondKey := issuerValidityKey(t), issuerValidityKey(t)
	first := issuerValidityCA(t, "Rollover Issuer", firstKey, root, rootKey, current.Add(-time.Hour), current.Add(2*time.Hour))
	second := issuerValidityCA(t, "Rollover Issuer", secondKey, root, rootKey, current.Add(-time.Hour), current.Add(3*time.Hour))
	chain := []*x509.Certificate{first}
	signer := firstKey
	calls := 0
	service := &SoftCAS{RootCertificates: []*x509.Certificate{root}, CertificateSigner: func() ([]*x509.Certificate, crypto.Signer, error) {
		calls++
		return chain, signer, nil
	}}
	for _, snapshot := range []struct {
		cert *x509.Certificate
		key  crypto.Signer
	}{{first, firstKey}, {second, secondKey}, {first, firstKey}} {
		// Reuse the callback slice to exercise copied pointer-sequence keys.
		chain[0], signer = snapshot.cert, snapshot.key
		resp, err := service.CreateCertificate(&apiv1.CreateCertificateRequest{Template: issuerValidityTemplate(), Lifetime: 8 * time.Hour})
		require.NoError(t, err)
		require.NoError(t, resp.Certificate.CheckSignatureFrom(snapshot.cert))
		assert.Equal(t, snapshot.cert.RawSubject, resp.Certificate.RawIssuer)
		assert.Equal(t, snapshot.cert.NotAfter, resp.Certificate.NotAfter)
		require.Len(t, resp.CertificateChain, 1)
		assert.Same(t, snapshot.cert, resp.CertificateChain[0])
		assertIssuerValidityWarning(t, resp.Warnings, current.Add(8*time.Hour), snapshot.cert.NotAfter, snapshot.cert)
	}
	assert.Equal(t, 3, calls)

	// A root-only rotation must also invalidate link/root selection.
	shortRoot := issuerValidityCA(t, "Root", rootKey, nil, nil, current.Add(-time.Hour), current.Add(time.Hour))
	service.RootCertificates = []*x509.Certificate{shortRoot}
	resp, err := service.CreateCertificate(&apiv1.CreateCertificateRequest{Template: issuerValidityTemplate(), Lifetime: 8 * time.Hour})
	require.NoError(t, err)
	require.NoError(t, resp.Certificate.CheckSignatureFrom(first))
	assertIssuerValidityWarning(t, resp.Warnings, current.Add(8*time.Hour), shortRoot.NotAfter, shortRoot)
	require.NoError(t, service.SetIssuerValidityLimit("", []*x509.Certificate{root}))
	resp, err = service.CreateCertificate(&apiv1.CreateCertificateRequest{Template: issuerValidityTemplate(), Lifetime: 8 * time.Hour})
	require.NoError(t, err)
	require.NoError(t, resp.Certificate.CheckSignatureFrom(first))
	assertIssuerValidityWarning(t, resp.Warnings, current.Add(8*time.Hour), first.NotAfter, first)
	assert.Equal(t, 5, calls)
}

func TestIssuerValidityLimitConcurrentRotation(t *testing.T) {
	mockNow(t)
	current := testNow.UTC().Truncate(time.Second)
	rootKey := issuerValidityKey(t)
	root := issuerValidityCA(t, "Root", rootKey, nil, nil, current.Add(-time.Hour), current.Add(6*time.Hour))
	keys := []crypto.Signer{issuerValidityKey(t), issuerValidityKey(t)}
	issuers := []*x509.Certificate{
		issuerValidityCA(t, "Issuer One", keys[0], root, rootKey, current.Add(-time.Hour), current.Add(2*time.Hour)),
		issuerValidityCA(t, "Issuer Two", keys[1], root, rootKey, current.Add(-time.Hour), current.Add(3*time.Hour)),
	}
	var callbacks atomic.Uint64
	service := &SoftCAS{RootCertificates: []*x509.Certificate{root}, CertificateSigner: func() ([]*x509.Certificate, crypto.Signer, error) {
		index := int(callbacks.Add(1)-1) % len(issuers)
		return []*x509.Certificate{issuers[index]}, keys[index], nil
	}}
	type result struct {
		resp     *apiv1.CreateCertificateResponse
		err      error
		lifetime time.Duration
	}
	const requests = 64
	results := make(chan result, requests)
	var workers sync.WaitGroup
	for i := range requests {
		workers.Add(1)
		go func(short bool) {
			defer workers.Done()
			lifetime := 4 * time.Hour
			if short {
				lifetime = time.Hour
			}
			resp, err := service.CreateCertificate(&apiv1.CreateCertificateRequest{Template: issuerValidityTemplate(), Lifetime: lifetime})
			results <- result{resp, err, lifetime}
		}(i%2 == 0)
	}
	workers.Wait()
	close(results)
	for result := range results {
		require.NoError(t, result.err)
		require.Len(t, result.resp.CertificateChain, 1)
		issuer := result.resp.CertificateChain[0]
		require.True(t, issuer == issuers[0] || issuer == issuers[1])
		require.NoError(t, result.resp.Certificate.CheckSignatureFrom(issuer))
		assert.Equal(t, issuer.RawSubject, result.resp.Certificate.RawIssuer)
		if result.lifetime == time.Hour {
			assert.Equal(t, current.Add(time.Hour), result.resp.Certificate.NotAfter)
			assert.Nil(t, result.resp.Warnings)
		} else {
			assert.Equal(t, issuer.NotAfter, result.resp.Certificate.NotAfter)
			assertIssuerValidityWarning(t, result.resp.Warnings, current.Add(result.lifetime), issuer.NotAfter, issuer)
		}
	}
	assert.Equal(t, uint64(requests), callbacks.Load())
}
