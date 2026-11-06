package softcas

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/smallstep/certificates/cas/apiv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/x509util"
)

func issuerValidityKey(t *testing.T) crypto.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func issuerValidityCA(t *testing.T, name string, key crypto.Signer, parent *x509.Certificate, parentKey crypto.Signer, start, expiry time.Time) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: start, NotAfter: expiry,
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	if parent == nil {
		parent, parentKey = template, key
	}
	cert, err := x509util.CreateCertificate(template, parent, key.Public(), parentKey)
	require.NoError(t, err)
	return cert
}

func issuerValidityPath(t *testing.T, rootExpiry, issuerExpiry time.Time) (*x509.Certificate, *x509.Certificate, crypto.Signer) {
	t.Helper()
	start := testNow.Add(-time.Hour)
	rootKey, issuerKey := issuerValidityKey(t), issuerValidityKey(t)
	root := issuerValidityCA(t, "Root", rootKey, nil, nil, start, rootExpiry)
	issuer := issuerValidityCA(t, "Issuer", issuerKey, root, rootKey, start, issuerExpiry)
	return root, issuer, issuerKey
}

func issuerValidityTemplate() *x509.Certificate {
	template := *testTemplate
	template.NotBefore, template.NotAfter = time.Time{}, time.Time{}
	template.SignatureAlgorithm = 0
	template.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte{5, 0}}}
	return &template
}

func assertIssuerValidityWarning(t *testing.T, warnings []apiv1.CertificateWarning, requested, effective time.Time, limiting *x509.Certificate) {
	t.Helper()
	require.Len(t, warnings, 1)
	warning := warnings[0]
	assert.Equal(t, "issuer_validity_truncated", warning.Code)
	assert.Equal(t, requested.UTC().Truncate(time.Second), warning.RequestedNotAfter)
	assert.Equal(t, effective.UTC().Truncate(time.Second), warning.EffectiveNotAfter)
	assert.Equal(t, limiting.Subject.String(), warning.LimitingCertificate.Subject)
	assert.Equal(t, effective.UTC().Truncate(time.Second), warning.LimitingCertificate.NotAfter)
	fingerprint := sha256.Sum256(limiting.Raw)
	assert.Equal(t, fmt.Sprintf("%x", fingerprint), warning.LimitingCertificate.Fingerprint)
}

func TestIssuerValidityLimit(t *testing.T) {
	mockNow(t)
	current := testNow.UTC().Truncate(time.Second)
	root, issuer, signer := issuerValidityPath(t, current.Add(2*time.Hour), current.Add(3*time.Hour))

	t.Run("resolved dates and modes", func(t *testing.T) {
		cases := []struct {
			name             string
			mode             apiv1.IssuerValidityLimit
			start, requested time.Time
			lifetime         time.Duration
			want             time.Time
			warn             bool
		}{
			{name: "omitted mode and dates", lifetime: 4 * time.Hour, want: root.NotAfter, warn: true},
			{name: "explicit truncate", mode: apiv1.IssuerValidityLimitTruncate, requested: current.Add(4 * time.Hour), lifetime: time.Hour, want: root.NotAfter, warn: true},
			{name: "earlier expiry", requested: current.Add(time.Hour), lifetime: time.Hour, want: current.Add(time.Hour)},
			{name: "equality", requested: root.NotAfter, lifetime: time.Hour, want: root.NotAfter},
			{name: "one second over", requested: root.NotAfter.Add(time.Second), lifetime: time.Hour, want: root.NotAfter, warn: true},
			{name: "same encoded second", mode: apiv1.IssuerValidityLimitReject, requested: root.NotAfter.Add(999 * time.Millisecond), lifetime: time.Hour, want: root.NotAfter},
			{name: "subsecond overrun", requested: root.NotAfter.Add(1999 * time.Millisecond), lifetime: time.Hour, want: root.NotAfter, warn: true},
			{name: "explicit start with default expiry", start: current.Add(-30 * time.Minute), lifetime: 4 * time.Hour, want: root.NotAfter, warn: true},
			{name: "strict earlier expiry", mode: apiv1.IssuerValidityLimitReject, requested: current.Add(time.Hour), lifetime: time.Hour, want: current.Add(time.Hour)},
			{name: "strict equality", mode: apiv1.IssuerValidityLimitReject, requested: root.NotAfter, lifetime: time.Hour, want: root.NotAfter},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				service := &SoftCAS{CertificateChain: []*x509.Certificate{issuer}, Signer: signer, RootCertificates: []*x509.Certificate{root}, IssuerValidityLimit: tc.mode}
				template := issuerValidityTemplate()
				template.NotBefore, template.NotAfter = tc.start, tc.requested
				resp, err := service.CreateCertificate(&apiv1.CreateCertificateRequest{Template: template, Lifetime: tc.lifetime, Backdate: time.Minute})
				require.NoError(t, err)
				require.NoError(t, resp.Certificate.CheckSignatureFrom(issuer))
				assert.Equal(t, tc.want, resp.Certificate.NotAfter)
				start := tc.start
				if start.IsZero() {
					start = current.Add(-time.Minute)
				}
				assert.Equal(t, start.UTC().Truncate(time.Second), resp.Certificate.NotBefore)
				assert.Equal(t, testTemplate.DNSNames, resp.Certificate.DNSNames)
				assert.Equal(t, testTemplate.PublicKey, resp.Certificate.PublicKey)
				assert.Equal(t, testTemplate.KeyUsage, resp.Certificate.KeyUsage)
				assert.Equal(t, testTemplate.ExtKeyUsage, resp.Certificate.ExtKeyUsage)
				assert.Contains(t, resp.Certificate.Extensions, template.ExtraExtensions[0])
				assert.Equal(t, []*x509.Certificate{issuer}, resp.CertificateChain)
				if tc.warn {
					requested := tc.requested
					if requested.IsZero() {
						requested = current.Add(tc.lifetime)
					}
					assertIssuerValidityWarning(t, resp.Warnings, requested, tc.want, root)
				} else {
					assert.Nil(t, resp.Warnings)
				}
			})
		}
	})

	t.Run("actual ordered path and roots", func(t *testing.T) {
		start := current.Add(-time.Hour)
		rootKey := issuerValidityKey(t)
		longRoot := issuerValidityCA(t, "Shared Root", rootKey, nil, nil, start, current.Add(5*time.Hour))
		shortRoot := issuerValidityCA(t, "Shared Root", rootKey, nil, nil, start, current.Add(2*time.Hour))
		equalRoot := issuerValidityCA(t, "Shared Root", rootKey, nil, nil, start, shortRoot.NotAfter)
		wrongKey := issuerValidityCA(t, "Shared Root", issuerValidityKey(t), nil, nil, start, current.Add(time.Minute))
		unrelated := issuerValidityCA(t, "Unrelated", issuerValidityKey(t), nil, nil, start, current.Add(time.Minute))
		parentKey, leafIssuerKey := issuerValidityKey(t), issuerValidityKey(t)
		parent := issuerValidityCA(t, "Parent", parentKey, longRoot, rootKey, start, current.Add(4*time.Hour))
		leafIssuer := issuerValidityCA(t, "Leaf Issuer", leafIssuerKey, parent, parentKey, start, current.Add(6*time.Hour))
		shortParent := issuerValidityCA(t, "Parent", parentKey, longRoot, rootKey, start, current.Add(time.Hour))
		shortIssuer := issuerValidityCA(t, "Issuer", signer, longRoot, rootKey, start, current.Add(time.Hour))
		tiedIssuer := issuerValidityCA(t, "Issuer", signer, longRoot, rootKey, start, shortRoot.NotAfter)
		cases := []struct {
			name         string
			chain, roots []*x509.Certificate
			signer       crypto.Signer
			limiting     *x509.Certificate
		}{
			{"root earlier", []*x509.Certificate{issuer}, []*x509.Certificate{root}, signer, root},
			{"issuer earlier", []*x509.Certificate{shortIssuer}, []*x509.Certificate{longRoot}, signer, shortIssuer},
			{"extra intermediate earlier", []*x509.Certificate{leafIssuer, shortParent}, []*x509.Certificate{longRoot}, leafIssuerKey, shortParent},
			{"unrelated and wrong key roots ignored", []*x509.Certificate{leafIssuer, parent}, []*x509.Certificate{unrelated, wrongKey, longRoot}, leafIssuerKey, parent},
			{"multiple issuing roots", []*x509.Certificate{leafIssuer, parent}, []*x509.Certificate{longRoot, shortRoot}, leafIssuerKey, shortRoot},
			{"root ties follow configured order", []*x509.Certificate{leafIssuer, parent}, []*x509.Certificate{equalRoot, shortRoot}, leafIssuerKey, equalRoot},
			{"supplied certificate wins tie", []*x509.Certificate{tiedIssuer}, []*x509.Certificate{shortRoot}, signer, tiedIssuer},
			{"already included root ignores alternatives", []*x509.Certificate{leafIssuer, parent, longRoot}, []*x509.Certificate{shortRoot, longRoot}, leafIssuerKey, parent},
			{"standalone issuer path", []*x509.Certificate{leafIssuer, parent}, nil, leafIssuerKey, parent},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				service := &SoftCAS{CertificateChain: tc.chain, RootCertificates: tc.roots, Signer: tc.signer}
				resp, err := service.CreateCertificate(&apiv1.CreateCertificateRequest{Template: issuerValidityTemplate(), Lifetime: 8 * time.Hour})
				require.NoError(t, err)
				require.NoError(t, resp.Certificate.CheckSignatureFrom(tc.chain[0]))
				assert.Equal(t, tc.limiting.NotAfter, resp.Certificate.NotAfter)
				assert.Equal(t, tc.chain, resp.CertificateChain)
				assertIssuerValidityWarning(t, resp.Warnings, current.Add(8*time.Hour), tc.limiting.NotAfter, tc.limiting)
			})
		}
	})

	t.Run("no new PKIX constraints", func(t *testing.T) {
		rootKey, issuerKey := issuerValidityKey(t), issuerValidityKey(t)
		futureRoot := issuerValidityCA(t, "Future Root", rootKey, nil, nil, current.Add(time.Hour), current.Add(3*time.Hour))
		template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Constrained Issuer"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: current.Add(time.Hour), NotAfter: current.Add(2 * time.Hour), PermittedDNSDomainsCritical: true, PermittedDNSDomains: []string{"other.example"}}
		futureIssuer, err := x509util.CreateCertificate(template, futureRoot, issuerKey.Public(), rootKey)
		require.NoError(t, err)
		service := &SoftCAS{CertificateChain: []*x509.Certificate{futureIssuer}, Signer: issuerKey, RootCertificates: []*x509.Certificate{futureRoot}}
		resp, err := service.CreateCertificate(&apiv1.CreateCertificateRequest{Template: issuerValidityTemplate(), Lifetime: 4 * time.Hour})
		require.NoError(t, err)
		require.NoError(t, resp.Certificate.CheckSignatureFrom(futureIssuer))
		assert.Equal(t, futureIssuer.NotAfter, resp.Certificate.NotAfter)
		assertIssuerValidityWarning(t, resp.Warnings, current.Add(4*time.Hour), futureIssuer.NotAfter, futureIssuer)
	})
}

func TestIssuerValidityLimitConfiguration(t *testing.T) {
	mockNow(t)
	current := testNow.UTC().Truncate(time.Second)
	root, issuer, signer := issuerValidityPath(t, current.Add(2*time.Hour), current.Add(4*time.Hour))
	shortRoot, _, _ := issuerValidityPath(t, current.Add(time.Hour), current.Add(3*time.Hour))
	for _, mode := range []apiv1.IssuerValidityLimit{"off", "TRUNCATE", "invalid"} {
		_, err := New(context.Background(), apiv1.Options{IsCreator: true, IssuerValidityLimit: mode})
		require.Error(t, err)
		injected := &SoftCAS{IssuerValidityLimit: mode}
		require.Error(t, injected.SetIssuerValidityLimit("", []*x509.Certificate{root}))
	}
	roots := []*x509.Certificate{root}
	service, err := New(context.Background(), apiv1.Options{CertificateChain: []*x509.Certificate{issuer}, Signer: signer, RootCertificates: roots, IssuerValidityLimit: apiv1.IssuerValidityLimitReject})
	require.NoError(t, err)
	roots[0] = shortRoot
	resp, err := service.CreateCertificate(&apiv1.CreateCertificateRequest{Template: issuerValidityTemplate(), Lifetime: time.Hour})
	require.NoError(t, err)
	require.NoError(t, resp.Certificate.CheckSignatureFrom(issuer))
	assert.Equal(t, current.Add(time.Hour), resp.Certificate.NotAfter)
	assert.Nil(t, resp.Warnings)

	roots[0] = root
	require.NoError(t, service.SetIssuerValidityLimit("", roots))
	roots[0] = shortRoot
	resp, err = service.CreateCertificate(&apiv1.CreateCertificateRequest{Template: issuerValidityTemplate(), Lifetime: 3 * time.Hour})
	var policy *apiv1.IssuerValidityError
	require.ErrorAs(t, err, &policy)
	assert.Equal(t, "exceeds_limit", policy.Reason)
	assert.Nil(t, resp)

	require.Error(t, service.SetIssuerValidityLimit("off", []*x509.Certificate{shortRoot}))
	resp, err = service.CreateCertificate(&apiv1.CreateCertificateRequest{Template: issuerValidityTemplate(), Lifetime: 3 * time.Hour})
	require.ErrorAs(t, err, &policy)
	assert.Equal(t, root.NotAfter, policy.LimitNotAfter)
	assert.Nil(t, resp)

	require.NoError(t, service.SetIssuerValidityLimit(apiv1.IssuerValidityLimitTruncate, []*x509.Certificate{root}))
	resp, err = service.CreateCertificate(&apiv1.CreateCertificateRequest{Template: issuerValidityTemplate(), Lifetime: 3 * time.Hour})
	require.NoError(t, err)
	require.NoError(t, resp.Certificate.CheckSignatureFrom(issuer))
	assertIssuerValidityWarning(t, resp.Warnings, current.Add(3*time.Hour), root.NotAfter, root)
}
