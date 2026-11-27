package softcas

import (
	"crypto"
	"crypto/x509"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/smallstep/certificates/cas/apiv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type issuerValiditySigner struct {
	crypto.Signer
	calls atomic.Int64
	err   error
}

func (s *issuerValiditySigner) Sign(reader io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.calls.Add(1)
	if s.err != nil {
		return nil, s.err
	}
	return s.Signer.Sign(reader, digest, opts)
}

func TestIssuerValidityLimitReject(t *testing.T) {
	mockNow(t)
	current := testNow.UTC().Truncate(time.Second)
	root, issuer, key := issuerValidityPath(t, current.Add(time.Hour), current.Add(2*time.Hour))
	for _, renew := range []bool{false, true} {
		t.Run(map[bool]string{false: "create", true: "renew"}[renew], func(t *testing.T) {
			signer := &issuerValiditySigner{Signer: key}
			callbacks := 0
			service := &SoftCAS{RootCertificates: []*x509.Certificate{root}, IssuerValidityLimit: apiv1.IssuerValidityLimitReject, CertificateSigner: func() ([]*x509.Certificate, crypto.Signer, error) {
				callbacks++
				return []*x509.Certificate{issuer}, signer, nil
			}}
			var err error
			if renew {
				resp, e := service.RenewCertificate(&apiv1.RenewCertificateRequest{Template: issuerValidityTemplate(), Lifetime: time.Hour + time.Second})
				assert.Nil(t, resp)
				err = e
			} else {
				resp, e := service.CreateCertificate(&apiv1.CreateCertificateRequest{Template: issuerValidityTemplate(), Lifetime: time.Hour + time.Second})
				assert.Nil(t, resp)
				err = e
			}
			var policy *apiv1.IssuerValidityError
			require.ErrorAs(t, err, &policy)
			assert.Equal(t, "exceeds_limit", policy.Reason)
			assert.Equal(t, current.Add(time.Hour+time.Second), policy.RequestedNotAfter)
			assert.Equal(t, root.NotAfter, policy.LimitNotAfter)
			assert.Equal(t, int64(0), signer.calls.Load())
			assert.Equal(t, 1, callbacks)
		})
	}
}

func TestIssuerValidityLimitInvalidPath(t *testing.T) {
	mockNow(t)
	current := testNow.UTC().Truncate(time.Second)
	root, issuer, key := issuerValidityPath(t, current.Add(2*time.Hour), current.Add(3*time.Hour))
	wrongRoot := issuerValidityCA(t, root.Subject.CommonName, issuerValidityKey(t), nil, nil, current.Add(-time.Hour), current.Add(time.Hour))
	unrelatedRoot := issuerValidityCA(t, "Unrelated", issuerValidityKey(t), nil, nil, current.Add(-time.Hour), current.Add(time.Hour))
	cases := []struct {
		name         string
		chain, roots []*x509.Certificate
	}{
		{"empty chain", nil, nil},
		{"nil issuer", []*x509.Certificate{nil}, nil},
		{"nil ancestor", []*x509.Certificate{issuer, nil}, nil},
		{"missing issuer expiry", []*x509.Certificate{{}}, nil},
		{"missing ancestor expiry", []*x509.Certificate{issuer, {}}, nil},
		{"unordered chain", []*x509.Certificate{root, issuer}, nil},
		{"bad adjacent signature", []*x509.Certificate{issuer, wrongRoot}, nil},
		{"no matching root", []*x509.Certificate{issuer}, []*x509.Certificate{unrelatedRoot}},
		{"same subject wrong key", []*x509.Certificate{issuer}, []*x509.Certificate{wrongRoot}},
		{"nil configured root", []*x509.Certificate{issuer}, []*x509.Certificate{root, nil}},
		{"missing root expiry", []*x509.Certificate{issuer}, []*x509.Certificate{root, {}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			signer := &issuerValiditySigner{Signer: key}
			service := &SoftCAS{CertificateChain: tc.chain, RootCertificates: tc.roots, Signer: signer}
			resp, err := service.CreateCertificate(&apiv1.CreateCertificateRequest{Template: issuerValidityTemplate(), Lifetime: time.Hour})
			require.Error(t, err)
			var policy *apiv1.IssuerValidityError
			assert.False(t, errors.As(err, &policy))
			assert.Nil(t, resp)
			assert.Equal(t, int64(0), signer.calls.Load())
		})
	}
}

func TestIssuerValidityLimitIntervals(t *testing.T) {
	mockNow(t)
	current := testNow.UTC().Truncate(time.Second)
	cases := []struct {
		name       string
		cap, start time.Time
		lifetime   time.Duration
		wantErr    bool
	}{
		{"cap at now", current, current.Add(-time.Minute), time.Hour, true},
		{"cap before now", current.Add(-time.Second), current.Add(-time.Minute), time.Hour, true},
		{"cap between backdate and now", current.Add(-30 * time.Second), current.Add(-time.Minute), time.Hour, true},
		{"cap at future start", current.Add(time.Minute), current.Add(time.Minute), time.Hour, true},
		{"cap before future start", current.Add(time.Minute), current.Add(2 * time.Minute), time.Hour, true},
		{"future start with same encoded expiry", current.Add(time.Minute), current.Add(time.Minute + 900*time.Millisecond), time.Hour, true},
		{"requested expiry at now", current.Add(time.Hour), current.Add(-time.Minute), -time.Second, true},
		{"positive second below minimum", current.Add(time.Second), current.Add(-time.Minute), time.Hour, false},
		{"positive second after future start", current.Add(time.Minute + time.Second), current.Add(time.Minute), time.Hour, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, issuer, key := issuerValidityPath(t, tc.cap, current.Add(2*time.Hour))
			signer := &issuerValiditySigner{Signer: key}
			service := &SoftCAS{CertificateChain: []*x509.Certificate{issuer}, RootCertificates: []*x509.Certificate{root}, Signer: signer}
			template := issuerValidityTemplate()
			template.NotBefore = tc.start
			resp, err := service.CreateCertificate(&apiv1.CreateCertificateRequest{Template: template, Lifetime: tc.lifetime})
			if tc.wantErr {
				var policy *apiv1.IssuerValidityError
				require.ErrorAs(t, err, &policy)
				assert.Equal(t, "no_remaining_validity", policy.Reason)
				assert.Equal(t, tc.cap, policy.LimitNotAfter)
				assert.Nil(t, resp)
				assert.Equal(t, int64(0), signer.calls.Load())
				return
			}
			require.NoError(t, err)
			require.NoError(t, resp.Certificate.CheckSignatureFrom(issuer))
			assert.Equal(t, tc.cap, resp.Certificate.NotAfter)
			assert.Equal(t, tc.start, resp.Certificate.NotBefore)
			assertIssuerValidityWarning(t, resp.Warnings, current.Add(tc.lifetime), tc.cap, root)
			assert.Equal(t, int64(1), signer.calls.Load())
		})
	}
}

func TestIssuerValidityWarningsSigningFailure(t *testing.T) {
	mockNow(t)
	current := testNow.UTC().Truncate(time.Second)
	root, issuer, key := issuerValidityPath(t, current.Add(time.Hour), current.Add(2*time.Hour))
	for _, renew := range []bool{false, true} {
		t.Run(map[bool]string{false: "create", true: "renew"}[renew], func(t *testing.T) {
			signer := &issuerValiditySigner{Signer: key, err: errTest}
			service := &SoftCAS{CertificateChain: []*x509.Certificate{issuer}, RootCertificates: []*x509.Certificate{root}, Signer: signer}
			if renew {
				resp, err := service.RenewCertificate(&apiv1.RenewCertificateRequest{Template: issuerValidityTemplate(), Lifetime: 3 * time.Hour})
				require.Error(t, err)
				assert.Nil(t, resp)
			} else {
				resp, err := service.CreateCertificate(&apiv1.CreateCertificateRequest{Template: issuerValidityTemplate(), Lifetime: 3 * time.Hour})
				require.Error(t, err)
				assert.Nil(t, resp)
			}
			assert.Equal(t, int64(1), signer.calls.Load())
		})
	}
}
