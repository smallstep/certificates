package authority

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/provisioner"
	casapi "github.com/smallstep/certificates/cas/apiv1"
	"github.com/smallstep/certificates/cas/softcas"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/certificates/errs"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/x509util"
)

// Build the root-shorter-than-intermediate fixture directly: using SoftCAS here
// would apply the policy under test and erase the intended chain boundary.
func issuerValidityChain(t *testing.T, rootExpiry, issuerExpiry time.Time) (*x509.Certificate, *x509.Certificate, crypto.Signer) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Validity root"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: rootExpiry, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)
	issuerTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Validity issuer"}, NotBefore: root.NotBefore, NotAfter: issuerExpiry, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, root, issuerKey.Public(), rootKey)
	require.NoError(t, err)
	issuer, err := x509.ParseCertificate(issuerDER)
	require.NoError(t, err)
	return root, issuer, issuerKey
}

func issuerValidityRequest(t *testing.T) *x509.CertificateRequest {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csr, err := x509util.CreateCertificateRequest("validity.example", []string{"validity.example"}, key)
	require.NoError(t, err)
	return csr
}

func issuerValidityDates(expiry time.Time) provisioner.CertificateModifierFunc {
	return func(crt *x509.Certificate, opts provisioner.SignOptions) error {
		crt.NotBefore = time.Now().Add(-opts.Backdate)
		crt.NotAfter = expiry
		return nil
	}
}

func TestIssuerValidityLimit(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	root, issuer, signer := issuerValidityChain(t, now.Add(time.Hour), now.Add(2*time.Hour))
	for _, construction := range []string{"signer", "chain", "callback", "service"} {
		t.Run(construction, func(t *testing.T) {
			var option Option
			switch construction {
			case "signer":
				option = WithX509Signer(issuer, signer)
			case "chain":
				option = WithX509SignerChain([]*x509.Certificate{issuer}, signer)
			case "callback":
				option = WithX509SignerFunc(func() ([]*x509.Certificate, crypto.Signer, error) { return []*x509.Certificate{issuer}, signer, nil })
			case "service":
				option = WithX509CAService(&softcas.SoftCAS{CertificateChain: []*x509.Certificate{issuer}, Signer: signer})
			}
			a := testAuthority(t, WithX509RootCerts(root), option)
			chain, err := a.SignWithContext(context.Background(), issuerValidityRequest(t), provisioner.SignOptions{}, issuerValidityDates(now.Add(3*time.Hour)))
			require.NoError(t, err)
			require.Equal(t, root.NotAfter, chain[0].NotAfter)
			require.NoError(t, chain[0].CheckSignatureFrom(issuer))
			require.Equal(t, []*x509.Certificate{issuer}, chain[1:])
		})
	}
	t.Run("configuration overrides injected policy", func(t *testing.T) {
		svc := &softcas.SoftCAS{CertificateChain: []*x509.Certificate{issuer}, Signer: signer, IssuerValidityLimit: casapi.IssuerValidityLimitReject}
		a := testAuthority(t, WithX509RootCerts(root), WithX509CAService(svc), func(a *Authority) error {
			a.config.AuthorityConfig.Options = &casapi.Options{IssuerValidityLimit: casapi.IssuerValidityLimitTruncate}
			return nil
		})
		chain, err := a.SignWithContext(context.Background(), issuerValidityRequest(t), provisioner.SignOptions{}, issuerValidityDates(now.Add(3*time.Hour)))
		require.NoError(t, err)
		require.Equal(t, root.NotAfter, chain[0].NotAfter)
	})
	t.Run("omitted configuration preserves injected reject", func(t *testing.T) {
		svc := &softcas.SoftCAS{CertificateChain: []*x509.Certificate{issuer}, Signer: signer, IssuerValidityLimit: casapi.IssuerValidityLimitReject}
		a := testAuthority(t, WithX509RootCerts(root), WithX509CAService(svc))
		stored := 0
		a.db = &db.MockAuthDB{MStoreCertificate: func(*x509.Certificate) error { stored++; return nil }}
		chain, err := a.SignWithContext(context.Background(), issuerValidityRequest(t), provisioner.SignOptions{}, issuerValidityDates(now.Add(3*time.Hour)))
		require.Nil(t, chain)
		var policyErr *casapi.IssuerValidityError
		require.ErrorAs(t, err, &policyErr)
		require.Equal(t, "exceeds_limit", policyErr.Reason)
		require.Equal(t, 0, stored)
		var publicErr *errs.Error
		require.ErrorAs(t, err, &publicErr)
		require.Equal(t, 403, publicErr.StatusCode())
		wire, err := json.Marshal(publicErr)
		require.NoError(t, err)
		var payload struct {
			Message string `json:"message"`
		}
		require.NoError(t, json.Unmarshal(wire, &payload))
		require.Contains(t, payload.Message, root.NotAfter.Format(time.RFC3339))
		require.Contains(t, payload.Message, now.Add(3*time.Hour).Format(time.RFC3339))
	})
	t.Run("unsupported backend requires omitted policy", func(t *testing.T) {
		for _, mode := range []casapi.IssuerValidityLimit{"", casapi.IssuerValidityLimitTruncate, casapi.IssuerValidityLimitReject, "off"} {
			cfg := &config.Config{Address: "127.0.0.1:9000", DNSNames: []string{"localhost"}, AuthorityConfig: &config.AuthConfig{Options: &casapi.Options{IssuerValidityLimit: mode}}}
			a, err := NewEmbedded(WithConfig(cfg), WithX509RootCerts(root), WithX509CAService(notImplementedCAS{}))
			if mode == "" {
				require.NoError(t, err)
				require.NotNil(t, a)
			} else {
				require.Error(t, err)
				require.Nil(t, a)
			}
		}
	})
	t.Run("original provisioner minimum validated before cap", func(t *testing.T) {
		shortRoot, shortIssuer, shortSigner := issuerValidityChain(t, now.Add(2*time.Minute), now.Add(time.Hour))
		a := testAuthority(t, WithX509RootCerts(shortRoot), WithX509Signer(shortIssuer, shortSigner))
		key, err := jose.ReadKey("testdata/secrets/step_cli_key_priv.jwk", jose.WithPassword([]byte("pass")))
		require.NoError(t, err)
		for _, lifetime := range []time.Duration{10 * time.Minute, time.Minute} {
			token, err := generateToken("validity.example", "step-cli", testAudiences.Sign[0], []string{"validity.example"}, time.Now(), key)
			require.NoError(t, err)
			ctx := provisioner.NewContextWithMethod(context.Background(), provisioner.SignMethod)
			opts, err := a.Authorize(ctx, token)
			require.NoError(t, err)
			chain, err := a.SignWithContext(ctx, issuerValidityRequest(t), provisioner.SignOptions{NotBefore: provisioner.NewTimeDuration(now), NotAfter: provisioner.NewTimeDuration(now.Add(lifetime))}, opts...)
			if lifetime == time.Minute {
				require.Error(t, err)
				require.Nil(t, chain)
			} else {
				require.NoError(t, err)
				require.Equal(t, shortRoot.NotAfter, chain[0].NotAfter)
				require.Less(t, chain[0].NotAfter.Sub(chain[0].NotBefore), 5*time.Minute)
				require.NoError(t, chain[0].CheckSignatureFrom(shortIssuer))
			}
		}
	})
	t.Run("strict server TLS has no exemption", func(t *testing.T) {
		svc := &softcas.SoftCAS{CertificateChain: []*x509.Certificate{issuer}, Signer: signer, IssuerValidityLimit: casapi.IssuerValidityLimitReject}
		a := testAuthority(t, WithX509RootCerts(root), WithX509CAService(svc))
		cert, err := a.GetTLSCertificate()
		require.Nil(t, cert)
		var policyErr *casapi.IssuerValidityError
		require.True(t, errors.As(err, &policyErr))
		require.Equal(t, "exceeds_limit", policyErr.Reason)
	})
}
