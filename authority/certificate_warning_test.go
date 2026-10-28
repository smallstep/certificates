package authority

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"log"
	"math/big"
	"testing"
	"time"

	"github.com/smallstep/certificates/authority/provisioner"
	casapi "github.com/smallstep/certificates/cas/apiv1"
	"github.com/smallstep/certificates/cas/softcas"
	"github.com/smallstep/certificates/db"
	"github.com/stretchr/testify/require"
)

func TestIssuerValidityWarnings(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	root, issuer, signer := issuerValidityChain(t, now.Add(time.Hour), now.Add(2*time.Hour))
	a := testAuthority(t, WithX509RootCerts(root), WithX509Signer(issuer, signer))
	var persisted *x509.Certificate
	a.db = &db.MockAuthDB{Ret1: false, MStoreCertificate: func(cert *x509.Certificate) error { persisted = cert; return nil }}
	var warnings []casapi.CertificateWarning
	ctx := casapi.WithCertificateWarningHandler(context.Background(), func(warning casapi.CertificateWarning) {
		require.NotNil(t, persisted, "warnings are published only after successful persistence")
		warnings = append(warnings, warning)
	})
	chain, err := a.SignWithContext(ctx, issuerValidityRequest(t), provisioner.SignOptions{}, issuerValidityDates(now.Add(3*time.Hour)))
	require.NoError(t, err)
	require.NoError(t, chain[0].CheckSignatureFrom(issuer))
	require.Equal(t, root.NotAfter, chain[0].NotAfter)
	require.Len(t, warnings, 1)
	sum := sha256.Sum256(root.Raw)
	require.Equal(t, "issuer_validity_truncated", warnings[0].Code)
	require.Equal(t, hex.EncodeToString(sum[:]), warnings[0].LimitingCertificate.Fingerprint)
	require.Equal(t, now.Add(3*time.Hour), warnings[0].RequestedNotAfter)
	require.Equal(t, root.NotAfter, warnings[0].EffectiveNotAfter)

	// A different request must not inherit the preceding warning.
	warnings = nil
	_, err = a.SignWithContext(ctx, issuerValidityRequest(t), provisioner.SignOptions{}, issuerValidityDates(now.Add(30*time.Minute)))
	require.NoError(t, err)
	require.Empty(t, warnings)

	// Renew/rekey keep their historical duration arithmetic but publish the
	// fresh CAS cap on this request's context, including the replacement key.
	oldKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	oldTemplate := &x509.Certificate{SerialNumber: big.NewInt(900), Subject: chain[0].Subject, DNSNames: chain[0].DNSNames, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(2 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: chain[0].ExtKeyUsage}
	der, err := x509.CreateCertificate(rand.Reader, oldTemplate, issuer, oldKey.Public(), signer)
	require.NoError(t, err)
	old, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	for _, rekey := range []bool{false, true} {
		warnings = nil
		persisted = nil
		pk := old.PublicKey
		if rekey {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			pk = key.Public()
		}
		if rekey {
			chain, err = a.RenewContext(ctx, old, pk)
		} else {
			chain, err = a.RenewContext(ctx, old, nil)
		}
		require.NoError(t, err)
		require.Equal(t, root.NotAfter, chain[0].NotAfter)
		require.Equal(t, pk, chain[0].PublicKey)
		require.NoError(t, chain[0].CheckSignatureFrom(issuer))
		require.NotNil(t, persisted, "each renewal persists before warning delivery")
		require.Len(t, warnings, 1)
	}

	t.Run("failed persistence emits no success warning", func(t *testing.T) {
		warnings = nil
		a.db = &db.MockAuthDB{MStoreCertificate: func(*x509.Certificate) error { return errors.New("storage failed") }}
		chain, err := a.SignWithContext(ctx, issuerValidityRequest(t), provisioner.SignOptions{}, issuerValidityDates(now.Add(3*time.Hour)))
		require.Error(t, err)
		require.Nil(t, chain)
		require.Empty(t, warnings)
	})
	t.Run("failed renewal persistence emits no success warning", func(t *testing.T) {
		warnings = nil
		persisted = nil
		a.db = &db.MockAuthDB{MIsRevoked: func(string) (bool, error) { return false, nil }, MStoreCertificate: func(*x509.Certificate) error { return errors.New("storage failed") }}
		chain, err := a.RenewContext(ctx, old, nil)
		require.Error(t, err)
		require.Nil(t, chain)
		require.Nil(t, persisted)
		require.Empty(t, warnings)
	})
	t.Run("not implemented storage retains successful warnings", func(t *testing.T) {
		warnings = nil
		a.db = &db.MockAuthDB{MStoreCertificate: func(cert *x509.Certificate) error { persisted = cert; return db.ErrNotImplemented }}
		chain, err := a.SignWithContext(ctx, issuerValidityRequest(t), provisioner.SignOptions{}, issuerValidityDates(now.Add(3*time.Hour)))
		require.NoError(t, err)
		require.Equal(t, root.NotAfter, chain[0].NotAfter)
		require.Len(t, warnings, 1)
	})
	t.Run("rejection emits no success warning", func(t *testing.T) {
		warnings = nil
		require.NoError(t, a.x509CAService.(*softcas.SoftCAS).SetIssuerValidityLimit(casapi.IssuerValidityLimitReject, []*x509.Certificate{root}))
		chain, err := a.SignWithContext(ctx, issuerValidityRequest(t), provisioner.SignOptions{}, issuerValidityDates(now.Add(3*time.Hour)))
		require.Error(t, err)
		require.Nil(t, chain)
		require.Empty(t, warnings)
	})
}

func TestIssuerValidityWarningsInternalTLS(t *testing.T) {
	var output bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&output)
	t.Cleanup(func() { log.SetOutput(previous) })
	now := time.Now().UTC().Truncate(time.Second)
	root, issuer, signer := issuerValidityChain(t, now.Add(time.Hour), now.Add(2*time.Hour))
	a := testAuthority(t, WithX509RootCerts(root), WithX509Signer(issuer, signer))
	cert, err := a.GetTLSCertificate()
	require.NoError(t, err)
	require.Equal(t, root.NotAfter, cert.Leaf.NotAfter)
	require.NoError(t, cert.Leaf.CheckSignatureFrom(issuer))
	require.Contains(t, output.String(), "WARNING:")
	require.Contains(t, output.String(), "issuer_validity_truncated")
	root, issuer, signer = issuerValidityChain(t, now.Add(30*time.Hour), now.Add(48*time.Hour))
	a = testAuthority(t, WithX509RootCerts(root), WithX509Signer(issuer, signer))
	output.Reset()
	cert, err = a.GetTLSCertificate()
	require.NoError(t, err)
	require.WithinDuration(t, now.Add(24*time.Hour), cert.Leaf.NotAfter, 30*time.Second)
	require.Empty(t, output.String())
}
