//go:build unix

// go-sev-guest's testing package, which signs reports with test-only AMD keys,
// imports golang.org/x/sys/unix.

package provisioner

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smallstep/certificates/attestation"
	"github.com/smallstep/certificates/attestation/cmw"
	"github.com/smallstep/certificates/attestation/sevsnp/sevsnptest"
)

// TestACME_VerifyRemoteAttestation_sevsnp verifies a signed SEV-SNP report the
// way the remote-attest-01 challenge does, revocation included: the revocation
// list is signed by the test ARK and served by the provisioner's HTTP client.
func TestACME_VerifyRemoteAttestation_sevsnp(t *testing.T) {
	s := sevsnptest.New(t, false)
	crlURL, crl := s.CRL(t)
	p := newRemoteAttestationACME(t, &ACMERemoteAttestation{SEVSNPRoots: s.Roots}, staticHTTPClient{crlURL: crl})
	bound := testBound()

	tsmReport := func(report, certTable []byte) []byte {
		return []byte(`{"provider":"sev_guest","outblob":"` + base64.RawURLEncoding.EncodeToString(report) +
			`","auxblob":"` + base64.RawURLEncoding.EncodeToString(certTable) + `"}`)
	}
	const mediaType = `application/vnd.veraison.tsm-report+json; provider="sev_guest"`

	t.Run("ok", func(t *testing.T) {
		value := tsmReport(s.Report(t, bound, false), s.CertTable)
		got, gotBound, err := p.VerifyRemoteAttestation(context.Background(), jsonCMW(mediaType, value, cmw.Evidence), "")
		require.NoError(t, err)
		assert.Equal(t, bound, gotBound)
		assert.Equal(t, attestation.FormatSEVSNP, got.Format)
		assert.Equal(t, mediaType, got.MediaType)
		assert.Equal(t, value, got.Evidence)
		require.NotNil(t, got.SEVSNP)
		assert.Equal(t, "vcek", got.SEVSNP.SigningKey)
	})

	t.Run("fail debug", func(t *testing.T) {
		value := tsmReport(s.Report(t, bound, true), s.CertTable)
		_, _, err := p.VerifyRemoteAttestation(context.Background(), jsonCMW(mediaType, value, 0), "")
		assert.ErrorContains(t, err, "policy allows debugging")
		assert.ErrorIs(t, err, attestation.ErrInvalidEvidence)
	})

	t.Run("fail crl unreachable", func(t *testing.T) {
		p := newRemoteAttestationACME(t, &ACMERemoteAttestation{SEVSNPRoots: s.Roots}, staticHTTPClient{})
		value := tsmReport(s.Report(t, bound, false), s.CertTable)
		_, _, err := p.VerifyRemoteAttestation(context.Background(), jsonCMW(mediaType, value, 0), "")
		assert.ErrorContains(t, err, "error fetching sev-snp certificates")
		assert.False(t, errors.Is(err, attestation.ErrInvalidEvidence))
	})
}
