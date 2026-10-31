//go:build unix

package sevsnp

import (
	"context"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smallstep/certificates/attestation"
	"github.com/smallstep/certificates/attestation/sevsnp/sevsnptest"
)

// failingGetter fails every fetch, so a test fails if the verifier needs AMD's
// key distribution service, and stands for an unreachable service.
type failingGetter struct{}

func (failingGetter) Get(url string) ([]byte, error) {
	return nil, errors.New("unexpected fetch of " + url)
}

func newVerifier(t *testing.T, roots []byte) *Verifier {
	t.Helper()
	v, err := New(roots, failingGetter{})
	require.NoError(t, err)
	v.checkRevocations = false
	return v
}

func TestVerifier(t *testing.T) {
	s := sevsnptest.New(t, false)
	other := sevsnptest.New(t, true)
	reportData := make([]byte, ReportDataSize)
	for i := range reportData {
		reportData[i] = byte(i)
	}

	t.Run("ok", func(t *testing.T) {
		got, gotReportData, err := newVerifier(t, s.Roots).Verify(context.Background(), s.Report(t, reportData, false), s.CertTable)
		require.NoError(t, err)
		assert.Equal(t, reportData, gotReportData)
		assert.Len(t, got.Measurement, 96)
		assert.Len(t, got.HostData, 64)
		assert.Len(t, got.ChipID, 128)
		assert.Equal(t, "vcek", got.SigningKey)
		assert.Equal(t, "Milan", got.Product)
	})

	tests := []struct {
		name        string
		v           *Verifier
		report      []byte
		certTable   []byte
		wantErr     string
		wantInvalid bool
	}{
		{"fail debug", newVerifier(t, s.Roots), s.Report(t, reportData, true), s.CertTable,
			"policy allows debugging", true},
		// A report under the workload's own ARK, sent in its certificate
		// table, is not trusted when the verifier has AMD's roots.
		{"fail amd roots", newVerifier(t, nil), s.Report(t, reportData, false), s.CertTable,
			"could not be verified by any trusted roots", true},
		// go-sev-guest before v0.15.0 trusted the evidence's own ARK when it
		// was given no roots; the verifier never relies on that, and this
		// case fails if the module is downgraded below the fix.
		{"fail library default roots", &Verifier{getter: failingGetter{}, now: time.Now},
			s.Report(t, reportData, false), s.CertTable, "could not be verified by any trusted roots", true},
		{"fail other vcek", newVerifier(t, s.Roots), other.Report(t, reportData, false), s.CertTable,
			"error verifying sev-snp report", true},
		// Without a certificate table, the VCEK is fetched, and the failure
		// to fetch it is not the report's.
		{"fail vcek unreachable", newVerifier(t, s.Roots), s.Report(t, reportData, false), nil,
			"error fetching sev-snp certificates", false},
		{"fail tampered", newVerifier(t, s.Roots), func() []byte {
			report := s.Report(t, reportData, false)
			report[0x50] ^= 1 // the first byte of REPORT_DATA
			return report
		}(), s.CertTable, "error verifying sev-snp report", true},
		{"fail parse", newVerifier(t, s.Roots), []byte("not a report"), nil, "error parsing sev-snp report", true},
		{"fail certificate table", newVerifier(t, s.Roots), s.Report(t, reportData, false), []byte("not a table"),
			"error parsing sev-snp certificate table", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := tt.v.Verify(context.Background(), tt.report, tt.certTable)
			assert.ErrorContains(t, err, tt.wantErr)
			assert.Equal(t, tt.wantInvalid, errors.Is(err, attestation.ErrInvalidEvidence))
		})
	}
}

func TestParseRoots(t *testing.T) {
	s := sevsnptest.New(t, false)
	roots, err := parseRoots(s.Roots)
	require.NoError(t, err)
	require.Contains(t, roots, "Milan")
	require.Len(t, roots["Milan"], 1)
	assert.Equal(t, s.Ark(), roots["Milan"][0].ProductCerts.Ark)
	assert.Equal(t, s.Ask(), roots["Milan"][0].ProductCerts.Ask)
	assert.Equal(t, s.Asvk(), roots["Milan"][0].ProductCerts.Asvk)

	_, err = parseRoots(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Ask().Raw}))
	assert.ErrorContains(t, err, "product line Milan needs its ARK")

	_, err = parseRoots([]byte("not pem"))
	assert.ErrorContains(t, err, "no certificates found")

	amd, err := amdRoots()
	require.NoError(t, err)
	for _, line := range []string{"Milan", "Genoa", "Turin"} {
		require.Len(t, amd[line], 1, line)
		pc := amd[line][0].ProductCerts
		assert.Equal(t, "ARK-"+line, pc.Ark.Subject.CommonName)
		assert.Equal(t, "SEV-"+line, pc.Ask.Subject.CommonName)
		assert.Equal(t, "SEV-VLEK-"+line, pc.Asvk.Subject.CommonName)
	}
}
