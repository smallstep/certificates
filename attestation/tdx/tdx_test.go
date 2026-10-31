package tdx

import (
	"context"
	"errors"
	"testing"
	"time"

	tdxtest "github.com/google/go-tdx-guest/testing"
	"github.com/google/go-tdx-guest/testing/testdata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smallstep/certificates/attestation"
)

// testTime is a time at which go-tdx-guest's sample quote, its PCK chain and
// its sample collateral are all valid.
var testTime = time.Date(2023, time.July, 1, 1, 0, 0, 0, time.UTC)

// failingGetter fails every fetch, as an unreachable service would.
type failingGetter struct{}

func (failingGetter) Get(url string) (map[string][]string, []byte, error) {
	return nil, nil, errors.New("unexpected fetch of " + url)
}

func newVerifier(t *testing.T, getCollateral bool, now time.Time) *Verifier {
	t.Helper()
	v, err := New(nil, tdxtest.TestGetter)
	require.NoError(t, err)
	v.getCollateral = getCollateral
	v.now = func() time.Time { return now }
	return v
}

func TestVerifier(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		// Without collateral, the quote's signature, its quoting enclave's
		// report and its PCK chain to Intel's embedded root are verified.
		got, reportData, err := newVerifier(t, false, testTime).Verify(context.Background(), testdata.RawQuote)
		require.NoError(t, err)
		assert.Len(t, got.MRTD, 96)
		assert.Len(t, got.RTMRs, 4)
		for _, rtmr := range got.RTMRs {
			assert.Len(t, rtmr, 96)
		}
		assert.Len(t, got.MRConfigID, 96)
		assert.Len(t, got.TDAttributes, 16)
		assert.Equal(t, "50806f000000", got.FMSPC)
		assert.Empty(t, got.TCBStatus)
		assert.Len(t, reportData, ReportDataSize)
	})

	unreachable := newVerifier(t, true, testTime)
	unreachable.getter = failingGetter{}

	tests := []struct {
		name        string
		verifier    *Verifier
		quote       []byte
		wantErr     string
		wantInvalid bool
	}{
		// The sample collateral's TCB levels do not match the sample quote's
		// TEE_TCB_SVN, so a verifier that checks the TCB status refuses it.
		{"fail tcb status", newVerifier(t, true, testTime), testdata.RawQuote, "no matching TCB level found", true},
		{"fail collateral unreachable", unreachable, testdata.RawQuote, "error fetching tdx collateral", false},
		{"fail expired", newVerifier(t, false, time.Date(2053, time.July, 1, 0, 0, 0, 0, time.UTC)), testdata.RawQuote,
			"error verifying tdx quote", true},
		{"fail parse", newVerifier(t, false, testTime), []byte("not a quote"), "error parsing tdx quote", true},
		{"fail signature", newVerifier(t, false, testTime), func() []byte {
			quote := append([]byte(nil), testdata.RawQuote...)
			// Flip a bit of the report data in the signed TD quote body.
			quote[48+520] ^= 1
			return quote
		}(), "error verifying tdx quote", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := tt.verifier.Verify(context.Background(), tt.quote)
			assert.ErrorContains(t, err, tt.wantErr)
			assert.Equal(t, tt.wantInvalid, errors.Is(err, attestation.ErrInvalidEvidence))
		})
	}
}

func TestNew(t *testing.T) {
	_, err := New([]byte("not pem"), tdxtest.TestGetter)
	assert.EqualError(t, err, "no certificates found in the tdx roots")
}
