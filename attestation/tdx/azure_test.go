package tdx

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smallstep/certificates/attestation"
)

// azureTestTime is shortly after testdata/azure-dcesv6.json was captured on an
// Azure Standard_DC2es_v6 confidential VM, which has since been deleted.
var azureTestTime = time.Date(2026, time.September, 1, 2, 0, 0, 0, time.UTC)

// azureUserData is the user data the guest wrote before that capture.
const azureUserData = "ff094709cc1749f0f41c874e557a2fda67fda8a01d1d35c18333161cdd50a10e" +
	"3a078b959e9c31cbb23fe75ec1b9cb4ff431086984784bd5bc2734d19985631c"

func readAzureEvidence(t *testing.T) *AzureEvidence {
	t.Helper()
	b, err := os.ReadFile("testdata/azure-dcesv6.json")
	require.NoError(t, err)
	e, err := ParseAzureEvidence(b)
	require.NoError(t, err)
	return e
}

// commit returns the report data that commits to runtime data.
func commit(runtimeData []byte) []byte {
	reportData := make([]byte, ReportDataSize)
	sum := sha256.Sum256(runtimeData)
	copy(reportData, sum[:])
	return reportData
}

func TestAzureEvidence(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		// A real quote from Azure's paravisor: its signature, its quoting
		// enclave's report and its PCK chain to Intel's root are verified.
		e := readAzureEvidence(t)
		res, reportData, err := newVerifier(t, false, azureTestTime).Verify(context.Background(), e.Quote)
		require.NoError(t, err)
		// MRTD measures the paravisor, and the RTMRs are not used.
		assert.True(t, strings.HasPrefix(res.MRTD, "a2e61f13"))
		for _, rtmr := range res.RTMRs {
			assert.Equal(t, strings.Repeat("0", 96), rtmr)
		}
		assert.Equal(t, "0000001000000000", res.TDAttributes)

		runtime, userData, err := e.Claims(reportData)
		require.NoError(t, err)
		assert.Equal(t, azureUserData, hex.EncodeToString(userData))
		require.Len(t, runtime.Keys, 2)
		assert.Equal(t, "HCLAkPub", runtime.Keys[0]["kid"])
		assert.Equal(t, true, runtime.VMConfiguration["secure-boot"])
	})

	t.Run("fail runtime data changed", func(t *testing.T) {
		e := readAzureEvidence(t)
		_, reportData, err := newVerifier(t, false, azureTestTime).Verify(context.Background(), e.Quote)
		require.NoError(t, err)
		e.RuntimeData = []byte(strings.Replace(string(e.RuntimeData), `"secure-boot":true`, `"secure-boot":false`, 1))
		_, _, err = e.Claims(reportData)
		assert.ErrorContains(t, err, "does not commit to the azure runtime data")
		assert.True(t, errors.Is(err, attestation.ErrInvalidEvidence))
	})

	padded := []byte(`{"user-data":"` + azureUserData + `"}`)
	nonZeroPadding := commit(padded)
	nonZeroPadding[ReportDataSize-1] = 1
	short := []byte(`{"user-data":"0011"}`)
	notHex := []byte(`{"user-data":"zz"}`)
	notJSON := []byte(`not json`)
	tests := []struct {
		name        string
		runtimeData []byte
		reportData  []byte
		wantErr     string
	}{
		{"fail report data size", padded, commit(padded)[:32], "report data has 32 bytes"},
		{"fail non-zero padding", padded, nonZeroPadding, "does not commit"},
		{"fail user-data size", short, commit(short), "not the hex encoding of 64 bytes"},
		{"fail user-data hex", notHex, commit(notHex), "not the hex encoding of 64 bytes"},
		{"fail runtime claims json", notJSON, commit(notJSON), "error parsing azure runtime claims"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &AzureEvidence{Quote: []byte{1}, RuntimeData: tt.runtimeData}
			_, _, err := e.Claims(tt.reportData)
			assert.ErrorContains(t, err, tt.wantErr)
			assert.True(t, errors.Is(err, attestation.ErrInvalidEvidence))
		})
	}
}

func TestParseAzureEvidence(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr string
	}{
		{"fail not json", `quote`, "error parsing azure tdx evidence"},
		{"fail unknown field", `{"quote":"AQ==","runtimeData":"AQ==","nonce":"AQ=="}`, "unknown field"},
		{"fail trailing data", `{"quote":"AQ==","runtimeData":"AQ=="}{}`, "trailing data"},
		{"fail no quote", `{"runtimeData":"AQ=="}`, "needs a quote and runtime data"},
		{"fail no runtime data", `{"quote":"AQ=="}`, "needs a quote and runtime data"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseAzureEvidence([]byte(tt.value))
			assert.ErrorContains(t, err, tt.wantErr)
			assert.True(t, errors.Is(err, attestation.ErrInvalidEvidence))
		})
	}
}

func TestIsAzureMediaType(t *testing.T) {
	assert.True(t, IsAzureMediaType(AzureMediaType))
	assert.True(t, IsAzureMediaType(AzureMediaType+"; charset=utf-8"))
	assert.False(t, IsAzureMediaType("application/vnd.veraison.tsm-report+json"))
	assert.False(t, IsAzureMediaType("not a media type;"))
}
