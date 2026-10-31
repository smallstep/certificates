package webhook

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smallstep/certificates/attestation"
)

func TestWithAttestation(t *testing.T) {
	a := &Attestation{
		Challenge:              "remote-attest-01",
		Hint:                   "measured_boot",
		FreshnessNonce:         "nonce",
		KeyAuthorizationDigest: "00",
		KeyDigest:              "01",
		Result: &attestation.Result{
			Format:    attestation.FormatTDX,
			MediaType: "application/vnd.veraison.tsm-report+json",
			Evidence:  []byte("quote"),
			TDX:       &attestation.TDX{MRTD: "aa"},
		},
	}
	rb, err := NewRequestBody(WithAttestation(a))
	require.NoError(t, err)
	assert.Equal(t, a, rb.Attestation)

	// The result's fields are at the top level of the attestation object.
	b, err := json.Marshal(rb)
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal(b, &got))
	att, ok := got["attestation"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "remote-attest-01", att["challenge"])
	assert.Equal(t, "measured_boot", att["hint"])
	assert.Equal(t, "nonce", att["freshnessNonce"])
	assert.Equal(t, "00", att["keyAuthorizationDigest"])
	assert.Equal(t, "01", att["keyDigest"])
	assert.Equal(t, "tdx", att["format"])
	assert.Equal(t, "application/vnd.veraison.tsm-report+json", att["mediaType"])
	assert.Equal(t, "cXVvdGU=", att["evidence"])
	tdx, ok := att["tdx"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "aa", tdx["mrtd"])
	assert.NotContains(t, att, "sevSnp")
	assert.NotContains(t, att, "confidentialSpace")
}
