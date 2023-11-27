package acme

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustJSON(t *testing.T, m map[string]interface{}) string {
	t.Helper()

	b, err := json.Marshal(m)
	require.NoError(t, err)

	return string(b)
}

func TestError_WithAdditionalErrorDetail(t *testing.T) {
	internalJSON := mustJSON(t, map[string]interface{}{
		"detail": "The server experienced an internal error",
		"type":   "urn:ietf:params:acme:error:serverInternal",
	})
	malformedErr := NewError(ErrorMalformedType, "malformed error") // will result in Err == nil behavior
	malformedJSON := mustJSON(t, map[string]interface{}{
		"detail": "The request message was malformed",
		"type":   "urn:ietf:params:acme:error:malformed",
	})
	withDetailJSON := mustJSON(t, map[string]interface{}{
		"detail": "Attestation statement cannot be verified: invalid property",
		"type":   "urn:ietf:params:acme:error:badAttestationStatement",
	})
	tests := []struct {
		name string
		err  *Error
		want string
	}{
		{"internal", NewDetailedError(ErrorServerInternalType, ""), internalJSON},
		{"nil err", malformedErr, malformedJSON},
		{"detailed", NewDetailedError(ErrorBadAttestationStatementType, "invalid property"), withDetailJSON},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := json.Marshal(tt.err)
			require.NoError(t, err)

			// tests if the additional error detail is included in the JSON representation
			// of the ACME error. This is what is returned to ACME clients and being logged
			// by the CA.
			assert.JSONEq(t, tt.want, string(b))
		})
	}
}
