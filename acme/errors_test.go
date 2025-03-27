package acme

import (
	"encoding/json"
	"errors"
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

func Test_newErrorRecordCreatesErrorRecords(t *testing.T) {
	t.Parallel()

	t.Run("nil", func(t *testing.T) {
		t.Parallel()

		got := newErrorRecord(nil)
		assert.Nil(t, got)
	})

	t.Run("ok", func(t *testing.T) {
		t.Parallel()

		exp := map[string]any{
			"type":     "urn:ietf:params:acme:error:malformed",
			"detail":   "The request message was malformed",
			"internal": "fail",
		}
		expBytes, err := json.Marshal(exp)
		require.NoError(t, err)

		got := newErrorRecord(newError(ErrorMalformedType, errors.New("fail")))

		gotBytes, err := json.Marshal(got)
		require.NoError(t, err)

		assert.JSONEq(t, string(expBytes), string(gotBytes))
	})

	t.Run("subproblems", func(t *testing.T) {
		t.Parallel()

		s1 := NewSubproblem(ErrorMalformedType, "first-subproblem-msg")
		s1.Identifier = &Identifier{Type: DNS, Value: "test.example.com"}
		s2 := NewSubproblem(ErrorMalformedType, "second-subproblem-msg")
		e := newError(ErrorMalformedType, errors.New("fail"))
		e.AddSubproblems(s1, s2)

		exp := map[string]any{
			"type":        "urn:ietf:params:acme:error:malformed",
			"detail":      "The request message was malformed",
			"subproblems": []Subproblem{s1, s2},
			"internal":    "fail",
		}
		expBytes, err := json.Marshal(exp)
		require.NoError(t, err)

		got := newErrorRecord(e)

		gotBytes, err := json.Marshal(got)
		require.NoError(t, err)

		assert.JSONEq(t, string(expBytes), string(gotBytes))
	})
}
