package tsm

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smallstep/certificates/attestation"
)

func TestIsMediaType(t *testing.T) {
	assert.True(t, IsMediaType(MediaTypeJSON))
	assert.True(t, IsMediaType(MediaTypeCBOR+`; provider="sev_guest"`))
	assert.False(t, IsMediaType("application/eat+jwt"))
	assert.False(t, IsMediaType("not a media type;"))
}

func TestParse(t *testing.T) {
	// The blobs hold bytes whose base64 differs between the alphabets.
	out := []byte{0xfb, 0xff, 0x01}
	aux := []byte{0xfa, 0xfe}
	cborReport, err := cbor.Marshal(map[string]any{"provider": "sev_guest", "outblob": out, "auxblob": aux, "service_provider": "svsm"})
	require.NoError(t, err)

	tests := []struct {
		name      string
		mediaType string
		value     string
		want      *Report
		wantErr   string
	}{
		{"ok json", MediaTypeJSON + `; provider="tdx_guest"`, `{"provider":"tdx_guest","outblob":"-_8B"}`,
			&Report{Provider: "tdx_guest", OutBlob: out}, ""},
		{"ok json standard alphabet and padding", MediaTypeJSON, `{"provider":"sev_guest","outblob":"+/8B","auxblob":"+v4="}`,
			&Report{Provider: "sev_guest", OutBlob: out, AuxBlob: aux}, ""},
		{"ok cbor", MediaTypeCBOR, string(cborReport),
			&Report{Provider: "sev_guest", OutBlob: out, AuxBlob: aux}, ""},
		{"fail media type", MediaTypeJSON + "; provider", `{}`, nil, "error parsing media type"},
		{"fail other media type", "application/eat+jwt", `{}`, nil, "is not a tsm report"},
		{"fail json", MediaTypeJSON, `{`, nil, "error parsing tsm report"},
		{"fail json outblob", MediaTypeJSON, `{"provider":"tdx_guest","outblob":"*"}`, nil, "outblob must be base64url"},
		{"fail json auxblob", MediaTypeJSON, `{"provider":"tdx_guest","outblob":"-_8B","auxblob":"*"}`, nil, "auxblob must be base64url"},
		{"fail cbor", MediaTypeCBOR, "\xa1", nil, "error parsing tsm report"},
		{"fail no provider", MediaTypeJSON, `{"outblob":"-_8B"}`, nil, "has no provider"},
		{"fail no outblob", MediaTypeJSON, `{"provider":"tdx_guest"}`, nil, "has no outblob"},
		{"fail provider mismatch", MediaTypeJSON + `; provider="sev_guest"`, `{"provider":"tdx_guest","outblob":"-_8B"}`, nil,
			`provider "tdx_guest" does not match the media type's provider "sev_guest"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.mediaType, []byte(tt.value))
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				assert.ErrorIs(t, err, attestation.ErrInvalidEvidence)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
