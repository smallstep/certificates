package cmw

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustCBOR(t *testing.T, v any) []byte {
	t.Helper()
	b, err := cbor.Marshal(v)
	require.NoError(t, err)
	return b
}

func TestParse(t *testing.T) {
	const mediaType = `application/vnd.veraison.tsm-report+json; provider="tdx_guest"`
	value := []byte(`{"provider":"tdx_guest"}`)

	tests := []struct {
		name    string
		data    []byte
		want    *Record
		wantErr string
	}{
		{"ok json", []byte(`["application/eat+jwt", "ZXlKaGJHY2lPaUpTVXpJMU5pSjku", 8]`),
			&Record{MediaType: "application/eat+jwt", Value: []byte("eyJhbGciOiJSUzI1NiJ9."), Indicator: AttestationResults}, ""},
		{"ok json padded", []byte(`["text/plain", "Zm9vYg=="]`),
			&Record{MediaType: "text/plain", Value: []byte("foob")}, ""},
		{"ok json whitespace", []byte("\n [\"text/plain\", \"Zm9v\", 4] \n"),
			&Record{MediaType: "text/plain", Value: []byte("foo"), Indicator: Evidence}, ""},
		{"ok cbor", mustCBOR(t, []any{mediaType, value, uint(4)}),
			&Record{MediaType: mediaType, Value: value, Indicator: Evidence}, ""},
		{"ok cbor no indicator", mustCBOR(t, []any{mediaType, value}),
			&Record{MediaType: mediaType, Value: value}, ""},
		{"fail empty", []byte(" "), nil, "cmw is empty"},
		{"fail json collection", []byte(`{"a": ["text/plain", "Zm9v"]}`), nil, "collections are not supported"},
		{"fail json syntax", []byte(`["text/plain", "Zm9v"`), nil, "error parsing cmw json record"},
		{"fail json one element", []byte(`["text/plain"]`), nil, "must have 2 or 3 elements, it has 1"},
		{"fail json four elements", []byte(`["text/plain", "Zm9v", 4, 1]`), nil, "must have 2 or 3 elements, it has 4"},
		{"fail json type", []byte(`[1, "Zm9v"]`), nil, "type must be a media type string"},
		{"fail json value type", []byte(`["text/plain", 1]`), nil, "value must be a base64url string"},
		{"fail json value encoding", []byte(`["text/plain", "Zm9v+/"]`), nil, "value must be a base64url string"},
		{"fail json indicator", []byte(`["text/plain", "Zm9v", -1]`), nil, "indicator must be an unsigned integer"},
		{"fail json empty type", []byte(`["", "Zm9v"]`), nil, "type is empty"},
		{"fail json empty value", []byte(`["text/plain", ""]`), nil, "value is empty"},
		{"fail cbor collection", mustCBOR(t, map[string]any{"a": []any{mediaType, value}}), nil, "collections are not supported"},
		{"fail cbor tag", mustCBOR(t, cbor.Tag{Number: 1668546817 + 10000, Content: value}), nil, "tag form is not supported"},
		{"fail cbor content-format", mustCBOR(t, []any{uint(10000), value}), nil, "typed by a coap content-format are not supported"},
		{"fail cbor type", mustCBOR(t, []any{[]byte("x"), value}), nil, "type must be a media type string"},
		{"fail cbor value", mustCBOR(t, []any{mediaType, "text"}), nil, "value must be a byte string"},
		{"fail cbor indicator", mustCBOR(t, []any{mediaType, value, "x"}), nil, "indicator must be an unsigned integer"},
		{"fail cbor elements", mustCBOR(t, []any{mediaType}), nil, "must have 2 or 3 elements, it has 1"},
		{"fail cbor trailing data", append(mustCBOR(t, []any{mediaType, value}), 0x00), nil, "error parsing cmw cbor record"},
		{"fail neither", []byte{0x01}, nil, "neither a json nor a cbor record"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.data)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				assert.Nil(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIndicator_Has(t *testing.T) {
	assert.True(t, Evidence.Has(Evidence))
	assert.True(t, (Evidence | Endorsements).Has(Evidence))
	assert.False(t, Evidence.Has(AttestationResults))
	assert.False(t, Indicator(0).Has(Evidence))
}
