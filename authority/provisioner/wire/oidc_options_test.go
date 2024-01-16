package wire

import (
	"testing"
	"text/template"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOIDCOptions_Transform(t *testing.T) {
	defaultTransform, err := parseTransform(``)
	require.NoError(t, err)
	swapTransform, err := parseTransform(`{"name": "{{ .preferred_username }}", "handle": "{{ .name }}"}`)
	require.NoError(t, err)
	funcTransform, err := parseTransform(`{"name": "{{ .name }}", "handle": "{{ first .usernames }}"}`)
	require.NoError(t, err)
	type fields struct {
		transform *template.Template
	}
	type args struct {
		v map[string]any
	}
	tests := []struct {
		name        string
		fields      fields
		args        args
		want        map[string]any
		expectedErr error
	}{
		{
			name: "ok/no-transform",
			fields: fields{
				transform: nil,
			},
			args: args{
				v: map[string]any{
					"name":               "Example",
					"preferred_username": "Preferred",
				},
			},
			want: map[string]any{
				"name":               "Example",
				"preferred_username": "Preferred",
			},
		},
		{
			name: "ok/empty-data",
			fields: fields{
				transform: nil,
			},
			args: args{
				v: map[string]any{},
			},
			want: map[string]any{},
		},
		{
			name: "ok/default-transform",
			fields: fields{
				transform: defaultTransform,
			},
			args: args{
				v: map[string]any{
					"name":               "Example",
					"preferred_username": "Preferred",
				},
			},
			want: map[string]any{
				"name":               "Example",
				"handle":             "Preferred",
				"preferred_username": "Preferred",
			},
		},
		{
			name: "ok/swap-transform",
			fields: fields{
				transform: swapTransform,
			},
			args: args{
				v: map[string]any{
					"name":               "Example",
					"preferred_username": "Preferred",
				},
			},
			want: map[string]any{
				"name":               "Preferred",
				"handle":             "Example",
				"preferred_username": "Preferred",
			},
		},
		{
			name: "ok/transform-with-functions",
			fields: fields{
				transform: funcTransform,
			},
			args: args{
				v: map[string]any{
					"name":      "Example",
					"usernames": []string{"name-1", "name-2", "name-3"},
				},
			},
			want: map[string]any{
				"name":      "Example",
				"handle":    "name-1",
				"usernames": []string{"name-1", "name-2", "name-3"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &OIDCOptions{
				transform: tt.fields.transform,
			}
			got, err := o.Transform(tt.args.v)
			if tt.expectedErr != nil {
				assert.Error(t, err)
				return
			}

			assert.Equal(t, tt.want, got)
		})
	}
}
