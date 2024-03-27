package wire

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"text/template"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/jose"
)

func TestOIDCOptions_Transform(t *testing.T) {
	defaultTransform, err := parseTransform(``)
	require.NoError(t, err)
	swapTransform, err := parseTransform(`{"name": "{{ .preferred_username }}", "preferred_username": "{{ .name }}"}`)
	require.NoError(t, err)
	funcTransform, err := parseTransform(`{"name": "{{ .name }}", "preferred_username": "{{ first .usernames }}"}`)
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
				"preferred_username": "Example",
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
				"name":               "Example",
				"preferred_username": "name-1",
				"usernames":          []string{"name-1", "name-2", "name-3"},
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

func TestOIDCOptions_EvaluateTarget(t *testing.T) {
	tu := "http://target.example.com/{{.DeviceID}}"
	target, err := template.New("DeviceID").Parse(tu)
	require.NoError(t, err)
	empty := "http://target.example.com"
	emptyTarget, err := template.New("DeviceID").Parse(empty)
	require.NoError(t, err)
	fail := "https:/wire.com:15958/clients/{{.DeviceId}}/access-token"
	failTarget, err := template.New("DeviceID").Parse(fail)
	require.NoError(t, err)
	type fields struct {
		target *template.Template
	}
	type args struct {
		deviceID string
	}
	tests := []struct {
		name        string
		fields      fields
		args        args
		want        string
		expectedErr error
	}{
		{
			name: "ok", fields: fields{target: target}, args: args{deviceID: "deviceID"}, want: "http://target.example.com/deviceID",
		},
		{
			name: "ok/empty", fields: fields{target: emptyTarget}, args: args{deviceID: ""}, want: "http://target.example.com",
		},
		{
			name: "fail/template", fields: fields{target: failTarget}, args: args{deviceID: "bla"}, expectedErr: errors.New(`failed executing OIDC template: template: DeviceID:1:32: executing "DeviceID" at <.DeviceId>: can't evaluate field DeviceId in type struct { DeviceID string }`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &OIDCOptions{
				target: tt.fields.target,
			}
			got, err := o.EvaluateTarget(tt.args.deviceID)
			if tt.expectedErr != nil {
				assert.EqualError(t, err, tt.expectedErr.Error())
				assert.Empty(t, got)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestOIDCOptions_GetVerifier(t *testing.T) {
	signerJWK, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
	require.NoError(t, err)
	require.NoError(t, err)
	srv := mustDiscoveryServer(t, signerJWK.Public())
	defer srv.Close()
	type fields struct {
		Provider          *Provider
		Config            *Config
		TransformTemplate string
	}
	tests := []struct {
		name    string
		fields  fields
		ctx     context.Context
		want    *oidc.IDTokenVerifier
		wantErr bool
	}{
		{
			name: "fail/invalid-discovery-url",
			fields: fields{
				Provider: &Provider{
					DiscoveryBaseURL: "http://invalid.example.com",
				},
				Config: &Config{
					ClientID: "client-id",
				},
				TransformTemplate: "http://target.example.com/{{.DeviceID}}",
			},
			ctx:     context.Background(),
			wantErr: true,
		},
		{
			name: "ok/auto",
			fields: fields{
				Provider: &Provider{
					DiscoveryBaseURL: srv.URL,
				},
				Config: &Config{
					ClientID: "client-id",
				},
				TransformTemplate: "http://target.example.com/{{.DeviceID}}",
			},
			ctx: context.Background(),
		},
		{
			name: "ok/fixed",
			fields: fields{
				Provider: &Provider{
					IssuerURL: "http://issuer.example.com",
				},
				Config: &Config{
					ClientID: "client-id",
				},
				TransformTemplate: "http://target.example.com/{{.DeviceID}}",
			},
			ctx: context.Background(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &OIDCOptions{
				Provider:          tt.fields.Provider,
				Config:            tt.fields.Config,
				TransformTemplate: tt.fields.TransformTemplate,
			}

			err := o.validateAndInitialize()
			require.NoError(t, err)

			verifier, err := o.GetVerifier(tt.ctx)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, verifier)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, verifier)
			if assert.NotNil(t, o.provider) {
				assert.NotNil(t, o.provider.Endpoint())
			}
		})
	}
}

func mustDiscoveryServer(t *testing.T, pub jose.JSONWebKey) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	b, err := json.Marshal(struct {
		Keys []jose.JSONWebKey `json:"keys,omitempty"`
	}{
		Keys: []jose.JSONWebKey{pub},
	})
	require.NoError(t, err)
	jwks := string(b)

	wellKnown := fmt.Sprintf(`{
		"issuer": "%[1]s",
		"authorization_endpoint": "%[1]s/auth",
		"token_endpoint": "%[1]s/token",
		"jwks_uri": "%[1]s/keys",
		"userinfo_endpoint": "%[1]s/userinfo",
		"id_token_signing_alg_values_supported": ["ES256"]
	}`, server.URL)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, req *http.Request) {
		_, err := io.WriteString(w, wellKnown)
		if err != nil {
			w.WriteHeader(500)
		}
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, req *http.Request) {
		_, err := io.WriteString(w, jwks)
		if err != nil {
			w.WriteHeader(500)
		}
	})

	t.Cleanup(server.Close)
	return server
}
