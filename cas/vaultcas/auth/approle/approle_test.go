package approle

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	vault "github.com/hashicorp/vault/api"
)

func testCAHelper(t *testing.T) (*url.URL, *vault.Client) {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.RequestURI == "/v1/auth/approle/login":
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{
				  "auth": {
					"client_token": "hvs.0000"
				  }
				}`)
		case r.RequestURI == "/v1/auth/custom-approle/login":
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{
				  "auth": {
					"client_token": "hvs.9999"
				  }
				}`)
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, `{"error":"not found"}`)
		}
	}))
	t.Cleanup(func() {
		srv.Close()
	})
	u, err := url.Parse(srv.URL)
	if err != nil {
		srv.Close()
		t.Fatal(err)
	}

	config := vault.DefaultConfig()
	config.Address = srv.URL

	client, err := vault.NewClient(config)
	if err != nil {
		srv.Close()
		t.Fatal(err)
	}

	return u, client
}

func TestApprole_LoginMountPaths(t *testing.T) {
	caURL, _ := testCAHelper(t)

	config := vault.DefaultConfig()
	config.Address = caURL.String()
	client, _ := vault.NewClient(config)

	tests := []struct {
		name      string
		mountPath string
		token     string
	}{
		{
			name:      "ok default mount path",
			mountPath: "",
			token:     "hvs.0000",
		},
		{
			name:      "ok explicit mount path",
			mountPath: "approle",
			token:     "hvs.0000",
		},
		{
			name:      "ok custom mount path",
			mountPath: "custom-approle",
			token:     "hvs.9999",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method, err := NewApproleAuthMethod(tt.mountPath, json.RawMessage(`{"RoleID":"roleID","SecretID":"secretID","IsWrappingToken":false}`))
			if err != nil {
				t.Errorf("NewApproleAuthMethod() error = %v", err)
				return
			}

			secret, err := client.Auth().Login(context.Background(), method)
			if err != nil {
				t.Errorf("Login() error = %v", err)
				return
			}

			token, _ := secret.TokenID()
			if token != tt.token {
				t.Errorf("Token error got %v, expected %v", token, tt.token)
				return
			}
		})
	}
}

func TestApprole_NewApproleAuthMethod(t *testing.T) {
	tests := []struct {
		name      string
		mountPath string
		raw       string
		wantErr   bool
	}{
		{
			"ok secret-id string",
			"",
			`{"RoleID": "0000-0000-0000-0000", "SecretID": "0000-0000-0000-0000"}`,
			false,
		},
		{
			"ok secret-id string and wrapped",
			"",
			`{"RoleID": "0000-0000-0000-0000", "SecretID": "0000-0000-0000-0000", "isWrappedToken": true}`,
			false,
		},
		{
			"ok secret-id string and wrapped with custom mountPath",
			"approle2",
			`{"RoleID": "0000-0000-0000-0000", "SecretID": "0000-0000-0000-0000", "isWrappedToken": true}`,
			false,
		},
		{
			"ok secret-id file",
			"",
			`{"RoleID": "0000-0000-0000-0000", "SecretIDFile": "./secret-id"}`,
			false,
		},
		{
			"ok secret-id env",
			"",
			`{"RoleID": "0000-0000-0000-0000", "SecretIDEnv": "VAULT_APPROLE_SECRETID"}`,
			false,
		},
		{
			"fail mandatory role-id",
			"",
			`{}`,
			true,
		},
		{
			"fail mandatory secret-id any",
			"",
			`{"RoleID": "0000-0000-0000-0000"}`,
			true,
		},
		{
			"fail multiple secret-id types id and env",
			"",
			`{"RoleID": "0000-0000-0000-0000", "SecretID": "0000-0000-0000-0000", "SecretIDEnv": "VAULT_APPROLE_SECRETID"}`,
			true,
		},
		{
			"fail multiple secret-id types id and file",
			"",
			`{"RoleID": "0000-0000-0000-0000", "SecretID": "0000-0000-0000-0000", "SecretIDFile": "./secret-id"}`,
			true,
		},
		{
			"fail multiple secret-id types env and file",
			"",
			`{"RoleID": "0000-0000-0000-0000", "SecretIDFile": "./secret-id", "SecretIDEnv": "VAULT_APPROLE_SECRETID"}`,
			true,
		},
		{
			"fail multiple secret-id types all",
			"",
			`{"RoleID": "0000-0000-0000-0000", "SecretID": "0000-0000-0000-0000", "SecretIDFile": "./secret-id", "SecretIDEnv": "VAULT_APPROLE_SECRETID"}`,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewApproleAuthMethod(tt.mountPath, json.RawMessage(tt.raw))
			if (err != nil) != tt.wantErr {
				t.Errorf("Approle.NewApproleAuthMethod() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
