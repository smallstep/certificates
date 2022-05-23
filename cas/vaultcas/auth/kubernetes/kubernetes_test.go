package kubernetes

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"path/filepath"
	"runtime"
	"testing"

	vault "github.com/hashicorp/vault/api"
)

func testCAHelper(t *testing.T) (*url.URL, *vault.Client) {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.RequestURI == "/v1/auth/kubernetes/login":
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{
				  "auth": {
					"client_token": "hvs.0000"
				  }
				}`)
		case r.RequestURI == "/v1/auth/custom-kubernetes/login":
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
	_, filename, _, _ := runtime.Caller(0)
	tokenPath := filepath.Join(path.Dir(filename), "token")

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
			mountPath: "kubernetes",
			token:     "hvs.0000",
		},
		{
			name:      "ok custom mount path",
			mountPath: "custom-kubernetes",
			token:     "hvs.9999",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method, err := NewKubernetesAuthMethod(tt.mountPath, json.RawMessage(`{"role": "SomeRoleName", "tokenPath": "`+tokenPath+`"}`))
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
	_, filename, _, _ := runtime.Caller(0)
	tokenPath := filepath.Join(path.Dir(filename), "token")

	tests := []struct {
		name      string
		mountPath string
		raw       string
		wantErr   bool
	}{
		{
			"ok secret-id string",
			"",
			`{"role": "SomeRoleName", "tokenPath": "` + tokenPath + `"}`,
			false,
		},
		{
			"fail mandatory role",
			"",
			`{}`,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewKubernetesAuthMethod(tt.mountPath, json.RawMessage(tt.raw))
			if (err != nil) != tt.wantErr {
				t.Errorf("Kubernetes.NewKubernetesAuthMethod() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
