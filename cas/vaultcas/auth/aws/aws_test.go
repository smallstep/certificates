package aws

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
		switch r.RequestURI {
		case "/v1/auth/aws/login":
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{
				  "auth": {
					"client_token": "hvs.0000"
				  }
				}`)
		case "/v1/auth/custom-aws/login":
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

func TestAws_LoginMountPaths(t *testing.T) {
	_, client := testCAHelper(t)

	// Dummy AWS credentials is needed for Vault client to sign the STS request
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

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
			mountPath: "aws",
			token:     "hvs.0000",
		},
		{
			name:      "ok custom mount path",
			mountPath: "custom-aws",
			token:     "hvs.9999",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method, err := NewAwsAuthMethod(tt.mountPath, json.RawMessage(`{"role":"test-role","awsAuthType":"iam"}`))
			if err != nil {
				t.Errorf("NewAwsAuthMethod() error = %v", err)
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

func TestAws_NewAwsAuthMethod(t *testing.T) {
	tests := []struct {
		name      string
		mountPath string
		raw       string
		wantErr   bool
	}{
		{
			"ok iam",
			"",
			`{"role":"test-role","awsAuthType":"iam"}`,
			false,
		},
		{
			"ok iam with region",
			"",
			`{"role":"test-role","awsAuthType":"iam","region":"us-east-1"}`,
			false,
		},
		{
			"ok iam with header",
			"",
			`{"role":"test-role","awsAuthType":"iam","iamServerIdHeader":"vault.example.com"}`,
			false,
		},
		{
			"ok ec2",
			"",
			`{"role":"test-role","awsAuthType":"ec2"}`,
			false,
		},
		{
			"ok ec2 with nonce",
			"",
			`{"role":"test-role","awsAuthType":"ec2","nonce": "0000-0000-0000-0000"}`,
			false,
		},
		{
			"ok ec2 with signature type",
			"",
			`{"role":"test-role","awsAuthType":"ec2","signatureType":"rsa2048"}`,
			false,
		},
		{
			"fail mandatory role",
			"",
			`{}`,
			true,
		},
		{
			"fail mandatory auth type",
			"",
			`{"role":"test-role"}`,
			true,
		},
		{
			"fail invalid auth type",
			"",
			`{"role":"test-role","awsAuthType":"test"}`,
			true,
		},
		{
			"fail invalid ec2 signature type",
			"",
			`{"role":"test-role","awsAuthType":"test","signatureType":"test"}`,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewAwsAuthMethod(tt.mountPath, json.RawMessage(tt.raw))
			if (err != nil) != tt.wantErr {
				t.Errorf("Aws.NewAwsAuthMethod() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
