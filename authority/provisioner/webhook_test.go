package provisioner

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
)

func TestWebhook_Do(t *testing.T) {
	type test struct {
		webhook       Webhook
		dataArg       map[string]interface{}
		webhookData   map[string]interface{}
		expectPath    string
		errStatusCode int
		serverErrMsg  string
		expectErr     error
	}
	tests := map[string]test{
		"ok": {
			webhook: Webhook{
				ID:            "abc123",
				SigningSecret: "c2VjcmV0Cg==",
			},
			webhookData: map[string]interface{}{"role": "dba"},
		},
		"ok/bearer": {
			webhook: Webhook{
				ID:            "abc123",
				SigningSecret: "c2VjcmV0Cg==",
				BearerToken:   "mytoken",
			},
			webhookData: map[string]interface{}{"role": "dba"},
		},
		"ok/basic": {
			webhook: Webhook{
				ID:            "abc123",
				SigningSecret: "c2VjcmV0Cg==",
				BasicAuth: struct {
					Username string
					Password string
				}{
					Username: "myuser",
					Password: "mypass",
				},
			},
			webhookData: map[string]interface{}{"role": "dba"},
		},
		"ok/templated-url": {
			webhook: Webhook{
				ID: "abc123",
				// scheme, host, port will come from test server
				URL:           "/users/{{ .username }}?region={{ .region }}",
				SigningSecret: "c2VjcmV0Cg==",
			},
			dataArg:     map[string]interface{}{"username": "areed", "region": "central"},
			webhookData: map[string]interface{}{"role": "dba"},
			expectPath:  "/users/areed?region=central",
		},
		"fail/404": {
			webhook: Webhook{
				ID:            "abc123",
				SigningSecret: "c2VjcmV0Cg==",
			},
			webhookData:   map[string]interface{}{"role": "dba"},
			errStatusCode: 404,
			serverErrMsg:  "item not found",
			expectErr:     errors.New("Webhook server responded with 404"),
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				id := r.Header.Get("X-Smallstep-Webhook-ID")
				assert.Equals(t, tc.webhook.ID, id)

				sig, err := hex.DecodeString(r.Header.Get("X-Smallstep-Signature"))
				assert.FatalError(t, err)

				body, err := io.ReadAll(r.Body)
				assert.FatalError(t, err)

				secret, err := base64.StdEncoding.DecodeString(tc.webhook.SigningSecret)
				assert.FatalError(t, err)
				mac := hmac.New(sha256.New, secret).Sum(body)
				assert.True(t, hmac.Equal(sig, mac))

				if tc.webhook.BearerToken != "" {
					ah := fmt.Sprintf("Bearer %s", tc.webhook.BearerToken)
					assert.Equals(t, ah, r.Header.Get("Authorization"))
				} else if tc.webhook.BasicAuth.Username != "" || tc.webhook.BasicAuth.Password != "" {
					r, err := http.NewRequest("", "", nil)
					assert.FatalError(t, err)
					r.SetBasicAuth(tc.webhook.BasicAuth.Username, tc.webhook.BasicAuth.Password)
					ah := r.Header.Get("Authorization")
					assert.Equals(t, ah, r.Header.Get("Authorization"))
				} else {
					assert.Equals(t, "", r.Header.Get("Authorization"))
				}

				if tc.expectPath != "" {
					assert.Equals(t, tc.expectPath, r.URL.Path+"?"+r.URL.RawQuery)
				}

				if tc.errStatusCode != 0 {
					http.Error(w, tc.serverErrMsg, tc.errStatusCode)
					return
				}

				err = json.NewEncoder(w).Encode(webhookResponseBody{
					Data: tc.webhookData,
				})
				assert.FatalError(t, err)
			}))
			defer ts.Close()

			tc.webhook.URL = ts.URL + tc.webhook.URL

			csr := parseCertificateRequest(t, "testdata/certs/ecdsa.csr")
			got, err := tc.webhook.Do(context.Background(), http.DefaultClient, csr, tc.dataArg)
			if tc.expectErr != nil {
				assert.Equals(t, tc.expectErr.Error(), err.Error())
				return
			}
			assert.FatalError(t, err)

			assert.Equals(t, got, tc.webhookData)
		})
	}
}
