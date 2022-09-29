package provisioner

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
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
	"github.com/smallstep/certificates/webhook"
	"go.step.sm/crypto/x509util"
	"go.step.sm/linkedca"
)

func TestWebhookController_isCertTypeOK(t *testing.T) {
	type test struct {
		wc   *WebhookController
		wh   *Webhook
		want bool
	}
	tests := map[string]test{
		"all/all": {
			wc:   &WebhookController{certType: linkedca.Webhook_ALL},
			wh:   &Webhook{CertType: linkedca.Webhook_ALL.String()},
			want: true,
		},
		"all/x509": {
			wc:   &WebhookController{certType: linkedca.Webhook_ALL},
			wh:   &Webhook{CertType: linkedca.Webhook_X509.String()},
			want: true,
		},
		"all/ssh": {
			wc:   &WebhookController{certType: linkedca.Webhook_ALL},
			wh:   &Webhook{CertType: linkedca.Webhook_SSH.String()},
			want: true,
		},
		`all/""`: {
			wc:   &WebhookController{certType: linkedca.Webhook_ALL},
			wh:   &Webhook{},
			want: true,
		},
		"x509/all": {
			wc:   &WebhookController{certType: linkedca.Webhook_X509},
			wh:   &Webhook{CertType: linkedca.Webhook_ALL.String()},
			want: true,
		},
		"x509/x509": {
			wc:   &WebhookController{certType: linkedca.Webhook_X509},
			wh:   &Webhook{CertType: linkedca.Webhook_X509.String()},
			want: true,
		},
		"x509/ssh": {
			wc:   &WebhookController{certType: linkedca.Webhook_X509},
			wh:   &Webhook{CertType: linkedca.Webhook_SSH.String()},
			want: false,
		},
		`x509/""`: {
			wc:   &WebhookController{certType: linkedca.Webhook_X509},
			wh:   &Webhook{},
			want: true,
		},
		"ssh/all": {
			wc:   &WebhookController{certType: linkedca.Webhook_SSH},
			wh:   &Webhook{CertType: linkedca.Webhook_ALL.String()},
			want: true,
		},
		"ssh/x509": {
			wc:   &WebhookController{certType: linkedca.Webhook_SSH},
			wh:   &Webhook{CertType: linkedca.Webhook_X509.String()},
			want: false,
		},
		"ssh/ssh": {
			wc:   &WebhookController{certType: linkedca.Webhook_SSH},
			wh:   &Webhook{CertType: linkedca.Webhook_SSH.String()},
			want: true,
		},
		`ssh/""`: {
			wc:   &WebhookController{certType: linkedca.Webhook_SSH},
			wh:   &Webhook{},
			want: true,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equals(t, test.want, test.wc.isCertTypeOK(test.wh))
		})
	}
}

func TestWebhookController_Enrich(t *testing.T) {
	type test struct {
		ctl                *WebhookController
		req                *webhook.RequestBody
		responses          []*webhook.ResponseBody
		expectErr          bool
		expectTemplateData any
	}
	tests := map[string]test{
		"ok/no enriching webhooks": {
			ctl: &WebhookController{
				client:       http.DefaultClient,
				webhooks:     []*Webhook{{Name: "people", Kind: "AUTHORIZING"}},
				TemplateData: nil,
			},
			req:                &webhook.RequestBody{},
			responses:          nil,
			expectErr:          false,
			expectTemplateData: nil,
		},
		"ok/one webhook": {
			ctl: &WebhookController{
				client:       http.DefaultClient,
				webhooks:     []*Webhook{{Name: "people", Kind: "ENRICHING"}},
				TemplateData: x509util.TemplateData{},
			},
			req:                &webhook.RequestBody{},
			responses:          []*webhook.ResponseBody{{Allow: true, Data: map[string]any{"role": "bar"}}},
			expectErr:          false,
			expectTemplateData: x509util.TemplateData{"Webhooks": map[string]any{"people": map[string]any{"role": "bar"}}},
		},
		"ok/two webhooks": {
			ctl: &WebhookController{
				client: http.DefaultClient,
				webhooks: []*Webhook{
					{Name: "people", Kind: "ENRICHING"},
					{Name: "devices", Kind: "ENRICHING"},
				},
				TemplateData: x509util.TemplateData{},
			},
			req: &webhook.RequestBody{},
			responses: []*webhook.ResponseBody{
				{Allow: true, Data: map[string]any{"role": "bar"}},
				{Allow: true, Data: map[string]any{"serial": "123"}},
			},
			expectErr: false,
			expectTemplateData: x509util.TemplateData{
				"Webhooks": map[string]any{
					"devices": map[string]any{"serial": "123"},
					"people":  map[string]any{"role": "bar"},
				},
			},
		},
		"ok/x509 only": {
			ctl: &WebhookController{
				client: http.DefaultClient,
				webhooks: []*Webhook{
					{Name: "people", Kind: "ENRICHING", CertType: linkedca.Webhook_SSH.String()},
					{Name: "devices", Kind: "ENRICHING"},
				},
				TemplateData: x509util.TemplateData{},
				certType:     linkedca.Webhook_X509,
			},
			req: &webhook.RequestBody{},
			responses: []*webhook.ResponseBody{
				{Allow: true, Data: map[string]any{"role": "bar"}},
				{Allow: true, Data: map[string]any{"serial": "123"}},
			},
			expectErr: false,
			expectTemplateData: x509util.TemplateData{
				"Webhooks": map[string]any{
					"devices": map[string]any{"serial": "123"},
				},
			},
		},
		"deny": {
			ctl: &WebhookController{
				client:       http.DefaultClient,
				webhooks:     []*Webhook{{Name: "people", Kind: "ENRICHING"}},
				TemplateData: x509util.TemplateData{},
			},
			req:                &webhook.RequestBody{},
			responses:          []*webhook.ResponseBody{{Allow: false}},
			expectErr:          true,
			expectTemplateData: x509util.TemplateData{},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			for i, wh := range test.ctl.webhooks {
				var j = i
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					err := json.NewEncoder(w).Encode(test.responses[j])
					assert.FatalError(t, err)
				}))
				// nolint: gocritic // defer in loop isn't a memory leak
				defer ts.Close()
				wh.URL = ts.URL
			}

			err := test.ctl.Enrich(test.req)
			if (err != nil) != test.expectErr {
				t.Fatalf("Got err %v, want %v", err, test.expectErr)
			}
			assert.Equals(t, test.expectTemplateData, test.ctl.TemplateData)
		})
	}
}

func TestWebhookController_Authorize(t *testing.T) {
	type test struct {
		ctl       *WebhookController
		req       *webhook.RequestBody
		responses []*webhook.ResponseBody
		expectErr bool
	}
	tests := map[string]test{
		"ok/no enriching webhooks": {
			ctl: &WebhookController{
				client:   http.DefaultClient,
				webhooks: []*Webhook{{Name: "people", Kind: "ENRICHING"}},
			},
			req:       &webhook.RequestBody{},
			responses: nil,
			expectErr: false,
		},
		"ok": {
			ctl: &WebhookController{
				client:   http.DefaultClient,
				webhooks: []*Webhook{{Name: "people", Kind: "AUTHORIZING"}},
			},
			req:       &webhook.RequestBody{},
			responses: []*webhook.ResponseBody{{Allow: true}},
			expectErr: false,
		},
		"ok/ssh only": {
			ctl: &WebhookController{
				client:   http.DefaultClient,
				webhooks: []*Webhook{{Name: "people", Kind: "AUTHORIZING", CertType: linkedca.Webhook_X509.String()}},
				certType: linkedca.Webhook_SSH,
			},
			req:       &webhook.RequestBody{},
			responses: []*webhook.ResponseBody{{Allow: false}},
			expectErr: false,
		},
		"deny": {
			ctl: &WebhookController{
				client:   http.DefaultClient,
				webhooks: []*Webhook{{Name: "people", Kind: "AUTHORIZING"}},
			},
			req:       &webhook.RequestBody{},
			responses: []*webhook.ResponseBody{{Allow: false}},
			expectErr: true,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			for i, wh := range test.ctl.webhooks {
				var j = i
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					err := json.NewEncoder(w).Encode(test.responses[j])
					assert.FatalError(t, err)
				}))
				// nolint: gocritic // defer in loop isn't a memory leak
				defer ts.Close()
				wh.URL = ts.URL
			}

			err := test.ctl.Authorize(test.req)
			if (err != nil) != test.expectErr {
				t.Fatalf("Got err %v, want %v", err, test.expectErr)
			}
		})
	}
}

func TestWebhook_Do(t *testing.T) {
	csr := parseCertificateRequest(t, "testdata/certs/ecdsa.csr")
	type test struct {
		webhook         Webhook
		dataArg         any
		webhookResponse webhook.ResponseBody
		expectPath      string
		errStatusCode   int
		serverErrMsg    string
		expectErr       error
		// expectToken     any
	}
	tests := map[string]test{
		"ok": {
			webhook: Webhook{
				ID:     "abc123",
				Secret: "c2VjcmV0Cg==",
			},
			webhookResponse: webhook.ResponseBody{
				Data: map[string]interface{}{"role": "dba"},
			},
		},
		"ok/bearer": {
			webhook: Webhook{
				ID:          "abc123",
				Secret:      "c2VjcmV0Cg==",
				BearerToken: "mytoken",
			},
			webhookResponse: webhook.ResponseBody{
				Data: map[string]interface{}{"role": "dba"},
			},
		},
		"ok/basic": {
			webhook: Webhook{
				ID:     "abc123",
				Secret: "c2VjcmV0Cg==",
				BasicAuth: struct {
					Username string
					Password string
				}{
					Username: "myuser",
					Password: "mypass",
				},
			},
			webhookResponse: webhook.ResponseBody{
				Data: map[string]interface{}{"role": "dba"},
			},
		},
		"ok/templated-url": {
			webhook: Webhook{
				ID: "abc123",
				// scheme, host, port will come from test server
				URL:    "/users/{{ .username }}?region={{ .region }}",
				Secret: "c2VjcmV0Cg==",
			},
			dataArg: map[string]interface{}{"username": "areed", "region": "central"},
			webhookResponse: webhook.ResponseBody{
				Data: map[string]interface{}{"role": "dba"},
			},
			expectPath: "/users/areed?region=central",
		},
		/*
			"ok/token from ssh template": {
				webhook: Webhook{
					ID:     "abc123",
					Secret: "c2VjcmV0Cg==",
				},
				webhookResponse: webhook.ResponseBody{
					Data: map[string]interface{}{"role": "dba"},
				},
				dataArg:     sshutil.TemplateData{sshutil.TokenKey: "token"},
				expectToken: "token",
			},
			"ok/token from x509 template": {
				webhook: Webhook{
					ID:     "abc123",
					Secret: "c2VjcmV0Cg==",
				},
				webhookResponse: webhook.ResponseBody{
					Data: map[string]interface{}{"role": "dba"},
				},
				dataArg:     x509util.TemplateData{sshutil.TokenKey: "token"},
				expectToken: "token",
			},
		*/
		"ok/allow": {
			webhook: Webhook{
				ID:     "abc123",
				Secret: "c2VjcmV0Cg==",
			},
			webhookResponse: webhook.ResponseBody{
				Allow: true,
			},
		},
		"fail/404": {
			webhook: Webhook{
				ID:     "abc123",
				Secret: "c2VjcmV0Cg==",
			},
			webhookResponse: webhook.ResponseBody{
				Data: map[string]interface{}{"role": "dba"},
			},
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

				secret, err := base64.StdEncoding.DecodeString(tc.webhook.Secret)
				assert.FatalError(t, err)
				mac := hmac.New(sha256.New, secret).Sum(body)
				assert.True(t, hmac.Equal(sig, mac))

				switch {
				case tc.webhook.BearerToken != "":
					ah := fmt.Sprintf("Bearer %s", tc.webhook.BearerToken)
					assert.Equals(t, ah, r.Header.Get("Authorization"))
				case tc.webhook.BasicAuth.Username != "" || tc.webhook.BasicAuth.Password != "":
					whReq, err := http.NewRequest("", "", http.NoBody)
					assert.FatalError(t, err)
					whReq.SetBasicAuth(tc.webhook.BasicAuth.Username, tc.webhook.BasicAuth.Password)
					ah := whReq.Header.Get("Authorization")
					assert.Equals(t, ah, whReq.Header.Get("Authorization"))
				default:
					assert.Equals(t, "", r.Header.Get("Authorization"))
				}

				if tc.expectPath != "" {
					assert.Equals(t, tc.expectPath, r.URL.Path+"?"+r.URL.RawQuery)
				}

				if tc.errStatusCode != 0 {
					http.Error(w, tc.serverErrMsg, tc.errStatusCode)
					return
				}

				reqBody := new(webhook.RequestBody)
				err = json.Unmarshal(body, reqBody)
				assert.FatalError(t, err)
				// assert.Equals(t, tc.expectToken, reqBody.Token)

				err = json.NewEncoder(w).Encode(tc.webhookResponse)
				assert.FatalError(t, err)
			}))
			defer ts.Close()

			tc.webhook.URL = ts.URL + tc.webhook.URL

			reqBody, err := webhook.NewRequestBody(webhook.WithX509CertificateRequest(csr))
			assert.FatalError(t, err)
			got, err := tc.webhook.Do(http.DefaultClient, reqBody, tc.dataArg)
			if tc.expectErr != nil {
				assert.Equals(t, tc.expectErr.Error(), err.Error())
				return
			}
			assert.FatalError(t, err)

			assert.Equals(t, got, &tc.webhookResponse)
		})
	}

	t.Run("disableTLSClientAuth", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("{}"))
		}))
		ts.TLS.ClientAuth = tls.RequireAnyClientCert
		wh := Webhook{
			URL: ts.URL,
		}
		cert, err := tls.LoadX509KeyPair("testdata/certs/foo.crt", "testdata/secrets/foo.key")
		assert.FatalError(t, err)
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{cert},
		}
		client := &http.Client{
			Transport: transport,
		}
		reqBody, err := webhook.NewRequestBody(webhook.WithX509CertificateRequest(csr))
		assert.FatalError(t, err)
		_, err = wh.Do(client, reqBody, nil)
		assert.FatalError(t, err)

		wh.DisableTLSClientAuth = true
		_, err = wh.Do(client, reqBody, nil)
		assert.Error(t, err)
	})
}
