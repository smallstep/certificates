package provisioner

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/x509util"
	"go.step.sm/linkedca"

	"github.com/smallstep/certificates/middleware/requestid"
	"github.com/smallstep/certificates/webhook"
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
			assert.Equal(t, test.want, test.wc.isCertTypeOK(test.wh))
		})
	}
}

// withRequestID is a helper that calls into [requestid.NewContext] and returns
// a new context with the requestID added.
func withRequestID(t *testing.T, ctx context.Context, requestID string) context.Context {
	t.Helper()
	return requestid.NewContext(ctx, requestID)
}

func TestWebhookController_Enrich(t *testing.T) {
	cert, err := pemutil.ReadCertificate("testdata/certs/x5c-leaf.crt", pemutil.WithFirstBlock())
	require.NoError(t, err)

	type test struct {
		ctl                *WebhookController
		ctx                context.Context
		req                *webhook.RequestBody
		responses          []*webhook.ResponseBody
		expectErr          bool
		expectTemplateData any
		assertRequest      func(t *testing.T, req *webhook.RequestBody)
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
			ctx:                withRequestID(t, context.Background(), "reqID"),
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
			ctx: withRequestID(t, context.Background(), "reqID"),
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
			ctx: withRequestID(t, context.Background(), "reqID"),
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
		"ok/with options": {
			ctl: &WebhookController{
				client:       http.DefaultClient,
				webhooks:     []*Webhook{{Name: "people", Kind: "ENRICHING"}},
				TemplateData: x509util.TemplateData{},
				options:      []webhook.RequestBodyOption{webhook.WithX5CCertificate(cert)},
			},
			ctx:                withRequestID(t, context.Background(), "reqID"),
			req:                &webhook.RequestBody{},
			responses:          []*webhook.ResponseBody{{Allow: true, Data: map[string]any{"role": "bar"}}},
			expectErr:          false,
			expectTemplateData: x509util.TemplateData{"Webhooks": map[string]any{"people": map[string]any{"role": "bar"}}},
			assertRequest: func(t *testing.T, req *webhook.RequestBody) {
				key, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
				require.NoError(t, err)
				assert.Equal(t, &webhook.X5CCertificate{
					Raw:                cert.Raw,
					PublicKey:          key,
					PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
					NotBefore:          cert.NotBefore,
					NotAfter:           cert.NotAfter,
				}, req.X5CCertificate)
			},
		},
		"deny": {
			ctl: &WebhookController{
				client:       http.DefaultClient,
				webhooks:     []*Webhook{{Name: "people", Kind: "ENRICHING"}},
				TemplateData: x509util.TemplateData{},
			},
			ctx:                withRequestID(t, context.Background(), "reqID"),
			req:                &webhook.RequestBody{},
			responses:          []*webhook.ResponseBody{{Allow: false}},
			expectErr:          true,
			expectTemplateData: x509util.TemplateData{},
		},
		"fail/with options": {
			ctl: &WebhookController{
				client:       http.DefaultClient,
				webhooks:     []*Webhook{{Name: "people", Kind: "ENRICHING"}},
				TemplateData: x509util.TemplateData{},
				options: []webhook.RequestBodyOption{webhook.WithX5CCertificate(&x509.Certificate{
					PublicKey: []byte("bad"),
				})},
			},
			ctx:                withRequestID(t, context.Background(), "reqID"),
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
					assert.Equal(t, "reqID", r.Header.Get("X-Request-ID"))

					err := json.NewEncoder(w).Encode(test.responses[j])
					require.NoError(t, err)
				}))
				// nolint: gocritic // defer in loop isn't a memory leak
				defer ts.Close()
				wh.URL = ts.URL
			}

			err := test.ctl.Enrich(test.ctx, test.req)
			if (err != nil) != test.expectErr {
				t.Fatalf("Got err %v, want %v", err, test.expectErr)
			}
			assert.Equal(t, test.expectTemplateData, test.ctl.TemplateData)
			if test.assertRequest != nil {
				test.assertRequest(t, test.req)
			}
		})
	}
}

func TestWebhookController_Authorize(t *testing.T) {
	cert, err := pemutil.ReadCertificate("testdata/certs/x5c-leaf.crt", pemutil.WithFirstBlock())
	require.NoError(t, err)

	type test struct {
		ctl           *WebhookController
		ctx           context.Context
		req           *webhook.RequestBody
		responses     []*webhook.ResponseBody
		expectErr     bool
		assertRequest func(t *testing.T, req *webhook.RequestBody)
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
			ctx:       withRequestID(t, context.Background(), "reqID"),
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
			ctx:       withRequestID(t, context.Background(), "reqID"),
			req:       &webhook.RequestBody{},
			responses: []*webhook.ResponseBody{{Allow: false}},
			expectErr: false,
		},
		"ok/with options": {
			ctl: &WebhookController{
				client:   http.DefaultClient,
				webhooks: []*Webhook{{Name: "people", Kind: "AUTHORIZING"}},
				options:  []webhook.RequestBodyOption{webhook.WithX5CCertificate(cert)},
			},
			ctx:       withRequestID(t, context.Background(), "reqID"),
			req:       &webhook.RequestBody{},
			responses: []*webhook.ResponseBody{{Allow: true}},
			expectErr: false,
			assertRequest: func(t *testing.T, req *webhook.RequestBody) {
				key, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
				require.NoError(t, err)
				assert.Equal(t, &webhook.X5CCertificate{
					Raw:                cert.Raw,
					PublicKey:          key,
					PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
					NotBefore:          cert.NotBefore,
					NotAfter:           cert.NotAfter,
				}, req.X5CCertificate)
			},
		},
		"deny": {
			ctl: &WebhookController{
				client:   http.DefaultClient,
				webhooks: []*Webhook{{Name: "people", Kind: "AUTHORIZING"}},
			},
			ctx:       withRequestID(t, context.Background(), "reqID"),
			req:       &webhook.RequestBody{},
			responses: []*webhook.ResponseBody{{Allow: false}},
			expectErr: true,
		},
		"fail/with options": {
			ctl: &WebhookController{
				client:   http.DefaultClient,
				webhooks: []*Webhook{{Name: "people", Kind: "AUTHORIZING"}},
				options: []webhook.RequestBodyOption{webhook.WithX5CCertificate(&x509.Certificate{
					PublicKey: []byte("bad"),
				})},
			},
			ctx:       withRequestID(t, context.Background(), "reqID"),
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
					assert.Equal(t, "reqID", r.Header.Get("X-Request-ID"))

					err := json.NewEncoder(w).Encode(test.responses[j])
					require.NoError(t, err)
				}))
				// nolint: gocritic // defer in loop isn't a memory leak
				defer ts.Close()
				wh.URL = ts.URL
			}

			err := test.ctl.Authorize(test.ctx, test.req)
			if (err != nil) != test.expectErr {
				t.Fatalf("Got err %v, want %v", err, test.expectErr)
			}
			if test.assertRequest != nil {
				test.assertRequest(t, test.req)
			}
		})
	}
}

func TestWebhook_Do(t *testing.T) {
	csr := parseCertificateRequest(t, "testdata/certs/ecdsa.csr")
	type test struct {
		webhook         Webhook
		dataArg         any
		requestID       string
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
			requestID: "reqID",
			webhookResponse: webhook.ResponseBody{
				Data: map[string]interface{}{"role": "dba"},
			},
		},
		"ok/no-request-id": {
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
			requestID: "reqID",
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
			requestID: "reqID",
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
			requestID: "reqID",
			dataArg:   map[string]interface{}{"username": "areed", "region": "central"},
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
			requestID: "reqID",
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
			requestID:     "reqID",
			errStatusCode: 404,
			serverErrMsg:  "item not found",
			expectErr:     errors.New("Webhook server responded with 404"),
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.requestID != "" {
					assert.Equal(t, tc.requestID, r.Header.Get("X-Request-ID"))
				}

				assert.Equal(t, tc.webhook.ID, r.Header.Get("X-Smallstep-Webhook-ID"))

				sig, err := hex.DecodeString(r.Header.Get("X-Smallstep-Signature"))
				assert.NoError(t, err)

				body, err := io.ReadAll(r.Body)
				assert.NoError(t, err)

				secret, err := base64.StdEncoding.DecodeString(tc.webhook.Secret)
				assert.NoError(t, err)
				h := hmac.New(sha256.New, secret)
				h.Write(body)
				mac := h.Sum(nil)
				assert.True(t, hmac.Equal(sig, mac))

				switch {
				case tc.webhook.BearerToken != "":
					ah := fmt.Sprintf("Bearer %s", tc.webhook.BearerToken)
					assert.Equal(t, ah, r.Header.Get("Authorization"))
				case tc.webhook.BasicAuth.Username != "" || tc.webhook.BasicAuth.Password != "":
					whReq, err := http.NewRequest("", "", http.NoBody)
					require.NoError(t, err)
					whReq.SetBasicAuth(tc.webhook.BasicAuth.Username, tc.webhook.BasicAuth.Password)
					ah := whReq.Header.Get("Authorization")
					assert.Equal(t, ah, whReq.Header.Get("Authorization"))
				default:
					assert.Equal(t, "", r.Header.Get("Authorization"))
				}

				if tc.expectPath != "" {
					assert.Equal(t, tc.expectPath, r.URL.Path+"?"+r.URL.RawQuery)
				}

				if tc.errStatusCode != 0 {
					http.Error(w, tc.serverErrMsg, tc.errStatusCode)
					return
				}

				reqBody := new(webhook.RequestBody)
				err = json.Unmarshal(body, reqBody)
				require.NoError(t, err)

				err = json.NewEncoder(w).Encode(tc.webhookResponse)
				require.NoError(t, err)
			}))
			defer ts.Close()

			tc.webhook.URL = ts.URL + tc.webhook.URL

			reqBody, err := webhook.NewRequestBody(webhook.WithX509CertificateRequest(csr))
			require.NoError(t, err)

			ctx := context.Background()
			if tc.requestID != "" {
				ctx = withRequestID(t, ctx, tc.requestID)
			}
			ctx, cancel := context.WithTimeout(ctx, time.Second*10)
			defer cancel()

			got, err := tc.webhook.DoWithContext(ctx, http.DefaultClient, reqBody, tc.dataArg)
			if tc.expectErr != nil {
				assert.Equal(t, tc.expectErr.Error(), err.Error())
				return
			}
			assert.NoError(t, err)

			assert.Equal(t, &tc.webhookResponse, got)
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
		require.NoError(t, err)
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{cert},
		}
		client := &http.Client{
			Transport: transport,
		}
		reqBody, err := webhook.NewRequestBody(webhook.WithX509CertificateRequest(csr))
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()

		_, err = wh.DoWithContext(ctx, client, reqBody, nil)
		require.NoError(t, err)

		ctx, cancel = context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()

		wh.DisableTLSClientAuth = true
		_, err = wh.DoWithContext(ctx, client, reqBody, nil)
		require.Error(t, err)
	})
}
