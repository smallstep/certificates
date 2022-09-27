package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/admin"
	"github.com/stretchr/testify/assert"
	"go.step.sm/linkedca"
	"google.golang.org/protobuf/encoding/protojson"
)

// ignore secret and id since those are set by the server
func assertEqualWebhook(t *testing.T, a, b *linkedca.Webhook) {
	assert.Equal(t, a.Name, b.Name)
	assert.Equal(t, a.Url, b.Url)
	assert.Equal(t, a.Kind, b.Kind)
	assert.Equal(t, a.CertType, b.CertType)
	assert.Equal(t, a.DisableTlsClientAuth, b.DisableTlsClientAuth)

	assert.Equal(t, a.GetAuth(), b.GetAuth())
}

func TestWebhookAdminResponder_CreateProvisionerWebhook(t *testing.T) {
	type test struct {
		auth       adminAuthority
		body       []byte
		ctx        context.Context
		err        *admin.Error
		response   *linkedca.Webhook
		statusCode int
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/existing-webhook": func(t *testing.T) test {
			webhook := &linkedca.Webhook{
				Name: "already-exists",
				Url:  "https://example.com",
			}
			prov := &linkedca.Provisioner{
				Name:     "provName",
				Webhooks: []*linkedca.Webhook{webhook},
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			err := admin.NewError(admin.ErrorConflictType, `provisioner "provName" already has a webhook with the name "already-exists"`)
			err.Message = `provisioner "provName" already has a webhook with the name "already-exists"`
			body := []byte(`
			{
				"name": "already-exists",
				"url": "https://example.com",
				"kind": "ENRICHING"
			}`)
			return test{
				ctx:        ctx,
				body:       body,
				err:        err,
				statusCode: 409,
			}
		},
		"fail/read.ProtoJSON": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Name: "provName",
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			adminErr := admin.NewError(admin.ErrorBadRequestType, "proto: syntax error (line 1:2): invalid value ?")
			adminErr.Message = "proto: syntax error (line 1:2): invalid value ?"
			body := []byte("{?}")
			return test{
				ctx:        ctx,
				body:       body,
				err:        adminErr,
				statusCode: 400,
			}
		},
		"fail/missing-name": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Name: "provName",
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			adminErr := admin.NewError(admin.ErrorBadRequestType, "webhook name is required")
			adminErr.Message = "webhook name is required"
			body := []byte(`{"url": "https://example.com", "kind": "ENRICHING"}`)
			return test{
				ctx:        ctx,
				body:       body,
				err:        adminErr,
				statusCode: 400,
			}
		},
		"fail/missing-url": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Name: "provName",
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			adminErr := admin.NewError(admin.ErrorBadRequestType, "webhook url is invalid")
			adminErr.Message = "webhook url is invalid"
			body := []byte(`{"name": "metadata", "kind": "ENRICHING"}`)
			return test{
				ctx:        ctx,
				body:       body,
				err:        adminErr,
				statusCode: 400,
			}
		},
		"fail/relative-url": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Name: "provName",
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			adminErr := admin.NewError(admin.ErrorBadRequestType, "webhook url is invalid")
			adminErr.Message = "webhook url is invalid"
			body := []byte(`{"name": "metadata", "url": "example.com/path", "kind": "ENRICHING"}`)
			return test{
				ctx:        ctx,
				body:       body,
				err:        adminErr,
				statusCode: 400,
			}
		},
		"fail/http-url": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Name: "provName",
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			adminErr := admin.NewError(admin.ErrorBadRequestType, "webhook url must use https")
			adminErr.Message = "webhook url must use https"
			body := []byte(`{"name": "metadata", "url": "http://example.com", "kind": "ENRICHING"}`)
			return test{
				ctx:        ctx,
				body:       body,
				err:        adminErr,
				statusCode: 400,
			}
		},
		"fail/basic-auth-in-url": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Name: "provName",
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			adminErr := admin.NewError(admin.ErrorBadRequestType, "webhook url may not contain username or password")
			adminErr.Message = "webhook url may not contain username or password"
			body := []byte(`
			{
				"name": "metadata",
				"url": "https://user:pass@example.com",
				"kind": "ENRICHING"
			}`)
			return test{
				ctx:        ctx,
				body:       body,
				err:        adminErr,
				statusCode: 400,
			}
		},
		"fail/secret-in-request": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Name: "provName",
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			adminErr := admin.NewError(admin.ErrorBadRequestType, "webhook secret must not be set")
			adminErr.Message = "webhook secret must not be set"
			body := []byte(`
			{
				"name": "metadata",
				"url": "https://example.com",
				"kind": "ENRICHING",
				"secret": "secret"
			}`)
			return test{
				ctx:        ctx,
				body:       body,
				err:        adminErr,
				statusCode: 400,
			}
		},
		"fail/auth.UpdateProvisioner-error": func(t *testing.T) test {
			adm := &linkedca.Admin{
				Subject: "step",
			}
			prov := &linkedca.Provisioner{
				Name: "provName",
			}
			ctx := linkedca.NewContextWithAdmin(context.Background(), adm)
			ctx = linkedca.NewContextWithProvisioner(ctx, prov)
			adminErr := admin.NewError(admin.ErrorServerInternalType, "error creating provisioner webhook: force")
			adminErr.Message = "error creating provisioner webhook: force"
			body := []byte(`{"name": "metadata", "url": "https://example.com", "kind": "ENRICHING"}`)
			return test{
				ctx: ctx,
				auth: &mockAdminAuthority{
					MockUpdateProvisioner: func(ctx context.Context, nu *linkedca.Provisioner) error {
						return &authority.PolicyError{
							Typ: authority.StoreFailure,
							Err: errors.New("force"),
						}
					},
				},
				body:       body,
				err:        adminErr,
				statusCode: 500,
			}
		},
		"ok": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Name: "provName",
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			body := []byte(`{"name": "metadata", "url": "https://example.com", "kind": "ENRICHING", "certType": "X509"}`)
			return test{
				ctx: ctx,
				auth: &mockAdminAuthority{
					MockUpdateProvisioner: func(ctx context.Context, nu *linkedca.Provisioner) error {
						assert.Equal(t, linkedca.Webhook_X509, nu.Webhooks[0].CertType)
						return nil
					},
				},
				body: body,
				response: &linkedca.Webhook{
					Name:     "metadata",
					Url:      "https://example.com",
					Kind:     linkedca.Webhook_ENRICHING,
					CertType: linkedca.Webhook_X509,
				},
				statusCode: 201,
			}
		},
	}
	for name, prep := range tests {
		tc := prep(t)
		t.Run(name, func(t *testing.T) {
			mockMustAuthority(t, tc.auth)
			ctx := admin.NewContext(tc.ctx, &admin.MockDB{})
			war := NewWebhookAdminResponder()

			req := httptest.NewRequest("POST", "/foo", io.NopCloser(bytes.NewBuffer(tc.body)))
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()

			war.CreateProvisionerWebhook(w, req)
			res := w.Result()

			assert.Equal(t, tc.statusCode, res.StatusCode)

			if res.StatusCode >= 400 {

				body, err := io.ReadAll(res.Body)
				res.Body.Close()
				assert.NoError(t, err)

				ae := testAdminError{}
				assert.NoError(t, json.Unmarshal(bytes.TrimSpace(body), &ae))

				assert.Equal(t, tc.err.Type, ae.Type)
				assert.Equal(t, tc.err.StatusCode(), res.StatusCode)
				assert.Equal(t, tc.err.Detail, ae.Detail)
				assert.Equal(t, []string{"application/json"}, res.Header["Content-Type"])

				// when the error message starts with "proto", we expect it to have
				// a syntax error (in the tests). If the message doesn't start with "proto",
				// we expect a full string match.
				if strings.HasPrefix(tc.err.Message, "proto:") {
					assert.True(t, strings.Contains(ae.Message, "syntax error"))
				} else {
					assert.Equal(t, tc.err.Message, ae.Message)
				}

				return
			}

			resp := &linkedca.Webhook{}
			body, err := io.ReadAll(res.Body)
			assert.NoError(t, err)
			assert.NoError(t, protojson.Unmarshal(body, resp))

			assertEqualWebhook(t, tc.response, resp)
			assert.NotEmpty(t, resp.Secret)
			assert.NotEmpty(t, resp.Id)
		})
	}
}

func TestWebhookAdminResponder_DeleteProvisionerWebhook(t *testing.T) {
	type test struct {
		auth                adminAuthority
		err                 *admin.Error
		statusCode          int
		provisionerWebhooks []*linkedca.Webhook
		webhookName         string
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/auth.UpdateProvisioner-error": func(t *testing.T) test {
			adminErr := admin.NewError(admin.ErrorServerInternalType, "error deleting provisioner webhook: force")
			adminErr.Message = "error deleting provisioner webhook: force"
			return test{
				err: adminErr,
				auth: &mockAdminAuthority{
					MockUpdateProvisioner: func(ctx context.Context, nu *linkedca.Provisioner) error {
						return &authority.PolicyError{
							Typ: authority.StoreFailure,
							Err: errors.New("force"),
						}
					},
				},
				statusCode:  500,
				webhookName: "my-webhook",
				provisionerWebhooks: []*linkedca.Webhook{
					{Name: "my-webhook", Url: "https://example.com", Kind: linkedca.Webhook_ENRICHING},
				},
			}
		},
		"ok/not-found": func(t *testing.T) test {
			return test{
				statusCode:          200,
				webhookName:         "no-exists",
				provisionerWebhooks: nil,
			}
		},
		"ok": func(t *testing.T) test {
			return test{
				statusCode:  200,
				webhookName: "exists",
				auth: &mockAdminAuthority{
					MockUpdateProvisioner: func(ctx context.Context, nu *linkedca.Provisioner) error {
						assert.Equal(t, nu.Webhooks, []*linkedca.Webhook{
							{Name: "my-2nd-webhook", Url: "https://example.com", Kind: linkedca.Webhook_ENRICHING},
						})
						return nil
					},
				},
				provisionerWebhooks: []*linkedca.Webhook{
					{Name: "exists", Url: "https.example.com", Kind: linkedca.Webhook_ENRICHING},
					{Name: "my-2nd-webhook", Url: "https://example.com", Kind: linkedca.Webhook_ENRICHING},
				},
			}
		},
	}
	for name, prep := range tests {
		tc := prep(t)
		t.Run(name, func(t *testing.T) {
			mockMustAuthority(t, tc.auth)

			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("webhookName", tc.webhookName)
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			prov := &linkedca.Provisioner{
				Name:     "provName",
				Webhooks: tc.provisionerWebhooks,
			}
			ctx = linkedca.NewContextWithProvisioner(ctx, prov)
			ctx = admin.NewContext(ctx, &admin.MockDB{})
			req := httptest.NewRequest("DELETE", "/foo", nil).WithContext(ctx)

			war := NewWebhookAdminResponder()

			w := httptest.NewRecorder()

			war.DeleteProvisionerWebhook(w, req)
			res := w.Result()

			assert.Equal(t, tc.statusCode, res.StatusCode)

			if res.StatusCode >= 400 {

				body, err := io.ReadAll(res.Body)
				res.Body.Close()
				assert.NoError(t, err)

				ae := testAdminError{}
				assert.NoError(t, json.Unmarshal(bytes.TrimSpace(body), &ae))

				assert.Equal(t, tc.err.Type, ae.Type)
				assert.Equal(t, tc.err.StatusCode(), res.StatusCode)
				assert.Equal(t, tc.err.Detail, ae.Detail)
				assert.Equal(t, []string{"application/json"}, res.Header["Content-Type"])

				// when the error message starts with "proto", we expect it to have
				// a syntax error (in the tests). If the message doesn't start with "proto",
				// we expect a full string match.
				if strings.HasPrefix(tc.err.Message, "proto:") {
					assert.True(t, strings.Contains(ae.Message, "syntax error"))
				} else {
					assert.Equal(t, tc.err.Message, ae.Message)
				}

				return
			}

			body, err := io.ReadAll(res.Body)
			assert.NoError(t, err)
			res.Body.Close()
			response := DeleteResponse{}
			assert.NoError(t, json.Unmarshal(bytes.TrimSpace(body), &response))
			assert.Equal(t, "ok", response.Status)
			assert.Equal(t, []string{"application/json"}, res.Header["Content-Type"])
		})
	}
}

func TestWebhookAdminResponder_UpdateProvisionerWebhook(t *testing.T) {
	type test struct {
		auth       adminAuthority
		adminDB    admin.DB
		body       []byte
		ctx        context.Context
		err        *admin.Error
		response   *linkedca.Webhook
		statusCode int
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/not-found": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Name:     "provName",
				Webhooks: []*linkedca.Webhook{{Name: "exists", Url: "https://example.com", Kind: linkedca.Webhook_ENRICHING}},
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			err := admin.NewError(admin.ErrorNotFoundType, `provisioner "provName" has no webhook with the name "no-exists"`)
			err.Message = `provisioner "provName" has no webhook with the name "no-exists"`
			body := []byte(`
			{
				"name": "no-exists",
				"url": "https://example.com",
				"kind": "ENRICHING"
			}`)
			return test{
				ctx:        ctx,
				adminDB:    &admin.MockDB{},
				body:       body,
				err:        err,
				statusCode: 404,
			}
		},
		"fail/read.ProtoJSON": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Name:     "provName",
				Webhooks: []*linkedca.Webhook{{Name: "my-webhook", Url: "https://example.com", Kind: linkedca.Webhook_ENRICHING}},
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			adminErr := admin.NewError(admin.ErrorBadRequestType, "proto: syntax error (line 1:2): invalid value ?")
			adminErr.Message = "proto: syntax error (line 1:2): invalid value ?"
			body := []byte("{?}")
			return test{
				ctx:        ctx,
				adminDB:    &admin.MockDB{},
				body:       body,
				err:        adminErr,
				statusCode: 400,
			}
		},
		"fail/missing-name": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Name:     "provName",
				Webhooks: []*linkedca.Webhook{{Name: "my-webhook", Url: "https://example.com", Kind: linkedca.Webhook_ENRICHING}},
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			adminErr := admin.NewError(admin.ErrorBadRequestType, "webhook name is required")
			adminErr.Message = "webhook name is required"
			body := []byte(`{"url": "https://example.com", "kind": "ENRICHING"}`)
			return test{
				ctx:        ctx,
				adminDB:    &admin.MockDB{},
				body:       body,
				err:        adminErr,
				statusCode: 400,
			}
		},
		"fail/missing-url": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Name:     "provName",
				Webhooks: []*linkedca.Webhook{{Name: "my-webhook", Url: "https://example.com", Kind: linkedca.Webhook_ENRICHING}},
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			adminErr := admin.NewError(admin.ErrorBadRequestType, "webhook url is invalid")
			adminErr.Message = "webhook url is invalid"
			body := []byte(`{"name": "metadata", "kind": "ENRICHING"}`)
			return test{
				ctx:        ctx,
				adminDB:    &admin.MockDB{},
				body:       body,
				err:        adminErr,
				statusCode: 400,
			}
		},
		"fail/relative-url": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Name:     "provName",
				Webhooks: []*linkedca.Webhook{{Name: "my-webhook", Url: "https://example.com", Kind: linkedca.Webhook_ENRICHING}},
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			adminErr := admin.NewError(admin.ErrorBadRequestType, "webhook url is invalid")
			adminErr.Message = "webhook url is invalid"
			body := []byte(`{"name": "metadata", "url": "example.com/path", "kind": "ENRICHING"}`)
			return test{
				ctx:        ctx,
				adminDB:    &admin.MockDB{},
				body:       body,
				err:        adminErr,
				statusCode: 400,
			}
		},
		"fail/http-url": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Name:     "provName",
				Webhooks: []*linkedca.Webhook{{Name: "my-webhook", Url: "https://example.com", Kind: linkedca.Webhook_ENRICHING}},
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			adminErr := admin.NewError(admin.ErrorBadRequestType, "webhook url must use https")
			adminErr.Message = "webhook url must use https"
			body := []byte(`{"name": "metadata", "url": "http://example.com", "kind": "ENRICHING"}`)
			return test{
				ctx:        ctx,
				adminDB:    &admin.MockDB{},
				body:       body,
				err:        adminErr,
				statusCode: 400,
			}
		},
		"fail/basic-auth-in-url": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Name:     "provName",
				Webhooks: []*linkedca.Webhook{{Name: "my-webhook", Url: "https://example.com", Kind: linkedca.Webhook_ENRICHING}},
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			adminErr := admin.NewError(admin.ErrorBadRequestType, "webhook url may not contain username or password")
			adminErr.Message = "webhook url may not contain username or password"
			body := []byte(`
			{
				"name": "my-webhook",
				"url": "https://user:pass@example.com",
				"kind": "ENRICHING"
			}`)
			return test{
				ctx:        ctx,
				adminDB:    &admin.MockDB{},
				body:       body,
				err:        adminErr,
				statusCode: 400,
			}
		},
		"fail/different-secret-in-request": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Name:     "provName",
				Webhooks: []*linkedca.Webhook{{Name: "my-webhook", Url: "https://example.com", Kind: linkedca.Webhook_ENRICHING, Secret: "c2VjcmV0"}},
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			adminErr := admin.NewError(admin.ErrorBadRequestType, "webhook secret cannot be updated")
			adminErr.Message = "webhook secret cannot be updated"
			body := []byte(`
			{
				"name": "my-webhook",
				"url": "https://example.com",
				"kind": "ENRICHING",
				"secret": "secret"
			}`)
			return test{
				ctx:        ctx,
				body:       body,
				err:        adminErr,
				statusCode: 400,
			}
		},
		"fail/auth.UpdateProvisioner-error": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Name:     "provName",
				Webhooks: []*linkedca.Webhook{{Name: "my-webhook", Url: "https://example.com", Kind: linkedca.Webhook_ENRICHING}},
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			adminErr := admin.NewError(admin.ErrorServerInternalType, "error updating provisioner webhook: force")
			adminErr.Message = "error updating provisioner webhook: force"
			body := []byte(`{"name": "my-webhook", "url": "https://example.com", "kind": "ENRICHING"}`)
			return test{
				ctx:     ctx,
				adminDB: &admin.MockDB{},
				auth: &mockAdminAuthority{
					MockUpdateProvisioner: func(ctx context.Context, nu *linkedca.Provisioner) error {
						return &authority.PolicyError{
							Typ: authority.StoreFailure,
							Err: errors.New("force"),
						}
					},
				},
				body:       body,
				err:        adminErr,
				statusCode: 500,
			}
		},
		"ok": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Name:     "provName",
				Webhooks: []*linkedca.Webhook{{Name: "my-webhook", Url: "https://example.com", Kind: linkedca.Webhook_ENRICHING}},
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			body := []byte(`{"name": "my-webhook", "url": "https://example.com", "kind": "ENRICHING"}`)
			return test{
				ctx:     ctx,
				adminDB: &admin.MockDB{},
				auth: &mockAdminAuthority{
					MockUpdateProvisioner: func(ctx context.Context, nu *linkedca.Provisioner) error {
						return nil
					},
				},
				body: body,
				response: &linkedca.Webhook{
					Name: "my-webhook",
					Url:  "https://example.com",
					Kind: linkedca.Webhook_ENRICHING,
				},
				statusCode: 201,
			}
		},
	}
	for name, prep := range tests {
		tc := prep(t)
		t.Run(name, func(t *testing.T) {
			mockMustAuthority(t, tc.auth)
			ctx := admin.NewContext(tc.ctx, tc.adminDB)
			war := NewWebhookAdminResponder()

			req := httptest.NewRequest("PUT", "/foo", io.NopCloser(bytes.NewBuffer(tc.body)))
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()

			war.UpdateProvisionerWebhook(w, req)
			res := w.Result()

			assert.Equal(t, tc.statusCode, res.StatusCode)

			if res.StatusCode >= 400 {

				body, err := io.ReadAll(res.Body)
				res.Body.Close()
				assert.NoError(t, err)

				ae := testAdminError{}
				assert.NoError(t, json.Unmarshal(bytes.TrimSpace(body), &ae))

				assert.Equal(t, tc.err.Type, ae.Type)
				assert.Equal(t, tc.err.StatusCode(), res.StatusCode)
				assert.Equal(t, tc.err.Detail, ae.Detail)
				assert.Equal(t, []string{"application/json"}, res.Header["Content-Type"])

				// when the error message starts with "proto", we expect it to have
				// a syntax error (in the tests). If the message doesn't start with "proto",
				// we expect a full string match.
				if strings.HasPrefix(tc.err.Message, "proto:") {
					assert.True(t, strings.Contains(ae.Message, "syntax error"))
				} else {
					assert.Equal(t, tc.err.Message, ae.Message)
				}

				return
			}

			resp := &linkedca.Webhook{}
			body, err := io.ReadAll(res.Body)
			assert.NoError(t, err)
			assert.NoError(t, protojson.Unmarshal(body, resp))

			assertEqualWebhook(t, tc.response, resp)
		})
	}
}
