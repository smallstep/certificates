package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/authority/admin"
	"go.step.sm/linkedca"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestHandler_requireAPIEnabled(t *testing.T) {
	type test struct {
		ctx        context.Context
		auth       adminAuthority
		next       nextHTTP
		err        *admin.Error
		statusCode int
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/auth.IsAdminAPIEnabled": func(t *testing.T) test {
			return test{
				ctx: context.Background(),
				auth: &mockAdminAuthority{
					MockIsAdminAPIEnabled: func() bool {
						return false
					},
				},
				err: &admin.Error{
					Type:    admin.ErrorNotImplementedType.String(),
					Status:  501,
					Detail:  "not implemented",
					Message: "administration API not enabled",
				},
				statusCode: 501,
			}
		},
		"ok": func(t *testing.T) test {
			auth := &mockAdminAuthority{
				MockIsAdminAPIEnabled: func() bool {
					return true
				},
			}
			next := func(w http.ResponseWriter, r *http.Request) {
				w.Write(nil) // mock response with status 200
			}
			return test{
				ctx:        context.Background(),
				auth:       auth,
				next:       next,
				statusCode: 200,
			}
		},
	}
	for name, prep := range tests {
		tc := prep(t)
		t.Run(name, func(t *testing.T) {
			h := &Handler{
				auth: tc.auth,
			}
			req := httptest.NewRequest("GET", "/foo", nil) // chi routing is prepared in test setup
			req = req.WithContext(tc.ctx)
			w := httptest.NewRecorder()
			h.requireAPIEnabled(tc.next)(w, req)
			res := w.Result()

			assert.Equals(t, tc.statusCode, res.StatusCode)

			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			assert.FatalError(t, err)

			if res.StatusCode >= 400 {
				err := admin.Error{}
				assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &err))

				assert.Equals(t, tc.err.Type, err.Type)
				assert.Equals(t, tc.err.Message, err.Message)
				assert.Equals(t, tc.err.StatusCode(), res.StatusCode)
				assert.Equals(t, tc.err.Detail, err.Detail)
				assert.Equals(t, []string{"application/json"}, res.Header["Content-Type"])
				return
			}

			// nothing to test when the requireAPIEnabled middleware succeeds, currently

		})
	}
}

func TestHandler_extractAuthorizeTokenAdmin(t *testing.T) {
	type test struct {
		ctx        context.Context
		auth       adminAuthority
		req        *http.Request
		next       nextHTTP
		err        *admin.Error
		statusCode int
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/missing-authorization-token": func(t *testing.T) test {
			req := httptest.NewRequest("GET", "/foo", nil)
			req.Header["Authorization"] = []string{""}
			return test{
				ctx:        context.Background(),
				req:        req,
				statusCode: 401,
				err: &admin.Error{
					Type:    admin.ErrorUnauthorizedType.String(),
					Status:  401,
					Detail:  "unauthorized",
					Message: "missing authorization header token",
				},
			}
		},
		"fail/auth.AuthorizeAdminToken": func(t *testing.T) test {
			req := httptest.NewRequest("GET", "/foo", nil)
			req.Header["Authorization"] = []string{"token"}
			auth := &mockAdminAuthority{
				MockAuthorizeAdminToken: func(r *http.Request, token string) (*linkedca.Admin, error) {
					assert.Equals(t, "token", token)
					return nil, admin.NewError(
						admin.ErrorUnauthorizedType,
						"not authorized",
					)
				},
			}
			return test{
				ctx:        context.Background(),
				auth:       auth,
				req:        req,
				statusCode: 401,
				err: &admin.Error{
					Type:    admin.ErrorUnauthorizedType.String(),
					Status:  401,
					Detail:  "unauthorized",
					Message: "not authorized",
				},
			}
		},
		"ok": func(t *testing.T) test {
			req := httptest.NewRequest("GET", "/foo", nil)
			req.Header["Authorization"] = []string{"token"}
			createdAt := time.Now()
			var deletedAt time.Time
			admin := &linkedca.Admin{
				Id:            "adminID",
				AuthorityId:   "authorityID",
				Subject:       "admin",
				ProvisionerId: "provID",
				Type:          linkedca.Admin_SUPER_ADMIN,
				CreatedAt:     timestamppb.New(createdAt),
				DeletedAt:     timestamppb.New(deletedAt),
			}
			auth := &mockAdminAuthority{
				MockAuthorizeAdminToken: func(r *http.Request, token string) (*linkedca.Admin, error) {
					assert.Equals(t, "token", token)
					return admin, nil
				},
			}
			next := func(w http.ResponseWriter, r *http.Request) {
				ctx := r.Context()
				a := ctx.Value(adminContextKey) // verifying that the context now has a linkedca.Admin
				adm, ok := a.(*linkedca.Admin)
				if !ok {
					t.Errorf("expected *linkedca.Admin; got %T", a)
					return
				}
				opts := []cmp.Option{cmpopts.IgnoreUnexported(linkedca.Admin{}, timestamppb.Timestamp{})}
				if !cmp.Equal(admin, adm, opts...) {
					t.Errorf("linkedca.Admin diff =\n%s", cmp.Diff(admin, adm, opts...))
				}
				w.Write(nil) // mock response with status 200
			}
			return test{
				ctx:        context.Background(),
				auth:       auth,
				req:        req,
				next:       next,
				statusCode: 200,
				err:        nil,
			}
		},
	}
	for name, prep := range tests {
		tc := prep(t)
		t.Run(name, func(t *testing.T) {
			h := &Handler{
				auth: tc.auth,
			}

			req := tc.req.WithContext(tc.ctx)
			w := httptest.NewRecorder()
			h.extractAuthorizeTokenAdmin(tc.next)(w, req)
			res := w.Result()

			assert.Equals(t, tc.statusCode, res.StatusCode)

			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			assert.FatalError(t, err)

			if res.StatusCode >= 400 {
				err := admin.Error{}
				assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &err))

				assert.Equals(t, tc.err.Type, err.Type)
				assert.Equals(t, tc.err.Message, err.Message)
				assert.Equals(t, tc.err.StatusCode(), res.StatusCode)
				assert.Equals(t, tc.err.Detail, err.Detail)
				assert.Equals(t, []string{"application/json"}, res.Header["Content-Type"])
				return
			}
		})
	}
}
