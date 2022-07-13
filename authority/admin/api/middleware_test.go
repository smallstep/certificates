package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"google.golang.org/protobuf/types/known/timestamppb"

	"go.step.sm/linkedca"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/authority/admin/db/nosql"
	"github.com/smallstep/certificates/authority/provisioner"
)

func TestHandler_requireAPIEnabled(t *testing.T) {
	type test struct {
		ctx        context.Context
		auth       adminAuthority
		next       http.HandlerFunc
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
			mockMustAuthority(t, tc.auth)
			req := httptest.NewRequest("GET", "/foo", nil) // chi routing is prepared in test setup
			req = req.WithContext(tc.ctx)
			w := httptest.NewRecorder()
			requireAPIEnabled(tc.next)(w, req)
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
		next       http.HandlerFunc
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
			adm := &linkedca.Admin{
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
					return adm, nil
				},
			}
			next := func(w http.ResponseWriter, r *http.Request) {
				ctx := r.Context()
				adm := linkedca.MustAdminFromContext(ctx) // verifying that the context now has a linkedca.Admin
				opts := []cmp.Option{cmpopts.IgnoreUnexported(linkedca.Admin{}, timestamppb.Timestamp{})}
				if !cmp.Equal(adm, adm, opts...) {
					t.Errorf("linkedca.Admin diff =\n%s", cmp.Diff(adm, adm, opts...))
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
			mockMustAuthority(t, tc.auth)
			req := tc.req.WithContext(tc.ctx)
			w := httptest.NewRecorder()
			extractAuthorizeTokenAdmin(tc.next)(w, req)
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

func TestHandler_loadProvisionerByName(t *testing.T) {
	type test struct {
		adminDB    admin.DB
		auth       adminAuthority
		ctx        context.Context
		next       http.HandlerFunc
		err        *admin.Error
		statusCode int
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/auth.LoadProvisionerByName": func(t *testing.T) test {
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("provisionerName", "provName")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			auth := &mockAdminAuthority{
				MockLoadProvisionerByName: func(name string) (provisioner.Interface, error) {
					assert.Equals(t, "provName", name)
					return nil, errors.New("force")
				},
			}
			err := admin.WrapErrorISE(errors.New("force"), "error loading provisioner provName")
			err.Message = "error loading provisioner provName: force"
			return test{
				ctx:        ctx,
				auth:       auth,
				adminDB:    &admin.MockDB{},
				statusCode: 500,
				err:        err,
			}
		},
		"fail/db.GetProvisioner": func(t *testing.T) test {
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("provisionerName", "provName")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			auth := &mockAdminAuthority{
				MockLoadProvisionerByName: func(name string) (provisioner.Interface, error) {
					assert.Equals(t, "provName", name)
					return &provisioner.MockProvisioner{
						MgetID: func() string {
							return "provID"
						},
					}, nil
				},
			}
			db := &admin.MockDB{
				MockGetProvisioner: func(ctx context.Context, id string) (*linkedca.Provisioner, error) {
					assert.Equals(t, "provID", id)
					return nil, errors.New("force")
				},
			}
			err := admin.WrapErrorISE(errors.New("force"), "error retrieving provisioner provName")
			err.Message = "error retrieving provisioner provName: force"
			return test{
				ctx:        ctx,
				auth:       auth,
				adminDB:    db,
				statusCode: 500,
				err:        err,
			}
		},
		"ok": func(t *testing.T) test {
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("provisionerName", "provName")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			auth := &mockAdminAuthority{
				MockLoadProvisionerByName: func(name string) (provisioner.Interface, error) {
					assert.Equals(t, "provName", name)
					return &provisioner.MockProvisioner{
						MgetID: func() string {
							return "provID"
						},
					}, nil
				},
			}
			db := &admin.MockDB{
				MockGetProvisioner: func(ctx context.Context, id string) (*linkedca.Provisioner, error) {
					assert.Equals(t, "provID", id)
					return &linkedca.Provisioner{
						Id:   "provID",
						Name: "provName",
					}, nil
				},
			}
			return test{
				ctx:        ctx,
				auth:       auth,
				adminDB:    db,
				statusCode: 200,
				next: func(w http.ResponseWriter, r *http.Request) {
					prov := linkedca.MustProvisionerFromContext(r.Context())
					assert.NotNil(t, prov)
					assert.Equals(t, "provID", prov.GetId())
					assert.Equals(t, "provName", prov.GetName())
					w.Write(nil) // mock response with status 200
				},
			}
		},
	}
	for name, prep := range tests {
		tc := prep(t)
		t.Run(name, func(t *testing.T) {
			mockMustAuthority(t, tc.auth)
			ctx := admin.NewContext(tc.ctx, tc.adminDB)
			req := httptest.NewRequest("GET", "/foo", nil) // chi routing is prepared in test setup
			req = req.WithContext(ctx)

			w := httptest.NewRecorder()
			loadProvisionerByName(tc.next)(w, req)
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

func TestHandler_checkAction(t *testing.T) {
	type test struct {
		adminDB               admin.DB
		next                  http.HandlerFunc
		supportedInStandalone bool
		err                   *admin.Error
		statusCode            int
	}
	var tests = map[string]func(t *testing.T) test{
		"standalone-nosql-supported": func(t *testing.T) test {
			return test{
				supportedInStandalone: true,
				adminDB:               &nosql.DB{},
				next: func(w http.ResponseWriter, r *http.Request) {
					w.Write(nil) // mock response with status 200
				},
				statusCode: 200,
			}
		},
		"standalone-nosql-not-supported": func(t *testing.T) test {
			err := admin.NewError(admin.ErrorNotImplementedType, "operation not supported in standalone mode")
			err.Message = "operation not supported in standalone mode"
			return test{
				supportedInStandalone: false,
				adminDB:               &nosql.DB{},
				statusCode:            501,
				err:                   err,
			}
		},
		"standalone-no-nosql-not-supported": func(t *testing.T) test {
			err := admin.NewError(admin.ErrorNotImplementedType, "operation not supported")
			err.Message = "operation not supported"
			return test{
				supportedInStandalone: false,
				adminDB:               &admin.MockDB{},
				next: func(w http.ResponseWriter, r *http.Request) {
					w.Write(nil) // mock response with status 200
				},
				statusCode: 200,
				err:        err,
			}
		},
	}
	for name, prep := range tests {
		tc := prep(t)
		t.Run(name, func(t *testing.T) {
			ctx := admin.NewContext(context.Background(), tc.adminDB)
			req := httptest.NewRequest("GET", "/foo", nil).WithContext(ctx)
			w := httptest.NewRecorder()
			checkAction(tc.next, tc.supportedInStandalone)(w, req)
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

func TestHandler_loadExternalAccountKey(t *testing.T) {
	type test struct {
		ctx        context.Context
		acmeDB     acme.DB
		next       http.HandlerFunc
		err        *admin.Error
		statusCode int
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/keyID-not-found-error": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Id: "provID",
			}
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("keyID", "key")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			ctx = linkedca.NewContextWithProvisioner(ctx, prov)
			err := admin.NewError(admin.ErrorNotFoundType, "ACME External Account Key not found")
			err.Message = "ACME External Account Key not found"
			return test{
				ctx: ctx,
				acmeDB: &acme.MockDB{
					MockGetExternalAccountKey: func(ctx context.Context, provisionerID, keyID string) (*acme.ExternalAccountKey, error) {
						assert.Equals(t, "provID", provisionerID)
						assert.Equals(t, "key", keyID)
						return nil, acme.ErrNotFound
					},
				},
				err:        err,
				statusCode: 404,
			}
		},
		"fail/keyID-error": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Id: "provID",
			}
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("keyID", "key")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			ctx = linkedca.NewContextWithProvisioner(ctx, prov)
			err := admin.WrapErrorISE(errors.New("force"), "error retrieving ACME External Account Key")
			err.Message = "error retrieving ACME External Account Key: force"
			return test{
				ctx: ctx,
				acmeDB: &acme.MockDB{
					MockGetExternalAccountKey: func(ctx context.Context, provisionerID, keyID string) (*acme.ExternalAccountKey, error) {
						assert.Equals(t, "provID", provisionerID)
						assert.Equals(t, "key", keyID)
						return nil, errors.New("force")
					},
				},
				err:        err,
				statusCode: 500,
			}
		},
		"fail/reference-not-found-error": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Id: "provID",
			}
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("reference", "ref")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			ctx = linkedca.NewContextWithProvisioner(ctx, prov)
			err := admin.NewError(admin.ErrorNotFoundType, "ACME External Account Key not found")
			err.Message = "ACME External Account Key not found"
			return test{
				ctx: ctx,
				acmeDB: &acme.MockDB{
					MockGetExternalAccountKeyByReference: func(ctx context.Context, provisionerID, reference string) (*acme.ExternalAccountKey, error) {
						assert.Equals(t, "provID", provisionerID)
						assert.Equals(t, "ref", reference)
						return nil, acme.ErrNotFound
					},
				},
				err:        err,
				statusCode: 404,
			}
		},
		"fail/reference-error": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Id: "provID",
			}
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("reference", "ref")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			ctx = linkedca.NewContextWithProvisioner(ctx, prov)
			err := admin.WrapErrorISE(errors.New("force"), "error retrieving ACME External Account Key")
			err.Message = "error retrieving ACME External Account Key: force"
			return test{
				ctx: ctx,
				acmeDB: &acme.MockDB{
					MockGetExternalAccountKeyByReference: func(ctx context.Context, provisionerID, reference string) (*acme.ExternalAccountKey, error) {
						assert.Equals(t, "provID", provisionerID)
						assert.Equals(t, "ref", reference)
						return nil, errors.New("force")
					},
				},
				err:        err,
				statusCode: 500,
			}
		},
		"fail/no-key": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Id: "provID",
			}
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("reference", "ref")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			ctx = linkedca.NewContextWithProvisioner(ctx, prov)
			err := admin.NewError(admin.ErrorNotFoundType, "ACME External Account Key not found")
			err.Message = "ACME External Account Key not found"
			return test{
				ctx: ctx,
				acmeDB: &acme.MockDB{
					MockGetExternalAccountKeyByReference: func(ctx context.Context, provisionerID, reference string) (*acme.ExternalAccountKey, error) {
						assert.Equals(t, "provID", provisionerID)
						assert.Equals(t, "ref", reference)
						return nil, nil
					},
				},
				err:        err,
				statusCode: 404,
			}
		},
		"ok/keyID": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Id: "provID",
			}
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("keyID", "eakID")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			ctx = linkedca.NewContextWithProvisioner(ctx, prov)
			err := admin.NewError(admin.ErrorNotFoundType, "ACME External Account Key not found")
			err.Message = "ACME External Account Key not found"
			createdAt := time.Now().Add(-1 * time.Hour)
			var boundAt time.Time
			eak := &acme.ExternalAccountKey{
				ID:            "eakID",
				ProvisionerID: "provID",
				CreatedAt:     createdAt,
				BoundAt:       boundAt,
			}
			return test{
				ctx: ctx,
				acmeDB: &acme.MockDB{
					MockGetExternalAccountKey: func(ctx context.Context, provisionerID, keyID string) (*acme.ExternalAccountKey, error) {
						assert.Equals(t, "provID", provisionerID)
						assert.Equals(t, "eakID", keyID)
						return eak, nil
					},
				},
				next: func(w http.ResponseWriter, r *http.Request) {
					contextEAK := linkedca.MustExternalAccountKeyFromContext(r.Context())
					assert.NotNil(t, eak)
					exp := &linkedca.EABKey{
						Id:          "eakID",
						Provisioner: "provID",
						CreatedAt:   timestamppb.New(createdAt),
						BoundAt:     timestamppb.New(boundAt),
					}
					assert.Equals(t, exp, contextEAK)
					w.Write(nil) // mock response with status 200
				},
				err:        nil,
				statusCode: 200,
			}
		},
		"ok/reference": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Id: "provID",
			}
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("reference", "ref")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			ctx = linkedca.NewContextWithProvisioner(ctx, prov)
			err := admin.NewError(admin.ErrorNotFoundType, "ACME External Account Key not found")
			err.Message = "ACME External Account Key not found"
			createdAt := time.Now().Add(-1 * time.Hour)
			var boundAt time.Time
			eak := &acme.ExternalAccountKey{
				ID:            "eakID",
				ProvisionerID: "provID",
				Reference:     "ref",
				CreatedAt:     createdAt,
				BoundAt:       boundAt,
			}
			return test{
				ctx: ctx,
				acmeDB: &acme.MockDB{
					MockGetExternalAccountKeyByReference: func(ctx context.Context, provisionerID, reference string) (*acme.ExternalAccountKey, error) {
						assert.Equals(t, "provID", provisionerID)
						assert.Equals(t, "ref", reference)
						return eak, nil
					},
				},
				next: func(w http.ResponseWriter, r *http.Request) {
					contextEAK := linkedca.MustExternalAccountKeyFromContext(r.Context())
					assert.NotNil(t, eak)
					exp := &linkedca.EABKey{
						Id:          "eakID",
						Provisioner: "provID",
						Reference:   "ref",
						CreatedAt:   timestamppb.New(createdAt),
						BoundAt:     timestamppb.New(boundAt),
					}
					assert.Equals(t, exp, contextEAK)
					w.Write(nil) // mock response with status 200
				},
				err:        nil,
				statusCode: 200,
			}
		},
	}

	for name, prep := range tests {
		tc := prep(t)
		t.Run(name, func(t *testing.T) {
			ctx := acme.NewDatabaseContext(tc.ctx, tc.acmeDB)
			req := httptest.NewRequest("GET", "/foo", nil)
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()
			loadExternalAccountKey(tc.next)(w, req)
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
