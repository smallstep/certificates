package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/smallstep/assert"
	"go.step.sm/linkedca"

	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/authority/provisioner"
)

func TestHandler_GetProvisioner(t *testing.T) {
	type test struct {
		ctx        context.Context
		auth       adminAuthority
		adminDB    admin.DB
		req        *http.Request
		statusCode int
		err        *admin.Error
		prov       *linkedca.Provisioner
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/auth.LoadProvisionerByID": func(t *testing.T) test {
			req := httptest.NewRequest("GET", "/foo?id=provID", nil)
			chiCtx := chi.NewRouteContext()
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			auth := &mockAdminAuthority{
				MockLoadProvisionerByID: func(id string) (provisioner.Interface, error) {
					assert.Equals(t, "provID", id)
					return nil, errors.New("force")
				},
			}
			return test{
				ctx:        ctx,
				req:        req,
				auth:       auth,
				adminDB:    &admin.MockDB{},
				statusCode: 500,
				err: &admin.Error{
					Type:    admin.ErrorServerInternalType.String(),
					Status:  500,
					Detail:  "the server experienced an internal error",
					Message: "error loading provisioner provID: force",
				},
			}
		},
		"fail/auth.LoadProvisionerByName": func(t *testing.T) test {
			req := httptest.NewRequest("GET", "/foo", nil)
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("name", "provName")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			auth := &mockAdminAuthority{
				MockLoadProvisionerByName: func(name string) (provisioner.Interface, error) {
					assert.Equals(t, "provName", name)
					return nil, errors.New("force")
				},
			}
			return test{
				ctx:        ctx,
				req:        req,
				auth:       auth,
				adminDB:    &admin.MockDB{},
				statusCode: 500,
				err: &admin.Error{
					Type:    admin.ErrorServerInternalType.String(),
					Status:  500,
					Detail:  "the server experienced an internal error",
					Message: "error loading provisioner provName: force",
				},
			}
		},
		"fail/db.GetProvisioner": func(t *testing.T) test {
			req := httptest.NewRequest("GET", "/foo", nil)
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("name", "provName")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			auth := &mockAdminAuthority{
				MockLoadProvisionerByName: func(name string) (provisioner.Interface, error) {
					assert.Equals(t, "provName", name)
					return &provisioner.ACME{
						ID:   "acmeID",
						Name: "provName",
					}, nil
				},
			}
			db := &admin.MockDB{
				MockGetProvisioner: func(ctx context.Context, id string) (*linkedca.Provisioner, error) {
					assert.Equals(t, "acmeID", id)
					return nil, admin.NewErrorISE("error loading provisioner provName: force")
				},
			}
			return test{
				ctx:        ctx,
				req:        req,
				auth:       auth,
				adminDB:    db,
				statusCode: 500,
				err: &admin.Error{
					Type:    admin.ErrorServerInternalType.String(),
					Status:  500,
					Detail:  "the server experienced an internal error",
					Message: "error loading provisioner provName: force",
				},
			}
		},
		"ok": func(t *testing.T) test {
			req := httptest.NewRequest("GET", "/foo", nil)
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("name", "provName")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			auth := &mockAdminAuthority{
				MockLoadProvisionerByName: func(name string) (provisioner.Interface, error) {
					assert.Equals(t, "provName", name)
					return &provisioner.ACME{
						ID:   "acmeID",
						Name: "provName",
					}, nil
				},
			}
			prov := &linkedca.Provisioner{
				Id:   "acmeID",
				Type: linkedca.Provisioner_ACME,
				Name: "provName", // TODO(hs): other fields too?
			}
			db := &admin.MockDB{
				MockGetProvisioner: func(ctx context.Context, id string) (*linkedca.Provisioner, error) {
					assert.Equals(t, "acmeID", id)
					return prov, nil
				},
			}
			return test{
				ctx:        ctx,
				req:        req,
				auth:       auth,
				adminDB:    db,
				statusCode: 200,
				err:        nil,
				prov:       prov,
			}
		},
	}
	for name, prep := range tests {
		tc := prep(t)
		t.Run(name, func(t *testing.T) {
			mockMustAuthority(t, tc.auth)
			ctx := admin.NewContext(tc.ctx, tc.adminDB)
			req := tc.req.WithContext(ctx)
			w := httptest.NewRecorder()
			GetProvisioner(w, req)
			res := w.Result()

			assert.Equals(t, tc.statusCode, res.StatusCode)

			if res.StatusCode >= 400 {

				body, err := io.ReadAll(res.Body)
				res.Body.Close()
				assert.FatalError(t, err)

				adminErr := admin.Error{}
				assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &adminErr))

				assert.Equals(t, tc.err.Type, adminErr.Type)
				assert.Equals(t, tc.err.Message, adminErr.Message)
				assert.Equals(t, tc.err.Detail, adminErr.Detail)
				assert.Equals(t, []string{"application/json"}, res.Header["Content-Type"])
				return
			}

			prov := &linkedca.Provisioner{}
			err := readProtoJSON(res.Body, prov)
			assert.FatalError(t, err)

			assert.Equals(t, []string{"application/json"}, res.Header["Content-Type"])

			opts := []cmp.Option{cmpopts.IgnoreUnexported(linkedca.Provisioner{}, timestamppb.Timestamp{})}
			if !cmp.Equal(tc.prov, prov, opts...) {
				t.Errorf("h.GetProvisioner diff =\n%s", cmp.Diff(tc.prov, prov, opts...))
			}
		})
	}
}

func TestHandler_GetProvisioners(t *testing.T) {
	type test struct {
		ctx        context.Context
		auth       adminAuthority
		req        *http.Request
		statusCode int
		err        *admin.Error
		resp       GetProvisionersResponse
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/parse-cursor": func(t *testing.T) test {
			req := httptest.NewRequest("GET", "/foo?limit=X", nil)
			return test{
				ctx:        context.Background(),
				statusCode: 400,
				req:        req,
				err: &admin.Error{
					Status:  400,
					Type:    admin.ErrorBadRequestType.String(),
					Detail:  "bad request",
					Message: "error parsing cursor and limit from query params: limit 'X' is not an integer: strconv.Atoi: parsing \"X\": invalid syntax",
				},
			}
		},
		"fail/auth.GetProvisioners": func(t *testing.T) test {
			req := httptest.NewRequest("GET", "/foo", nil)
			auth := &mockAdminAuthority{
				MockGetProvisioners: func(cursor string, limit int) (provisioner.List, string, error) {
					assert.Equals(t, "", cursor)
					assert.Equals(t, 0, limit)
					return nil, "", errors.New("force")
				},
			}
			return test{
				ctx:        context.Background(),
				req:        req,
				auth:       auth,
				statusCode: 500,
				err: &admin.Error{
					Type:    "",
					Status:  500,
					Detail:  "",
					Message: "The certificate authority encountered an Internal Server Error. Please see the certificate authority logs for more info.",
				},
			}
		},
		"ok": func(t *testing.T) test {
			req := httptest.NewRequest("GET", "/foo", nil)
			provisioners := provisioner.List{
				&provisioner.OIDC{
					Type: "OIDC",
					Name: "oidcProv",
				},
				&provisioner.ACME{
					Type:       "ACME",
					Name:       "provName",
					ForceCN:    false,
					RequireEAB: false,
				},
			}
			auth := &mockAdminAuthority{
				MockGetProvisioners: func(cursor string, limit int) (provisioner.List, string, error) {
					assert.Equals(t, "", cursor)
					assert.Equals(t, 0, limit)
					return provisioners, "nextCursorValue", nil
				},
			}
			return test{
				ctx:        context.Background(),
				req:        req,
				auth:       auth,
				statusCode: 200,
				err:        nil,
				resp: GetProvisionersResponse{
					Provisioners: provisioners,
					NextCursor:   "nextCursorValue",
				},
			}
		},
	}
	for name, prep := range tests {
		tc := prep(t)
		t.Run(name, func(t *testing.T) {
			mockMustAuthority(t, tc.auth)
			req := tc.req.WithContext(tc.ctx)
			w := httptest.NewRecorder()
			GetProvisioners(w, req)
			res := w.Result()

			assert.Equals(t, tc.statusCode, res.StatusCode)

			if res.StatusCode >= 400 {

				body, err := io.ReadAll(res.Body)
				res.Body.Close()
				assert.FatalError(t, err)

				adminErr := admin.Error{}
				assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &adminErr))

				assert.Equals(t, tc.err.Type, adminErr.Type)
				assert.Equals(t, tc.err.Message, adminErr.Message)
				assert.Equals(t, tc.err.Detail, adminErr.Detail)
				assert.Equals(t, []string{"application/json"}, res.Header["Content-Type"])
				return
			}

			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			assert.FatalError(t, err)

			response := GetProvisionersResponse{}
			assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &response))

			assert.Equals(t, []string{"application/json"}, res.Header["Content-Type"])

			opts := []cmp.Option{cmpopts.IgnoreUnexported(provisioner.ACME{}, provisioner.OIDC{})}
			if !cmp.Equal(tc.resp, response, opts...) {
				t.Errorf("h.GetProvisioners diff =\n%s", cmp.Diff(tc.resp, response, opts...))
			}
		})
	}
}

func TestHandler_CreateProvisioner(t *testing.T) {
	type test struct {
		ctx        context.Context
		auth       adminAuthority
		body       []byte
		statusCode int
		err        *admin.Error
		prov       *linkedca.Provisioner
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/readProtoJSON": func(t *testing.T) test {
			body := []byte("{!?}")
			return test{
				ctx:        context.Background(),
				body:       body,
				statusCode: 400,
				err: &admin.Error{
					Type:    "badRequest",
					Status:  400,
					Detail:  "bad request",
					Message: "proto: syntax error (line 1:2): invalid value !",
				},
			}
		},
		// TODO(hs): ValidateClaims can't be mocked atm
		// "fail/authority.ValidateClaims": func(t *testing.T) test {
		// 	return test{}
		// },
		"fail/validateTemplates": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Id:   "provID",
				Type: linkedca.Provisioner_OIDC,
				Name: "provName",
				X509Template: &linkedca.Template{
					Template: []byte(`{ {{missingFunction "foo"}} }`),
				},
			}
			body, err := protojson.Marshal(prov)
			assert.FatalError(t, err)
			return test{
				ctx:        context.Background(),
				body:       body,
				statusCode: 400,
				err: &admin.Error{
					Type:    "badRequest",
					Status:  400,
					Detail:  "bad request",
					Message: "invalid template: invalid X.509 template: error parsing template: template: template:1: function \"missingFunction\" not defined",
				},
			}
		},
		"fail/auth.StoreProvisioner": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Id:   "provID",
				Type: linkedca.Provisioner_OIDC,
				Name: "provName",
			}
			body, err := protojson.Marshal(prov)
			assert.FatalError(t, err)
			auth := &mockAdminAuthority{
				MockStoreProvisioner: func(ctx context.Context, prov *linkedca.Provisioner) error {
					assert.Equals(t, "provID", prov.Id)
					return errors.New("force")
				},
			}
			return test{
				ctx:        context.Background(),
				body:       body,
				auth:       auth,
				statusCode: 500,
				err: &admin.Error{
					Type:    admin.ErrorServerInternalType.String(),
					Status:  500,
					Detail:  "the server experienced an internal error",
					Message: "error storing provisioner provName: force",
				},
			}
		},
		"ok": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Id:   "provID",
				Type: linkedca.Provisioner_OIDC,
				Name: "provName",
			}
			body, err := protojson.Marshal(prov)
			assert.FatalError(t, err)
			auth := &mockAdminAuthority{
				MockStoreProvisioner: func(ctx context.Context, prov *linkedca.Provisioner) error {
					assert.Equals(t, "provID", prov.Id)
					return nil
				},
			}
			return test{
				ctx:        context.Background(),
				body:       body,
				auth:       auth,
				statusCode: 201,
				err:        nil,
				prov:       prov,
			}
		},
	}
	for name, prep := range tests {
		tc := prep(t)
		t.Run(name, func(t *testing.T) {
			mockMustAuthority(t, tc.auth)
			req := httptest.NewRequest("POST", "/foo", io.NopCloser(bytes.NewBuffer(tc.body)))
			req = req.WithContext(tc.ctx)
			w := httptest.NewRecorder()
			CreateProvisioner(w, req)
			res := w.Result()

			assert.Equals(t, tc.statusCode, res.StatusCode)

			if res.StatusCode >= 400 {

				body, err := io.ReadAll(res.Body)
				res.Body.Close()
				assert.FatalError(t, err)

				adminErr := admin.Error{}
				assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &adminErr))

				assert.Equals(t, tc.err.Type, adminErr.Type)
				assert.Equals(t, tc.err.Detail, adminErr.Detail)
				assert.Equals(t, []string{"application/json"}, res.Header["Content-Type"])

				if strings.HasPrefix(tc.err.Message, "proto:") {
					assert.True(t, strings.Contains(adminErr.Message, "syntax error"))
				} else {
					assert.Equals(t, tc.err.Message, adminErr.Message)
				}

				return
			}

			prov := &linkedca.Provisioner{}
			err := readProtoJSON(res.Body, prov)
			assert.FatalError(t, err)

			assert.Equals(t, []string{"application/json"}, res.Header["Content-Type"])

			opts := []cmp.Option{cmpopts.IgnoreUnexported(linkedca.Provisioner{}, timestamppb.Timestamp{})}
			if !cmp.Equal(tc.prov, prov, opts...) {
				t.Errorf("linkedca.Admin diff =\n%s", cmp.Diff(tc.prov, prov, opts...))
			}
		})
	}
}

func TestHandler_DeleteProvisioner(t *testing.T) {
	type test struct {
		ctx        context.Context
		auth       adminAuthority
		req        *http.Request
		statusCode int
		err        *admin.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/auth.LoadProvisionerByID": func(t *testing.T) test {
			req := httptest.NewRequest("DELETE", "/foo?id=provID", nil)
			chiCtx := chi.NewRouteContext()
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			auth := &mockAdminAuthority{
				MockLoadProvisionerByID: func(id string) (provisioner.Interface, error) {
					assert.Equals(t, "provID", id)
					return nil, errors.New("force")
				},
			}
			return test{
				ctx:        ctx,
				req:        req,
				auth:       auth,
				statusCode: 500,
				err: &admin.Error{
					Type:    admin.ErrorServerInternalType.String(),
					Status:  500,
					Detail:  "the server experienced an internal error",
					Message: "error loading provisioner provID: force",
				},
			}
		},
		"fail/auth.LoadProvisionerByName": func(t *testing.T) test {
			req := httptest.NewRequest("DELETE", "/foo", nil)
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("name", "provName")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			auth := &mockAdminAuthority{
				MockLoadProvisionerByName: func(name string) (provisioner.Interface, error) {
					assert.Equals(t, "provName", name)
					return nil, errors.New("force")
				},
			}
			return test{
				ctx:        ctx,
				req:        req,
				auth:       auth,
				statusCode: 500,
				err: &admin.Error{
					Type:    admin.ErrorServerInternalType.String(),
					Status:  500,
					Detail:  "the server experienced an internal error",
					Message: "error loading provisioner provName: force",
				},
			}
		},
		"fail/auth.RemoveProvisioner": func(t *testing.T) test {
			req := httptest.NewRequest("DELETE", "/foo", nil)
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("name", "provName")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			auth := &mockAdminAuthority{
				MockLoadProvisionerByName: func(name string) (provisioner.Interface, error) {
					assert.Equals(t, "provName", name)
					return &provisioner.OIDC{
						ID:   "provID",
						Name: "provName",
						Type: "OIDC",
					}, nil
				},
				MockRemoveProvisioner: func(ctx context.Context, id string) error {
					assert.Equals(t, "provID", id)
					return errors.New("force")
				},
			}
			return test{
				ctx:        ctx,
				req:        req,
				auth:       auth,
				statusCode: 500,
				err: &admin.Error{
					Type:    admin.ErrorServerInternalType.String(),
					Status:  500,
					Detail:  "the server experienced an internal error",
					Message: "error removing provisioner provName: force",
				},
			}
		},
		"ok": func(t *testing.T) test {
			req := httptest.NewRequest("DELETE", "/foo", nil)
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("name", "provName")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			auth := &mockAdminAuthority{
				MockLoadProvisionerByName: func(name string) (provisioner.Interface, error) {
					assert.Equals(t, "provName", name)
					return &provisioner.OIDC{
						ID:   "provID",
						Name: "provName",
						Type: "OIDC",
					}, nil
				},
				MockRemoveProvisioner: func(ctx context.Context, id string) error {
					assert.Equals(t, "provID", id)
					return nil
				},
			}
			return test{
				ctx:        ctx,
				req:        req,
				auth:       auth,
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
			DeleteProvisioner(w, req)
			res := w.Result()

			assert.Equals(t, tc.statusCode, res.StatusCode)

			if res.StatusCode >= 400 {

				body, err := io.ReadAll(res.Body)
				res.Body.Close()
				assert.FatalError(t, err)

				adminErr := admin.Error{}
				assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &adminErr))

				assert.Equals(t, tc.err.Type, adminErr.Type)
				assert.Equals(t, tc.err.Message, adminErr.Message)
				assert.Equals(t, tc.err.Detail, adminErr.Detail)
				assert.Equals(t, []string{"application/json"}, res.Header["Content-Type"])
				return
			}

			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			assert.FatalError(t, err)

			response := DeleteResponse{}
			assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &response))
			assert.Equals(t, "ok", response.Status)
			assert.Equals(t, []string{"application/json"}, res.Header["Content-Type"])
		})
	}
}

func TestHandler_UpdateProvisioner(t *testing.T) {
	type test struct {
		ctx        context.Context
		auth       adminAuthority
		body       []byte
		adminDB    admin.DB
		statusCode int
		err        *admin.Error
		prov       *linkedca.Provisioner
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/readProtoJSON": func(t *testing.T) test {
			body := []byte("{!?}")
			return test{
				ctx:        context.Background(),
				body:       body,
				adminDB:    &admin.MockDB{},
				statusCode: 400,
				err: &admin.Error{
					Type:    "badRequest",
					Status:  400,
					Detail:  "bad request",
					Message: "proto: syntax error (line 1:2): invalid value !",
				},
			}
		},
		"fail/auth.LoadProvisionerByName": func(t *testing.T) test {
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("name", "provName")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			prov := &linkedca.Provisioner{
				Id:   "provID",
				Type: linkedca.Provisioner_OIDC,
				Name: "provName",
			}
			body, err := protojson.Marshal(prov)
			assert.FatalError(t, err)
			auth := &mockAdminAuthority{
				MockLoadProvisionerByName: func(name string) (provisioner.Interface, error) {
					assert.Equals(t, "provName", name)
					return nil, errors.New("force")
				},
			}
			return test{
				ctx:        ctx,
				body:       body,
				adminDB:    &admin.MockDB{},
				auth:       auth,
				statusCode: 500,
				err: &admin.Error{
					Type:    admin.ErrorServerInternalType.String(),
					Status:  500,
					Detail:  "the server experienced an internal error",
					Message: "error loading provisioner from cached configuration 'provName': force",
				},
			}
		},
		"fail/db.GetProvisioner": func(t *testing.T) test {
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("name", "provName")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			prov := &linkedca.Provisioner{
				Id:   "provID",
				Type: linkedca.Provisioner_OIDC,
				Name: "provName",
			}
			body, err := protojson.Marshal(prov)
			assert.FatalError(t, err)
			auth := &mockAdminAuthority{
				MockLoadProvisionerByName: func(name string) (provisioner.Interface, error) {
					assert.Equals(t, "provName", name)
					return &provisioner.OIDC{
						ID:   "provID",
						Name: "provName",
					}, nil
				},
			}
			db := &admin.MockDB{
				MockGetProvisioner: func(ctx context.Context, id string) (*linkedca.Provisioner, error) {
					assert.Equals(t, "provID", id)
					return nil, errors.New("force")
				},
			}
			return test{
				ctx:        ctx,
				body:       body,
				auth:       auth,
				adminDB:    db,
				statusCode: 500,
				err: &admin.Error{
					Type:    admin.ErrorServerInternalType.String(),
					Status:  500,
					Detail:  "the server experienced an internal error",
					Message: "error loading provisioner from db 'provID': force",
				},
			}
		},
		"fail/change-id-error": func(t *testing.T) test {
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("name", "provName")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			prov := &linkedca.Provisioner{
				Id:   "differentProvID",
				Type: linkedca.Provisioner_OIDC,
				Name: "provName",
			}
			body, err := protojson.Marshal(prov)
			assert.FatalError(t, err)
			auth := &mockAdminAuthority{
				MockLoadProvisionerByName: func(name string) (provisioner.Interface, error) {
					assert.Equals(t, "provName", name)
					return &provisioner.OIDC{
						ID:   "provID",
						Name: "provName",
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
				body:       body,
				auth:       auth,
				adminDB:    db,
				statusCode: 500,
				err: &admin.Error{
					Type:    admin.ErrorServerInternalType.String(),
					Status:  500,
					Detail:  "the server experienced an internal error",
					Message: "cannot change provisioner ID",
				},
			}
		},
		"fail/change-type-error": func(t *testing.T) test {
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("name", "provName")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			prov := &linkedca.Provisioner{
				Id:   "provID",
				Type: linkedca.Provisioner_JWK,
				Name: "provName",
			}
			body, err := protojson.Marshal(prov)
			assert.FatalError(t, err)
			auth := &mockAdminAuthority{
				MockLoadProvisionerByName: func(name string) (provisioner.Interface, error) {
					assert.Equals(t, "provName", name)
					return &provisioner.OIDC{
						ID:   "provID",
						Name: "provName",
					}, nil
				},
			}
			db := &admin.MockDB{
				MockGetProvisioner: func(ctx context.Context, id string) (*linkedca.Provisioner, error) {
					assert.Equals(t, "provID", id)
					return &linkedca.Provisioner{
						Id:   "provID",
						Name: "provName",
						Type: linkedca.Provisioner_OIDC,
					}, nil
				},
			}
			return test{
				ctx:        ctx,
				body:       body,
				auth:       auth,
				adminDB:    db,
				statusCode: 500,
				err: &admin.Error{
					Type:    admin.ErrorServerInternalType.String(),
					Status:  500,
					Detail:  "the server experienced an internal error",
					Message: "cannot change provisioner type",
				},
			}
		},
		"fail/change-authority-id-error": func(t *testing.T) test {
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("name", "provName")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			prov := &linkedca.Provisioner{
				Id:          "provID",
				Type:        linkedca.Provisioner_OIDC,
				Name:        "provName",
				AuthorityId: "differentAuthorityID",
			}
			body, err := protojson.Marshal(prov)
			assert.FatalError(t, err)
			auth := &mockAdminAuthority{
				MockLoadProvisionerByName: func(name string) (provisioner.Interface, error) {
					assert.Equals(t, "provName", name)
					return &provisioner.OIDC{
						ID:   "provID",
						Name: "provName",
					}, nil
				},
			}
			db := &admin.MockDB{
				MockGetProvisioner: func(ctx context.Context, id string) (*linkedca.Provisioner, error) {
					assert.Equals(t, "provID", id)
					return &linkedca.Provisioner{
						Id:          "provID",
						Name:        "provName",
						Type:        linkedca.Provisioner_OIDC,
						AuthorityId: "authorityID",
					}, nil
				},
			}
			return test{
				ctx:        ctx,
				body:       body,
				auth:       auth,
				adminDB:    db,
				statusCode: 500,
				err: &admin.Error{
					Type:    admin.ErrorServerInternalType.String(),
					Status:  500,
					Detail:  "the server experienced an internal error",
					Message: "cannot change provisioner authorityID",
				},
			}
		},
		"fail/change-createdAt-error": func(t *testing.T) test {
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("name", "provName")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			createdAt := time.Now()
			prov := &linkedca.Provisioner{
				Id:          "provID",
				Type:        linkedca.Provisioner_OIDC,
				Name:        "provName",
				AuthorityId: "authorityID",
				CreatedAt:   timestamppb.New(time.Now().Add(-1 * time.Hour)),
			}
			body, err := protojson.Marshal(prov)
			assert.FatalError(t, err)
			auth := &mockAdminAuthority{
				MockLoadProvisionerByName: func(name string) (provisioner.Interface, error) {
					assert.Equals(t, "provName", name)
					return &provisioner.OIDC{
						ID:   "provID",
						Name: "provName",
					}, nil
				},
			}
			db := &admin.MockDB{
				MockGetProvisioner: func(ctx context.Context, id string) (*linkedca.Provisioner, error) {
					assert.Equals(t, "provID", id)
					return &linkedca.Provisioner{
						Id:          "provID",
						Name:        "provName",
						Type:        linkedca.Provisioner_OIDC,
						AuthorityId: "authorityID",
						CreatedAt:   timestamppb.New(createdAt),
					}, nil
				},
			}
			return test{
				ctx:        ctx,
				body:       body,
				auth:       auth,
				adminDB:    db,
				statusCode: 500,
				err: &admin.Error{
					Type:    admin.ErrorServerInternalType.String(),
					Status:  500,
					Detail:  "the server experienced an internal error",
					Message: "cannot change provisioner createdAt",
				},
			}
		},
		"fail/change-deletedAt-error": func(t *testing.T) test {
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("name", "provName")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			createdAt := time.Now()
			var deletedAt time.Time
			prov := &linkedca.Provisioner{
				Id:          "provID",
				Type:        linkedca.Provisioner_OIDC,
				Name:        "provName",
				AuthorityId: "authorityID",
				CreatedAt:   timestamppb.New(createdAt),
				DeletedAt:   timestamppb.New(time.Now()),
			}
			body, err := protojson.Marshal(prov)
			assert.FatalError(t, err)
			auth := &mockAdminAuthority{
				MockLoadProvisionerByName: func(name string) (provisioner.Interface, error) {
					assert.Equals(t, "provName", name)
					return &provisioner.OIDC{
						ID:   "provID",
						Name: "provName",
					}, nil
				},
			}
			db := &admin.MockDB{
				MockGetProvisioner: func(ctx context.Context, id string) (*linkedca.Provisioner, error) {
					assert.Equals(t, "provID", id)
					return &linkedca.Provisioner{
						Id:          "provID",
						Name:        "provName",
						Type:        linkedca.Provisioner_OIDC,
						AuthorityId: "authorityID",
						CreatedAt:   timestamppb.New(createdAt),
						DeletedAt:   timestamppb.New(deletedAt),
					}, nil
				},
			}
			return test{
				ctx:        ctx,
				body:       body,
				auth:       auth,
				adminDB:    db,
				statusCode: 500,
				err: &admin.Error{
					Type:    admin.ErrorServerInternalType.String(),
					Status:  500,
					Detail:  "the server experienced an internal error",
					Message: "cannot change provisioner deletedAt",
				},
			}
		},
		// TODO(hs): ValidateClaims can't be mocked atm
		//"fail/ValidateClaims": func(t *testing.T) test { return test{} },
		"fail/validateTemplates": func(t *testing.T) test {
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("name", "provName")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			createdAt := time.Now()
			var deletedAt time.Time
			prov := &linkedca.Provisioner{
				Id:          "provID",
				Type:        linkedca.Provisioner_OIDC,
				Name:        "provName",
				AuthorityId: "authorityID",
				CreatedAt:   timestamppb.New(createdAt),
				DeletedAt:   timestamppb.New(deletedAt),
				X509Template: &linkedca.Template{
					Template: []byte("{ {{ missingFunction }} }"),
				},
			}
			body, err := protojson.Marshal(prov)
			assert.FatalError(t, err)
			auth := &mockAdminAuthority{
				MockLoadProvisionerByName: func(name string) (provisioner.Interface, error) {
					assert.Equals(t, "provName", name)
					return &provisioner.OIDC{
						ID:   "provID",
						Name: "provName",
					}, nil
				},
			}
			db := &admin.MockDB{
				MockGetProvisioner: func(ctx context.Context, id string) (*linkedca.Provisioner, error) {
					assert.Equals(t, "provID", id)
					return &linkedca.Provisioner{
						Id:          "provID",
						Name:        "provName",
						Type:        linkedca.Provisioner_OIDC,
						AuthorityId: "authorityID",
						CreatedAt:   timestamppb.New(createdAt),
						DeletedAt:   timestamppb.New(deletedAt),
					}, nil
				},
			}
			return test{
				ctx:        ctx,
				body:       body,
				auth:       auth,
				adminDB:    db,
				statusCode: 400,
				err: &admin.Error{
					Type:    "badRequest",
					Status:  400,
					Detail:  "bad request",
					Message: "invalid template: invalid X.509 template: error parsing template: template: template:1: function \"missingFunction\" not defined",
				},
			}
		},
		"fail/auth.UpdateProvisioner": func(t *testing.T) test {
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("name", "provName")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			createdAt := time.Now()
			var deletedAt time.Time
			prov := &linkedca.Provisioner{
				Id:          "provID",
				Type:        linkedca.Provisioner_OIDC,
				Name:        "provName",
				AuthorityId: "authorityID",
				CreatedAt:   timestamppb.New(createdAt),
				DeletedAt:   timestamppb.New(deletedAt),
			}
			body, err := protojson.Marshal(prov)
			assert.FatalError(t, err)
			auth := &mockAdminAuthority{
				MockLoadProvisionerByName: func(name string) (provisioner.Interface, error) {
					assert.Equals(t, "provName", name)
					return &provisioner.OIDC{
						ID:   "provID",
						Name: "provName",
					}, nil
				},
				MockUpdateProvisioner: func(ctx context.Context, nu *linkedca.Provisioner) error {
					assert.Equals(t, "provID", nu.Id)
					assert.Equals(t, "provName", nu.Name)
					return errors.New("force")
				},
			}
			db := &admin.MockDB{
				MockGetProvisioner: func(ctx context.Context, id string) (*linkedca.Provisioner, error) {
					assert.Equals(t, "provID", id)
					return &linkedca.Provisioner{
						Id:          "provID",
						Name:        "provName",
						Type:        linkedca.Provisioner_OIDC,
						AuthorityId: "authorityID",
						CreatedAt:   timestamppb.New(createdAt),
						DeletedAt:   timestamppb.New(deletedAt),
					}, nil
				},
			}
			return test{
				ctx:        ctx,
				body:       body,
				auth:       auth,
				adminDB:    db,
				statusCode: 500,
				err: &admin.Error{
					Type:    "", // TODO(hs): this error can be improved
					Status:  500,
					Detail:  "",
					Message: "",
				},
			}
		},
		"ok": func(t *testing.T) test {
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("name", "provName")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			createdAt := time.Now()
			var deletedAt time.Time
			prov := &linkedca.Provisioner{
				Id:          "provID",
				Type:        linkedca.Provisioner_OIDC,
				Name:        "provName",
				AuthorityId: "authorityID",
				CreatedAt:   timestamppb.New(createdAt),
				DeletedAt:   timestamppb.New(deletedAt),
				Details: &linkedca.ProvisionerDetails{
					Data: &linkedca.ProvisionerDetails_OIDC{
						OIDC: &linkedca.OIDCProvisioner{
							ClientId:     "new-client-id",
							ClientSecret: "new-client-secret",
						},
					},
				},
			}
			body, err := protojson.Marshal(prov)
			assert.FatalError(t, err)
			auth := &mockAdminAuthority{
				MockLoadProvisionerByName: func(name string) (provisioner.Interface, error) {
					assert.Equals(t, "provName", name)
					return &provisioner.OIDC{
						ID:   "provID",
						Name: "provName",
					}, nil
				},
				MockUpdateProvisioner: func(ctx context.Context, nu *linkedca.Provisioner) error {
					assert.Equals(t, "provID", nu.Id)
					assert.Equals(t, "provName", nu.Name)
					return nil
				},
			}
			db := &admin.MockDB{
				MockGetProvisioner: func(ctx context.Context, id string) (*linkedca.Provisioner, error) {
					assert.Equals(t, "provID", id)
					return &linkedca.Provisioner{
						Id:          "provID",
						Name:        "provName",
						Type:        linkedca.Provisioner_OIDC,
						AuthorityId: "authorityID",
						CreatedAt:   timestamppb.New(createdAt),
						DeletedAt:   timestamppb.New(deletedAt),
					}, nil
				},
			}
			return test{
				ctx:        ctx,
				body:       body,
				auth:       auth,
				adminDB:    db,
				statusCode: 200,
				prov:       prov,
			}
		},
	}
	for name, prep := range tests {
		tc := prep(t)
		t.Run(name, func(t *testing.T) {
			mockMustAuthority(t, tc.auth)
			ctx := admin.NewContext(tc.ctx, tc.adminDB)
			req := httptest.NewRequest("POST", "/foo", io.NopCloser(bytes.NewBuffer(tc.body)))
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()
			UpdateProvisioner(w, req)
			res := w.Result()

			assert.Equals(t, tc.statusCode, res.StatusCode)

			if res.StatusCode >= 400 {

				body, err := io.ReadAll(res.Body)
				res.Body.Close()
				assert.FatalError(t, err)

				adminErr := admin.Error{}
				assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &adminErr))

				assert.Equals(t, tc.err.Type, adminErr.Type)
				assert.Equals(t, tc.err.Detail, adminErr.Detail)
				assert.Equals(t, []string{"application/json"}, res.Header["Content-Type"])

				if strings.HasPrefix(tc.err.Message, "proto:") {
					assert.True(t, strings.Contains(adminErr.Message, "syntax error"))
				} else {
					assert.Equals(t, tc.err.Message, adminErr.Message)
				}

				return
			}

			prov := &linkedca.Provisioner{}
			err := readProtoJSON(res.Body, prov)
			assert.FatalError(t, err)

			assert.Equals(t, []string{"application/json"}, res.Header["Content-Type"])

			opts := []cmp.Option{
				cmpopts.IgnoreUnexported(
					linkedca.Provisioner{}, linkedca.ProvisionerDetails{}, linkedca.ProvisionerDetails_OIDC{},
					linkedca.OIDCProvisioner{}, timestamppb.Timestamp{},
				),
			}
			if !cmp.Equal(tc.prov, prov, opts...) {
				t.Errorf("linkedca.Admin diff =\n%s", cmp.Diff(tc.prov, prov, opts...))
			}
		})
	}
}

func Test_validateTemplates(t *testing.T) {
	type args struct {
		x509 *linkedca.Template
		ssh  *linkedca.Template
	}
	tests := []struct {
		name string
		args args
		err  error
	}{
		{
			name: "ok",
			args: args{},
			err:  nil,
		},
		{
			name: "ok/x509",
			args: args{
				x509: &linkedca.Template{
					Template: []byte(`{"x": 1}`),
				},
			},
			err: nil,
		},
		{
			name: "ok/ssh",
			args: args{
				ssh: &linkedca.Template{
					Template: []byte(`{"x": 1}`),
				},
			},
			err: nil,
		},
		{
			name: "fail/x509-template-missing-quote",
			args: args{
				x509: &linkedca.Template{
					Template: []byte(`{ {{printf "%q" "quoted}} }`),
				},
			},
			err: errors.New("invalid X.509 template: error parsing template: template: template:1: unterminated quoted string"),
		},
		{
			name: "fail/x509-template-data",
			args: args{
				x509: &linkedca.Template{
					Data: []byte(`{!?}`),
				},
			},
			err: errors.New("invalid X.509 template data: error validating json template data"),
		},
		{
			name: "fail/ssh-template-unknown-function",
			args: args{
				ssh: &linkedca.Template{
					Template: []byte(`{ {{unknownFunction "foo"}} }`),
				},
			},
			err: errors.New("invalid SSH template: error parsing template: template: template:1: function \"unknownFunction\" not defined"),
		},
		{
			name: "fail/ssh-template-data",
			args: args{
				ssh: &linkedca.Template{
					Data: []byte(`{!?}`),
				},
			},
			err: errors.New("invalid SSH template data: error validating json template data"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTemplates(tt.args.x509, tt.args.ssh)
			if tt.err != nil {
				assert.Error(t, err)
				assert.Equals(t, tt.err.Error(), err.Error())
				return
			}

			assert.Nil(t, err)
		})
	}
}
