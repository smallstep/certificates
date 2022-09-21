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
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/authority/provisioner"
)

type mockAdminAuthority struct {
	MockLoadProvisionerByName func(name string) (provisioner.Interface, error)
	MockGetProvisioners       func(nextCursor string, limit int) (provisioner.List, string, error)
	MockRet1, MockRet2        interface{} // TODO: refactor the ret1/ret2 into those two
	MockErr                   error
	MockIsAdminAPIEnabled     func() bool
	MockLoadAdminByID         func(id string) (*linkedca.Admin, bool)
	MockGetAdmins             func(cursor string, limit int) ([]*linkedca.Admin, string, error)
	MockStoreAdmin            func(ctx context.Context, adm *linkedca.Admin, prov provisioner.Interface) error
	MockUpdateAdmin           func(ctx context.Context, id string, nu *linkedca.Admin) (*linkedca.Admin, error)
	MockRemoveAdmin           func(ctx context.Context, id string) error
	MockAuthorizeAdminToken   func(r *http.Request, token string) (*linkedca.Admin, error)
	MockStoreProvisioner      func(ctx context.Context, prov *linkedca.Provisioner) error
	MockLoadProvisionerByID   func(id string) (provisioner.Interface, error)
	MockUpdateProvisioner     func(ctx context.Context, nu *linkedca.Provisioner) error
	MockRemoveProvisioner     func(ctx context.Context, id string) error

	MockGetAuthorityPolicy    func(ctx context.Context) (*linkedca.Policy, error)
	MockCreateAuthorityPolicy func(ctx context.Context, adm *linkedca.Admin, policy *linkedca.Policy) (*linkedca.Policy, error)
	MockUpdateAuthorityPolicy func(ctx context.Context, adm *linkedca.Admin, policy *linkedca.Policy) (*linkedca.Policy, error)
	MockRemoveAuthorityPolicy func(ctx context.Context) error
}

func (m *mockAdminAuthority) IsAdminAPIEnabled() bool {
	if m.MockIsAdminAPIEnabled != nil {
		return m.MockIsAdminAPIEnabled()
	}
	return m.MockRet1.(bool)
}

func (m *mockAdminAuthority) LoadProvisionerByName(name string) (provisioner.Interface, error) {
	if m.MockLoadProvisionerByName != nil {
		return m.MockLoadProvisionerByName(name)
	}
	return m.MockRet1.(provisioner.Interface), m.MockErr
}

func (m *mockAdminAuthority) GetProvisioners(nextCursor string, limit int) (provisioner.List, string, error) {
	if m.MockGetProvisioners != nil {
		return m.MockGetProvisioners(nextCursor, limit)
	}
	return m.MockRet1.(provisioner.List), m.MockRet2.(string), m.MockErr
}

func (m *mockAdminAuthority) LoadAdminByID(id string) (*linkedca.Admin, bool) {
	if m.MockLoadAdminByID != nil {
		return m.MockLoadAdminByID(id)
	}
	return m.MockRet1.(*linkedca.Admin), m.MockRet2.(bool)
}

func (m *mockAdminAuthority) GetAdmins(cursor string, limit int) ([]*linkedca.Admin, string, error) {
	if m.MockGetAdmins != nil {
		return m.MockGetAdmins(cursor, limit)
	}
	return m.MockRet1.([]*linkedca.Admin), m.MockRet2.(string), m.MockErr
}

func (m *mockAdminAuthority) StoreAdmin(ctx context.Context, adm *linkedca.Admin, prov provisioner.Interface) error {
	if m.MockStoreAdmin != nil {
		return m.MockStoreAdmin(ctx, adm, prov)
	}
	return m.MockErr
}

func (m *mockAdminAuthority) UpdateAdmin(ctx context.Context, id string, nu *linkedca.Admin) (*linkedca.Admin, error) {
	if m.MockUpdateAdmin != nil {
		return m.MockUpdateAdmin(ctx, id, nu)
	}
	return m.MockRet1.(*linkedca.Admin), m.MockErr
}

func (m *mockAdminAuthority) RemoveAdmin(ctx context.Context, id string) error {
	if m.MockRemoveAdmin != nil {
		return m.MockRemoveAdmin(ctx, id)
	}
	return m.MockErr
}

func (m *mockAdminAuthority) AuthorizeAdminToken(r *http.Request, token string) (*linkedca.Admin, error) {
	if m.MockAuthorizeAdminToken != nil {
		return m.MockAuthorizeAdminToken(r, token)
	}
	return m.MockRet1.(*linkedca.Admin), m.MockErr
}

func (m *mockAdminAuthority) StoreProvisioner(ctx context.Context, prov *linkedca.Provisioner) error {
	if m.MockStoreProvisioner != nil {
		return m.MockStoreProvisioner(ctx, prov)
	}
	return m.MockErr
}

func (m *mockAdminAuthority) LoadProvisionerByID(id string) (provisioner.Interface, error) {
	if m.MockLoadProvisionerByID != nil {
		return m.MockLoadProvisionerByID(id)
	}
	return m.MockRet1.(provisioner.Interface), m.MockErr
}

func (m *mockAdminAuthority) UpdateProvisioner(ctx context.Context, nu *linkedca.Provisioner) error {
	if m.MockUpdateProvisioner != nil {
		return m.MockUpdateProvisioner(ctx, nu)
	}
	return m.MockErr
}

func (m *mockAdminAuthority) RemoveProvisioner(ctx context.Context, id string) error {
	if m.MockRemoveProvisioner != nil {
		return m.MockRemoveProvisioner(ctx, id)
	}
	return m.MockErr
}

func (m *mockAdminAuthority) GetAuthorityPolicy(ctx context.Context) (*linkedca.Policy, error) {
	if m.MockGetAuthorityPolicy != nil {
		return m.MockGetAuthorityPolicy(ctx)
	}
	return m.MockRet1.(*linkedca.Policy), m.MockErr
}

func (m *mockAdminAuthority) CreateAuthorityPolicy(ctx context.Context, adm *linkedca.Admin, policy *linkedca.Policy) (*linkedca.Policy, error) {
	if m.MockCreateAuthorityPolicy != nil {
		return m.MockCreateAuthorityPolicy(ctx, adm, policy)
	}
	return m.MockRet1.(*linkedca.Policy), m.MockErr
}

func (m *mockAdminAuthority) UpdateAuthorityPolicy(ctx context.Context, adm *linkedca.Admin, policy *linkedca.Policy) (*linkedca.Policy, error) {
	if m.MockUpdateAuthorityPolicy != nil {
		return m.MockUpdateAuthorityPolicy(ctx, adm, policy)
	}
	return m.MockRet1.(*linkedca.Policy), m.MockErr
}

func (m *mockAdminAuthority) RemoveAuthorityPolicy(ctx context.Context) error {
	if m.MockRemoveAuthorityPolicy != nil {
		return m.MockRemoveAuthorityPolicy(ctx)
	}
	return m.MockErr
}

func TestCreateAdminRequest_Validate(t *testing.T) {
	type fields struct {
		Subject     string
		Provisioner string
		Type        linkedca.Admin_Type
	}
	tests := []struct {
		name   string
		fields fields
		err    *admin.Error
	}{
		{
			name: "fail/subject-empty",
			fields: fields{
				Subject:     "",
				Provisioner: "",
				Type:        0,
			},
			err: admin.NewError(admin.ErrorBadRequestType, "subject cannot be empty"),
		},
		{
			name: "fail/provisioner-empty",
			fields: fields{
				Subject:     "admin",
				Provisioner: "",
				Type:        0,
			},
			err: admin.NewError(admin.ErrorBadRequestType, "provisioner cannot be empty"),
		},
		{
			name: "fail/invalid-type",
			fields: fields{
				Subject:     "admin",
				Provisioner: "prov",
				Type:        -1,
			},
			err: admin.NewError(admin.ErrorBadRequestType, "invalid value for admin type"),
		},
		{
			name: "ok",
			fields: fields{
				Subject:     "admin",
				Provisioner: "prov",
				Type:        linkedca.Admin_SUPER_ADMIN,
			},
			err: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			car := &CreateAdminRequest{
				Subject:     tt.fields.Subject,
				Provisioner: tt.fields.Provisioner,
				Type:        tt.fields.Type,
			}
			err := car.Validate()

			if (err != nil) != (tt.err != nil) {
				t.Errorf("CreateAdminRequest.Validate() error = %v, wantErr %v", err, (tt.err != nil))
				return
			}

			if err != nil {
				assert.Type(t, &admin.Error{}, err)
				var adminErr *admin.Error
				if assert.True(t, errors.As(err, &adminErr)) {
					assert.Equals(t, tt.err.Type, adminErr.Type)
					assert.Equals(t, tt.err.Detail, adminErr.Detail)
					assert.Equals(t, tt.err.Status, adminErr.Status)
					assert.Equals(t, tt.err.Message, adminErr.Message)
				}
			}
		})
	}
}

func TestUpdateAdminRequest_Validate(t *testing.T) {
	type fields struct {
		Type linkedca.Admin_Type
	}
	tests := []struct {
		name   string
		fields fields
		err    *admin.Error
	}{
		{
			name: "fail/invalid-type",
			fields: fields{
				Type: -1,
			},
			err: admin.NewError(admin.ErrorBadRequestType, "invalid value for admin type"),
		},
		{
			name: "ok",
			fields: fields{
				Type: linkedca.Admin_SUPER_ADMIN,
			},
			err: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uar := &UpdateAdminRequest{
				Type: tt.fields.Type,
			}

			err := uar.Validate()

			if (err != nil) != (tt.err != nil) {
				t.Errorf("CreateAdminRequest.Validate() error = %v, wantErr %v", err, (tt.err != nil))
				return
			}

			if err != nil {
				assert.Type(t, &admin.Error{}, err)
				var ae *admin.Error
				if assert.True(t, errors.As(err, &ae)) {
					assert.Equals(t, tt.err.Type, ae.Type)
					assert.Equals(t, tt.err.Detail, ae.Detail)
					assert.Equals(t, tt.err.Status, ae.Status)
					assert.Equals(t, tt.err.Message, ae.Message)
				}
			}
		})
	}
}

func TestHandler_GetAdmin(t *testing.T) {
	type test struct {
		ctx        context.Context
		auth       adminAuthority
		statusCode int
		err        *admin.Error
		adm        *linkedca.Admin
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/auth.LoadAdminByID-not-found": func(t *testing.T) test {
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("id", "adminID")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			auth := &mockAdminAuthority{
				MockLoadAdminByID: func(id string) (*linkedca.Admin, bool) {
					assert.Equals(t, "adminID", id)
					return nil, false
				},
			}
			return test{
				ctx:        ctx,
				auth:       auth,
				statusCode: 404,
				err: &admin.Error{
					Type:    admin.ErrorNotFoundType.String(),
					Status:  404,
					Detail:  "resource not found",
					Message: "admin adminID not found",
				},
			}
		},
		"ok": func(t *testing.T) test {
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("id", "adminID")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
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
				MockLoadAdminByID: func(id string) (*linkedca.Admin, bool) {
					assert.Equals(t, "adminID", id)
					return adm, true
				},
			}
			return test{
				ctx:        ctx,
				auth:       auth,
				statusCode: 200,
				err:        nil,
				adm:        adm,
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
			GetAdmin(w, req)
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

			adm := &linkedca.Admin{}
			err := readProtoJSON(res.Body, adm)
			assert.FatalError(t, err)

			assert.Equals(t, []string{"application/json"}, res.Header["Content-Type"])

			opts := []cmp.Option{cmpopts.IgnoreUnexported(linkedca.Admin{}, timestamppb.Timestamp{})}
			if !cmp.Equal(tc.adm, adm, opts...) {
				t.Errorf("linkedca.Admin diff =\n%s", cmp.Diff(tc.adm, adm, opts...))
			}
		})
	}
}

func TestHandler_GetAdmins(t *testing.T) {
	type test struct {
		ctx        context.Context
		auth       adminAuthority
		req        *http.Request
		statusCode int
		err        *admin.Error
		resp       GetAdminsResponse
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/parse-cursor": func(t *testing.T) test {
			req := httptest.NewRequest("GET", "/foo?limit=A", nil)
			return test{
				ctx:        context.Background(),
				req:        req,
				statusCode: 400,
				err: &admin.Error{
					Status:  400,
					Type:    admin.ErrorBadRequestType.String(),
					Detail:  "bad request",
					Message: "error parsing cursor and limit from query params: limit 'A' is not an integer: strconv.Atoi: parsing \"A\": invalid syntax",
				},
			}
		},
		"fail/auth.GetAdmins": func(t *testing.T) test {
			req := httptest.NewRequest("GET", "/foo", nil)
			auth := &mockAdminAuthority{
				MockGetAdmins: func(cursor string, limit int) ([]*linkedca.Admin, string, error) {
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
					Status:  500,
					Type:    admin.ErrorServerInternalType.String(),
					Detail:  "the server experienced an internal error",
					Message: "error retrieving paginated admins: force",
				},
			}
		},
		"ok": func(t *testing.T) test {
			req := httptest.NewRequest("GET", "/foo", nil)
			createdAt := time.Now()
			var deletedAt time.Time
			adm1 := &linkedca.Admin{
				Id:            "adminID1",
				AuthorityId:   "authorityID1",
				Subject:       "admin1",
				ProvisionerId: "provID",
				Type:          linkedca.Admin_SUPER_ADMIN,
				CreatedAt:     timestamppb.New(createdAt),
				DeletedAt:     timestamppb.New(deletedAt),
			}
			adm2 := &linkedca.Admin{
				Id:            "adminID2",
				AuthorityId:   "authorityID",
				Subject:       "admin2",
				ProvisionerId: "provID",
				Type:          linkedca.Admin_ADMIN,
				CreatedAt:     timestamppb.New(createdAt),
				DeletedAt:     timestamppb.New(deletedAt),
			}
			auth := &mockAdminAuthority{
				MockGetAdmins: func(cursor string, limit int) ([]*linkedca.Admin, string, error) {
					assert.Equals(t, "", cursor)
					assert.Equals(t, 0, limit)
					return []*linkedca.Admin{
						adm1,
						adm2,
					}, "nextCursorValue", nil
				},
			}
			return test{
				ctx:        context.Background(),
				req:        req,
				auth:       auth,
				statusCode: 200,
				err:        nil,
				resp: GetAdminsResponse{
					Admins: []*linkedca.Admin{
						adm1,
						adm2,
					},
					NextCursor: "nextCursorValue",
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
			GetAdmins(w, req)
			res := w.Result()

			assert.Equals(t, tc.statusCode, res.StatusCode)

			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			assert.FatalError(t, err)

			if res.StatusCode >= 400 {

				adminErr := admin.Error{}
				assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &adminErr))

				assert.Equals(t, tc.err.Type, adminErr.Type)
				assert.Equals(t, tc.err.Message, adminErr.Message)
				assert.Equals(t, tc.err.Detail, adminErr.Detail)
				assert.Equals(t, []string{"application/json"}, res.Header["Content-Type"])
				return
			}

			response := GetAdminsResponse{}
			assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &response))
			assert.Equals(t, []string{"application/json"}, res.Header["Content-Type"])

			opts := []cmp.Option{cmpopts.IgnoreUnexported(linkedca.Admin{}, timestamppb.Timestamp{})}
			if !cmp.Equal(tc.resp, response, opts...) {
				t.Errorf("GetAdmins diff =\n%s", cmp.Diff(tc.resp, response, opts...))
			}
		})
	}
}

func TestHandler_CreateAdmin(t *testing.T) {
	type test struct {
		ctx        context.Context
		auth       adminAuthority
		body       []byte
		statusCode int
		err        *admin.Error
		adm        *linkedca.Admin
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/ReadJSON": func(t *testing.T) test {
			body := []byte("{!?}")
			return test{
				ctx:        context.Background(),
				body:       body,
				statusCode: 400,
				err: &admin.Error{
					Type:    admin.ErrorBadRequestType.String(),
					Status:  400,
					Detail:  "bad request",
					Message: "error reading request body: error decoding json: invalid character '!' looking for beginning of object key string",
				},
			}
		},
		"fail/validate": func(t *testing.T) test {
			req := CreateAdminRequest{
				Subject:     "",
				Provisioner: "",
				Type:        -1,
			}
			body, err := json.Marshal(req)
			assert.FatalError(t, err)
			return test{
				ctx:        context.Background(),
				body:       body,
				statusCode: 400,
				err: &admin.Error{
					Type:    admin.ErrorBadRequestType.String(),
					Status:  400,
					Detail:  "bad request",
					Message: "subject cannot be empty",
				},
			}
		},
		"fail/auth.LoadProvisionerByName": func(t *testing.T) test {
			req := CreateAdminRequest{
				Subject:     "admin",
				Provisioner: "prov",
				Type:        linkedca.Admin_SUPER_ADMIN,
			}
			body, err := json.Marshal(req)
			assert.FatalError(t, err)
			auth := &mockAdminAuthority{
				MockLoadProvisionerByName: func(name string) (provisioner.Interface, error) {
					assert.Equals(t, "prov", name)
					return nil, errors.New("force")
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
					Message: "error loading provisioner prov: force",
				},
			}
		},
		"fail/auth.StoreAdmin": func(t *testing.T) test {
			req := CreateAdminRequest{
				Subject:     "admin",
				Provisioner: "prov",
				Type:        linkedca.Admin_SUPER_ADMIN,
			}
			body, err := json.Marshal(req)
			assert.FatalError(t, err)
			auth := &mockAdminAuthority{
				MockLoadProvisionerByName: func(name string) (provisioner.Interface, error) {
					assert.Equals(t, "prov", name)
					return &provisioner.ACME{
						ID:   "provID",
						Name: "prov",
					}, nil
				},
				MockStoreAdmin: func(ctx context.Context, adm *linkedca.Admin, prov provisioner.Interface) error {
					assert.Equals(t, "admin", adm.Subject)
					assert.Equals(t, "provID", prov.GetID())
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
					Message: "error storing admin: force",
				},
			}
		},
		"ok": func(t *testing.T) test {
			req := CreateAdminRequest{
				Subject:     "admin",
				Provisioner: "prov",
				Type:        linkedca.Admin_SUPER_ADMIN,
			}
			body, err := json.Marshal(req)
			assert.FatalError(t, err)
			auth := &mockAdminAuthority{
				MockLoadProvisionerByName: func(name string) (provisioner.Interface, error) {
					assert.Equals(t, "prov", name)
					return &provisioner.ACME{
						ID:   "provID",
						Name: "prov",
					}, nil
				},
				MockStoreAdmin: func(ctx context.Context, adm *linkedca.Admin, prov provisioner.Interface) error {
					assert.Equals(t, "admin", adm.Subject)
					assert.Equals(t, "provID", prov.GetID())
					return nil
				},
			}
			return test{
				ctx:        context.Background(),
				body:       body,
				auth:       auth,
				statusCode: 201,
				err:        nil,
				adm: &linkedca.Admin{
					ProvisionerId: "provID",
					Subject:       "admin",
					Type:          linkedca.Admin_SUPER_ADMIN,
				},
			}
		},
	}
	for name, prep := range tests {
		tc := prep(t)
		t.Run(name, func(t *testing.T) {
			mockMustAuthority(t, tc.auth)
			req := httptest.NewRequest("GET", "/foo", io.NopCloser(bytes.NewBuffer(tc.body)))
			req = req.WithContext(tc.ctx)
			w := httptest.NewRecorder()
			CreateAdmin(w, req)
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

			adm := &linkedca.Admin{}
			err := readProtoJSON(res.Body, adm)
			assert.FatalError(t, err)

			assert.Equals(t, []string{"application/json"}, res.Header["Content-Type"])

			opts := []cmp.Option{cmpopts.IgnoreUnexported(linkedca.Admin{}, timestamppb.Timestamp{})}
			if !cmp.Equal(tc.adm, adm, opts...) {
				t.Errorf("h.CreateAdmin diff =\n%s", cmp.Diff(tc.adm, adm, opts...))
			}
		})
	}
}

func TestHandler_DeleteAdmin(t *testing.T) {
	type test struct {
		ctx        context.Context
		auth       adminAuthority
		statusCode int
		err        *admin.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/auth.RemoveAdmin": func(t *testing.T) test {
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("id", "adminID")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			auth := &mockAdminAuthority{
				MockRemoveAdmin: func(ctx context.Context, id string) error {
					assert.Equals(t, "adminID", id)
					return errors.New("force")
				},
			}
			return test{
				ctx:        ctx,
				auth:       auth,
				statusCode: 500,
				err: &admin.Error{
					Type:    admin.ErrorServerInternalType.String(),
					Status:  500,
					Detail:  "the server experienced an internal error",
					Message: "error deleting admin adminID: force",
				},
			}
		},
		"ok": func(t *testing.T) test {
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("id", "adminID")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			auth := &mockAdminAuthority{
				MockRemoveAdmin: func(ctx context.Context, id string) error {
					assert.Equals(t, "adminID", id)
					return nil
				},
			}
			return test{
				ctx:        ctx,
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
			req := httptest.NewRequest("DELETE", "/foo", nil) // chi routing is prepared in test setup
			req = req.WithContext(tc.ctx)
			w := httptest.NewRecorder()
			DeleteAdmin(w, req)
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
				assert.Equals(t, tc.err.StatusCode(), res.StatusCode)
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

func TestHandler_UpdateAdmin(t *testing.T) {
	type test struct {
		ctx        context.Context
		auth       adminAuthority
		body       []byte
		statusCode int
		err        *admin.Error
		adm        *linkedca.Admin
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/ReadJSON": func(t *testing.T) test {
			body := []byte("{!?}")
			return test{
				ctx:        context.Background(),
				body:       body,
				statusCode: 400,
				err: &admin.Error{
					Type:    admin.ErrorBadRequestType.String(),
					Status:  400,
					Detail:  "bad request",
					Message: "error reading request body: error decoding json: invalid character '!' looking for beginning of object key string",
				},
			}
		},
		"fail/validate": func(t *testing.T) test {
			req := UpdateAdminRequest{
				Type: -1,
			}
			body, err := json.Marshal(req)
			assert.FatalError(t, err)
			return test{
				ctx:        context.Background(),
				body:       body,
				statusCode: 400,
				err: &admin.Error{
					Type:    admin.ErrorBadRequestType.String(),
					Status:  400,
					Detail:  "bad request",
					Message: "invalid value for admin type",
				},
			}
		},
		"fail/auth.UpdateAdmin": func(t *testing.T) test {
			req := UpdateAdminRequest{
				Type: linkedca.Admin_ADMIN,
			}
			body, err := json.Marshal(req)
			assert.FatalError(t, err)
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("id", "adminID")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			auth := &mockAdminAuthority{
				MockUpdateAdmin: func(ctx context.Context, id string, nu *linkedca.Admin) (*linkedca.Admin, error) {
					assert.Equals(t, "adminID", id)
					assert.Equals(t, linkedca.Admin_ADMIN, nu.Type)
					return nil, errors.New("force")
				},
			}
			return test{
				ctx:        ctx,
				body:       body,
				auth:       auth,
				statusCode: 500,
				err: &admin.Error{
					Type:    admin.ErrorServerInternalType.String(),
					Status:  500,
					Detail:  "the server experienced an internal error",
					Message: "error updating admin adminID: force",
				},
			}
		},
		"ok": func(t *testing.T) test {
			req := UpdateAdminRequest{
				Type: linkedca.Admin_ADMIN,
			}
			body, err := json.Marshal(req)
			assert.FatalError(t, err)
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("id", "adminID")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			adm := &linkedca.Admin{
				Id:            "adminID",
				ProvisionerId: "provID",
				Subject:       "admin",
				Type:          linkedca.Admin_SUPER_ADMIN,
			}
			auth := &mockAdminAuthority{
				MockUpdateAdmin: func(ctx context.Context, id string, nu *linkedca.Admin) (*linkedca.Admin, error) {
					assert.Equals(t, "adminID", id)
					assert.Equals(t, linkedca.Admin_ADMIN, nu.Type)
					return adm, nil
				},
			}
			return test{
				ctx:        ctx,
				body:       body,
				auth:       auth,
				statusCode: 200,
				err:        nil,
				adm:        adm,
			}
		},
	}
	for name, prep := range tests {
		tc := prep(t)
		t.Run(name, func(t *testing.T) {
			mockMustAuthority(t, tc.auth)
			req := httptest.NewRequest("GET", "/foo", io.NopCloser(bytes.NewBuffer(tc.body)))
			req = req.WithContext(tc.ctx)
			w := httptest.NewRecorder()
			UpdateAdmin(w, req)
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

			adm := &linkedca.Admin{}
			err := readProtoJSON(res.Body, adm)
			assert.FatalError(t, err)

			assert.Equals(t, []string{"application/json"}, res.Header["Content-Type"])

			opts := []cmp.Option{cmpopts.IgnoreUnexported(linkedca.Admin{}, timestamppb.Timestamp{})}
			if !cmp.Equal(tc.adm, adm, opts...) {
				t.Errorf("h.UpdateAdmin diff =\n%s", cmp.Diff(tc.adm, adm, opts...))
			}
		})
	}
}
