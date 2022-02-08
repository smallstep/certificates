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

	"github.com/go-chi/chi"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/authority/provisioner"
	"go.step.sm/linkedca"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func readProtoJSON(r io.ReadCloser, m proto.Message) error {
	defer r.Close()
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	return protojson.Unmarshal(data, m)
}

func TestHandler_requireEABEnabled(t *testing.T) {
	type test struct {
		ctx        context.Context
		adminDB    admin.DB
		auth       adminAuthority
		next       nextHTTP
		err        *admin.Error
		statusCode int
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/h.provisionerHasEABEnabled": func(t *testing.T) test {
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("provisionerName", "provName")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			auth := &mockAdminAuthority{
				MockLoadProvisionerByName: func(name string) (provisioner.Interface, error) {
					assert.Equals(t, "provName", name)
					return nil, errors.New("force")
				},
			}
			err := admin.NewErrorISE("error loading provisioner provName: force")
			err.Message = "error loading provisioner provName: force"
			return test{
				ctx:        ctx,
				auth:       auth,
				err:        err,
				statusCode: 500,
			}
		},
		"ok/eab-disabled": func(t *testing.T) test {
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
						Details: &linkedca.ProvisionerDetails{
							Data: &linkedca.ProvisionerDetails_ACME{
								ACME: &linkedca.ACMEProvisioner{
									RequireEab: false,
								},
							},
						},
					}, nil
				},
			}
			err := admin.NewError(admin.ErrorBadRequestType, "ACME EAB not enabled for provisioner provName")
			err.Message = "ACME EAB not enabled for provisioner provName"
			return test{
				ctx:        ctx,
				auth:       auth,
				adminDB:    db,
				err:        err,
				statusCode: 400,
			}
		},
		"ok/eab-enabled": func(t *testing.T) test {
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
						Details: &linkedca.ProvisionerDetails{
							Data: &linkedca.ProvisionerDetails_ACME{
								ACME: &linkedca.ACMEProvisioner{
									RequireEab: true,
								},
							},
						},
					}, nil
				},
			}
			return test{
				ctx:     ctx,
				auth:    auth,
				adminDB: db,
				next: func(w http.ResponseWriter, r *http.Request) {
					w.Write(nil) // mock response with status 200
				},
				statusCode: 200,
			}
		},
	}

	for name, prep := range tests {
		tc := prep(t)
		t.Run(name, func(t *testing.T) {
			h := &Handler{
				auth:    tc.auth,
				adminDB: tc.adminDB,
				acmeDB:  nil,
			}

			req := httptest.NewRequest("GET", "/foo", nil) // chi routing is prepared in test setup
			req = req.WithContext(tc.ctx)
			w := httptest.NewRecorder()
			h.requireEABEnabled(tc.next)(w, req)
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

func TestHandler_provisionerHasEABEnabled(t *testing.T) {
	type test struct {
		adminDB         admin.DB
		auth            adminAuthority
		provisionerName string
		want            bool
		err             *admin.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/auth.LoadProvisionerByName": func(t *testing.T) test {
			auth := &mockAdminAuthority{
				MockLoadProvisionerByName: func(name string) (provisioner.Interface, error) {
					assert.Equals(t, "provName", name)
					return nil, errors.New("force")
				},
			}
			return test{
				auth:            auth,
				provisionerName: "provName",
				want:            false,
				err:             admin.WrapErrorISE(errors.New("force"), "error loading provisioner provName"),
			}
		},
		"fail/db.GetProvisioner": func(t *testing.T) test {
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
			return test{
				auth:            auth,
				adminDB:         db,
				provisionerName: "provName",
				want:            false,
				err:             admin.WrapErrorISE(errors.New("force"), "error loading provisioner provName"),
			}
		},
		"fail/prov.GetDetails": func(t *testing.T) test {
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
						Id:      "provID",
						Name:    "provName",
						Details: nil,
					}, nil
				},
			}
			return test{
				auth:            auth,
				adminDB:         db,
				provisionerName: "provName",
				want:            false,
				err:             admin.WrapErrorISE(errors.New("force"), "error loading provisioner provName"),
			}
		},
		"fail/details.GetACME": func(t *testing.T) test {
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
						Details: &linkedca.ProvisionerDetails{
							Data: &linkedca.ProvisionerDetails_ACME{
								ACME: nil,
							},
						},
					}, nil
				},
			}
			return test{
				auth:            auth,
				adminDB:         db,
				provisionerName: "provName",
				want:            false,
				err:             admin.WrapErrorISE(errors.New("force"), "error loading provisioner provName"),
			}
		},
		"ok/eab-disabled": func(t *testing.T) test {
			auth := &mockAdminAuthority{
				MockLoadProvisionerByName: func(name string) (provisioner.Interface, error) {
					assert.Equals(t, "eab-disabled", name)
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
						Name: "eab-disabled",
						Details: &linkedca.ProvisionerDetails{
							Data: &linkedca.ProvisionerDetails_ACME{
								ACME: &linkedca.ACMEProvisioner{
									RequireEab: false,
								},
							},
						},
					}, nil
				},
			}
			return test{
				adminDB:         db,
				auth:            auth,
				provisionerName: "eab-disabled",
				want:            false,
			}
		},
		"ok/eab-enabled": func(t *testing.T) test {
			auth := &mockAdminAuthority{
				MockLoadProvisionerByName: func(name string) (provisioner.Interface, error) {
					assert.Equals(t, "eab-enabled", name)
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
						Name: "eab-enabled",
						Details: &linkedca.ProvisionerDetails{
							Data: &linkedca.ProvisionerDetails_ACME{
								ACME: &linkedca.ACMEProvisioner{
									RequireEab: true,
								},
							},
						},
					}, nil
				},
			}
			return test{
				adminDB:         db,
				auth:            auth,
				provisionerName: "eab-enabled",
				want:            true,
			}
		},
	}
	for name, prep := range tests {
		tc := prep(t)
		t.Run(name, func(t *testing.T) {
			h := &Handler{
				auth:    tc.auth,
				adminDB: tc.adminDB,
				acmeDB:  nil,
			}
			got, prov, err := h.provisionerHasEABEnabled(context.TODO(), tc.provisionerName)
			if (err != nil) != (tc.err != nil) {
				t.Errorf("Handler.provisionerHasEABEnabled() error = %v, want err %v", err, tc.err)
				return
			}
			if tc.err != nil {
				assert.Type(t, &linkedca.Provisioner{}, prov)
				assert.Type(t, &admin.Error{}, err)
				adminError, _ := err.(*admin.Error)
				assert.Equals(t, tc.err.Type, adminError.Type)
				assert.Equals(t, tc.err.Status, adminError.Status)
				assert.Equals(t, tc.err.StatusCode(), adminError.StatusCode())
				assert.Equals(t, tc.err.Message, adminError.Message)
				assert.Equals(t, tc.err.Detail, adminError.Detail)
				return
			}
			if got != tc.want {
				t.Errorf("Handler.provisionerHasEABEnabled() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCreateExternalAccountKeyRequest_Validate(t *testing.T) {
	type fields struct {
		Reference string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "fail/reference-too-long",
			fields: fields{
				Reference: strings.Repeat("A", 257),
			},
			wantErr: true,
		},
		{
			name: "ok/empty-reference",
			fields: fields{
				Reference: "",
			},
			wantErr: false,
		},
		{
			name: "ok",
			fields: fields{
				Reference: "my-eab-reference",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &CreateExternalAccountKeyRequest{
				Reference: tt.fields.Reference,
			}
			if err := r.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("CreateExternalAccountKeyRequest.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestHandler_CreateExternalAccountKey(t *testing.T) {
	type test struct {
		ctx        context.Context
		statusCode int
		err        *admin.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"ok": func(t *testing.T) test {
			chiCtx := chi.NewRouteContext()
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			return test{
				ctx:        ctx,
				statusCode: 501,
				err: &admin.Error{
					Type:    admin.ErrorNotImplementedType.String(),
					Status:  http.StatusNotImplemented,
					Message: "this functionality is currently only available in Certificate Manager: https://smallstep.com/signup?product=cm",
					Detail:  "not implemented",
				},
			}
		},
	}
	for name, prep := range tests {
		tc := prep(t)
		t.Run(name, func(t *testing.T) {

			req := httptest.NewRequest("POST", "/foo", nil) // chi routing is prepared in test setup
			req = req.WithContext(tc.ctx)
			w := httptest.NewRecorder()
			acmeResponder := NewACMEAdminResponder()
			acmeResponder.CreateExternalAccountKey(w, req)
			res := w.Result()
			assert.Equals(t, tc.statusCode, res.StatusCode)

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

		})
	}
}

func TestHandler_DeleteExternalAccountKey(t *testing.T) {
	type test struct {
		ctx        context.Context
		statusCode int
		err        *admin.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"ok": func(t *testing.T) test {
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("provisionerName", "provName")
			chiCtx.URLParams.Add("id", "keyID")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			return test{
				ctx:        ctx,
				statusCode: 501,
				err: &admin.Error{
					Type:    admin.ErrorNotImplementedType.String(),
					Status:  http.StatusNotImplemented,
					Message: "this functionality is currently only available in Certificate Manager: https://smallstep.com/signup?product=cm",
					Detail:  "not implemented",
				},
			}
		},
	}
	for name, prep := range tests {
		tc := prep(t)
		t.Run(name, func(t *testing.T) {

			req := httptest.NewRequest("DELETE", "/foo", nil) // chi routing is prepared in test setup
			req = req.WithContext(tc.ctx)
			w := httptest.NewRecorder()
			acmeResponder := NewACMEAdminResponder()
			acmeResponder.DeleteExternalAccountKey(w, req)
			res := w.Result()
			assert.Equals(t, tc.statusCode, res.StatusCode)

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
		})
	}
}

func TestHandler_GetExternalAccountKeys(t *testing.T) {
	type test struct {
		ctx        context.Context
		statusCode int
		req        *http.Request
		err        *admin.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"ok": func(t *testing.T) test {
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("provisionerName", "provName")
			req := httptest.NewRequest("GET", "/foo", nil)
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			return test{
				ctx:        ctx,
				statusCode: 501,
				req:        req,
				err: &admin.Error{
					Type:    admin.ErrorNotImplementedType.String(),
					Status:  http.StatusNotImplemented,
					Message: "this functionality is currently only available in Certificate Manager: https://smallstep.com/signup?product=cm",
					Detail:  "not implemented",
				},
			}
		},
	}
	for name, prep := range tests {
		tc := prep(t)
		t.Run(name, func(t *testing.T) {

			req := tc.req.WithContext(tc.ctx)
			w := httptest.NewRecorder()
			acmeResponder := NewACMEAdminResponder()
			acmeResponder.GetExternalAccountKeys(w, req)

			res := w.Result()
			assert.Equals(t, tc.statusCode, res.StatusCode)

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
		})
	}
}
