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

	"github.com/go-chi/chi"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/authority/provisioner"
	"go.step.sm/linkedca"
)

func TestHandler_requireEABEnabled(t *testing.T) {
	type test struct {
		ctx        context.Context
		db         admin.DB
		auth       api.LinkedAuthority
		next       nextHTTP
		err        *admin.Error
		statusCode int
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/h.provisionerHasEABEnabled": func(t *testing.T) test {
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("prov", "provName")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			auth := &api.MockAuthority{
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
			chiCtx.URLParams.Add("prov", "provName")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			auth := &api.MockAuthority{
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
				db:         db,
				err:        err,
				statusCode: 400,
			}
		},
		"ok/eab-enabled": func(t *testing.T) test {
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("prov", "provName")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			auth := &api.MockAuthority{
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
				ctx:  ctx,
				auth: auth,
				db:   db,
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
				db:     tc.db,
				auth:   tc.auth,
				acmeDB: nil,
			}

			req := httptest.NewRequest("GET", "/foo", nil) // chi routing is prepared in test setup
			req = req.WithContext(tc.ctx)
			w := httptest.NewRecorder()
			h.requireEABEnabled(tc.next)(w, req)
			res := w.Result()

			assert.Equals(t, res.StatusCode, tc.statusCode)

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

			// nothing to test when the requireEABEnabled middleware succeeds, currently
		})
	}
}

func TestHandler_provisionerHasEABEnabled(t *testing.T) {
	type test struct {
		db              admin.DB
		auth            api.LinkedAuthority
		provisionerName string
		want            bool
		err             *admin.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/auth.LoadProvisionerByName": func(t *testing.T) test {
			auth := &api.MockAuthority{
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
			auth := &api.MockAuthority{
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
				db:              db,
				provisionerName: "provName",
				want:            false,
				err:             admin.WrapErrorISE(errors.New("force"), "error loading provisioner provName"),
			}
		},
		"fail/prov.GetDetails": func(t *testing.T) test {
			auth := &api.MockAuthority{
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
				db:              db,
				provisionerName: "provName",
				want:            false,
				err:             admin.WrapErrorISE(errors.New("force"), "error loading provisioner provName"),
			}
		},
		"fail/details.GetACME": func(t *testing.T) test {
			auth := &api.MockAuthority{
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
				db:              db,
				provisionerName: "provName",
				want:            false,
				err:             admin.WrapErrorISE(errors.New("force"), "error loading provisioner provName"),
			}
		},
		"ok/eab-disabled": func(t *testing.T) test {
			auth := &api.MockAuthority{
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
				db:              db,
				auth:            auth,
				provisionerName: "eab-disabled",
				want:            false,
			}
		},
		"ok/eab-enabled": func(t *testing.T) test {
			auth := &api.MockAuthority{
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
				db:              db,
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
				db:     tc.db,
				auth:   tc.auth,
				acmeDB: nil,
			}
			got, err := h.provisionerHasEABEnabled(context.TODO(), tc.provisionerName)
			if (err != nil) != (tc.err != nil) {
				t.Errorf("Handler.provisionerHasEABEnabled() error = %v, want err %v", err, tc.err)
				return
			}
			if tc.err != nil {
				// TODO(hs): the output of the diff seems to be equal to each other; not sure why it's marked as different =/
				// opts := []cmp.Option{cmpopts.EquateErrors()}
				// if !cmp.Equal(tc.err, err, opts...) {
				// 	t.Errorf("Handler.provisionerHasEABEnabled() diff =\n%v", cmp.Diff(tc.err, err, opts...))
				// }
				assert.Equals(t, tc.err.Type, err.Type)
				assert.Equals(t, tc.err.Status, err.Status)
				assert.Equals(t, tc.err.StatusCode(), err.StatusCode())
				assert.Equals(t, tc.err.Message, err.Message)
				assert.Equals(t, tc.err.Detail, err.Detail)
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
