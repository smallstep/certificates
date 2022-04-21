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

	"google.golang.org/protobuf/encoding/protojson"

	"go.step.sm/linkedca"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/admin"
)

func TestPolicyAdminResponder_GetAuthorityPolicy(t *testing.T) {
	type test struct {
		auth           adminAuthority
		deploymentType string
		adminDB        admin.DB
		ctx            context.Context
		err            *admin.Error
		policy         *linkedca.Policy
		statusCode     int
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/linkedca": func(t *testing.T) test {
			ctx := context.Background()
			err := admin.NewError(admin.ErrorNotImplementedType, "policy operations not yet supported in linked deployments")
			err.Message = "policy operations not yet supported in linked deployments"
			return test{
				ctx:            ctx,
				deploymentType: "linked",
				err:            err,
				statusCode:     501,
			}
		},
		"fail/auth.GetAuthorityPolicy-error": func(t *testing.T) test {
			ctx := context.Background()
			err := admin.WrapErrorISE(errors.New("force"), "error retrieving authority policy")
			err.Message = "error retrieving authority policy: force"
			return test{
				ctx: ctx,
				auth: &mockAdminAuthority{
					MockGetAuthorityPolicy: func(ctx context.Context) (*linkedca.Policy, error) {
						return nil, admin.NewError(admin.ErrorServerInternalType, "force")
					},
				},
				err:        err,
				statusCode: 500,
			}
		},
		"fail/auth.GetAuthorityPolicy-not-found": func(t *testing.T) test {
			ctx := context.Background()
			err := admin.NewError(admin.ErrorNotFoundType, "authority policy does not exist")
			err.Message = "authority policy does not exist"
			return test{
				ctx: ctx,
				auth: &mockAdminAuthority{
					MockGetAuthorityPolicy: func(ctx context.Context) (*linkedca.Policy, error) {
						return nil, admin.NewError(admin.ErrorNotFoundType, "not found")
					},
				},
				err:        err,
				statusCode: 404,
			}
		},
		"ok": func(t *testing.T) test {
			ctx := context.Background()
			policy := &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns: []string{"*.local"},
					},
				},
			}
			return test{
				ctx: ctx,
				auth: &mockAdminAuthority{
					MockGetAuthorityPolicy: func(ctx context.Context) (*linkedca.Policy, error) {
						return policy, nil
					},
				},
				policy:     policy,
				statusCode: 200,
			}
		},
	}
	for name, prep := range tests {
		tc := prep(t)
		t.Run(name, func(t *testing.T) {
			par := &PolicyAdminResponder{
				auth:           tc.auth,
				adminDB:        tc.adminDB,
				deploymentType: tc.deploymentType,
			}

			req := httptest.NewRequest("GET", "/foo", nil)
			req = req.WithContext(tc.ctx)
			w := httptest.NewRecorder()

			par.GetAuthorityPolicy(w, req)
			res := w.Result()

			assert.Equals(t, tc.statusCode, res.StatusCode)

			if res.StatusCode >= 400 {

				body, err := io.ReadAll(res.Body)
				res.Body.Close()
				assert.FatalError(t, err)

				ae := admin.Error{}
				assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &ae))

				assert.Equals(t, tc.err.Type, ae.Type)
				assert.Equals(t, tc.err.Message, ae.Message)
				assert.Equals(t, tc.err.StatusCode(), res.StatusCode)
				assert.Equals(t, tc.err.Detail, ae.Detail)
				assert.Equals(t, []string{"application/json"}, res.Header["Content-Type"])
				return
			}

			p := &linkedca.Policy{}
			assert.FatalError(t, readProtoJSON(res.Body, p))
			assert.Equals(t, tc.policy, p)

		})
	}
}

func TestPolicyAdminResponder_CreateAuthorityPolicy(t *testing.T) {
	type test struct {
		auth           adminAuthority
		deploymentType string
		adminDB        admin.DB
		body           []byte
		ctx            context.Context
		acmeDB         acme.DB
		err            *admin.Error
		policy         *linkedca.Policy
		statusCode     int
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/linkedca": func(t *testing.T) test {
			ctx := context.Background()
			err := admin.NewError(admin.ErrorNotImplementedType, "policy operations not yet supported in linked deployments")
			err.Message = "policy operations not yet supported in linked deployments"
			return test{
				ctx:            ctx,
				deploymentType: "linked",
				err:            err,
				statusCode:     501,
			}
		},
		"fail/auth.GetAuthorityPolicy-error": func(t *testing.T) test {
			ctx := context.Background()
			err := admin.WrapErrorISE(errors.New("force"), "error retrieving authority policy")
			err.Message = "error retrieving authority policy: force"
			return test{
				ctx: ctx,
				auth: &mockAdminAuthority{
					MockGetAuthorityPolicy: func(ctx context.Context) (*linkedca.Policy, error) {
						return nil, admin.NewError(admin.ErrorServerInternalType, "force")
					},
				},
				err:        err,
				statusCode: 500,
			}
		},
		"fail/existing-policy": func(t *testing.T) test {
			ctx := context.Background()
			err := admin.NewError(admin.ErrorConflictType, "authority already has a policy")
			err.Message = "authority already has a policy"
			return test{
				ctx: ctx,
				auth: &mockAdminAuthority{
					MockGetAuthorityPolicy: func(ctx context.Context) (*linkedca.Policy, error) {
						return &linkedca.Policy{}, nil
					},
				},
				err:        err,
				statusCode: 409,
			}
		},
		"fail/read.ProtoJSON": func(t *testing.T) test {
			ctx := context.Background()
			adminErr := admin.NewError(admin.ErrorBadRequestType, "proto: syntax error (line 1:2): invalid value ?")
			adminErr.Message = "proto: syntax error (line 1:2): invalid value ?"
			body := []byte("{?}")
			return test{
				ctx: ctx,
				auth: &mockAdminAuthority{
					MockGetAuthorityPolicy: func(ctx context.Context) (*linkedca.Policy, error) {
						return nil, admin.NewError(admin.ErrorNotFoundType, "not found")
					},
				},
				body:       body,
				err:        adminErr,
				statusCode: 400,
			}
		},
		"fail/CreateAuthorityPolicy-policy-admin-lockout-error": func(t *testing.T) test {
			adm := &linkedca.Admin{
				Subject: "step",
			}
			ctx := context.Background()
			ctx = linkedca.NewContextWithAdmin(ctx, adm)
			adminErr := admin.NewError(admin.ErrorBadRequestType, "error storing authority policy")
			adminErr.Message = "error storing authority policy: admin lock out"
			policy := &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns: []string{"*.local"},
					},
				},
			}
			body, err := protojson.Marshal(policy)
			assert.FatalError(t, err)
			return test{
				ctx: ctx,
				auth: &mockAdminAuthority{
					MockGetAuthorityPolicy: func(ctx context.Context) (*linkedca.Policy, error) {
						return nil, admin.NewError(admin.ErrorNotFoundType, "not found")
					},
					MockCreateAuthorityPolicy: func(ctx context.Context, adm *linkedca.Admin, policy *linkedca.Policy) (*linkedca.Policy, error) {
						return nil, &authority.PolicyError{
							Typ: authority.AdminLockOut,
							Err: errors.New("admin lock out"),
						}
					},
				},
				adminDB: &admin.MockDB{
					MockGetAdmins: func(ctx context.Context) ([]*linkedca.Admin, error) {
						return []*linkedca.Admin{
							adm,
							{
								Subject: "anotherAdmin",
							},
						}, nil
					},
				},
				body:       body,
				err:        adminErr,
				statusCode: 400,
			}
		},
		"fail/CreateAuthorityPolicy-error": func(t *testing.T) test {
			adm := &linkedca.Admin{
				Subject: "step",
			}
			ctx := context.Background()
			ctx = linkedca.NewContextWithAdmin(ctx, adm)
			adminErr := admin.NewError(admin.ErrorServerInternalType, "error storing authority policy: force")
			adminErr.Message = "error storing authority policy: force"
			policy := &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns: []string{"*.local"},
					},
				},
			}
			body, err := protojson.Marshal(policy)
			assert.FatalError(t, err)
			return test{
				ctx: ctx,
				auth: &mockAdminAuthority{
					MockGetAuthorityPolicy: func(ctx context.Context) (*linkedca.Policy, error) {
						return nil, admin.NewError(admin.ErrorNotFoundType, "not found")
					},
					MockCreateAuthorityPolicy: func(ctx context.Context, adm *linkedca.Admin, policy *linkedca.Policy) (*linkedca.Policy, error) {
						return nil, &authority.PolicyError{
							Typ: authority.StoreFailure,
							Err: errors.New("force"),
						}
					},
				},
				adminDB: &admin.MockDB{
					MockGetAdmins: func(ctx context.Context) ([]*linkedca.Admin, error) {
						return []*linkedca.Admin{
							adm,
							{
								Subject: "anotherAdmin",
							},
						}, nil
					},
				},
				body:       body,
				err:        adminErr,
				statusCode: 500,
			}
		},
		"ok": func(t *testing.T) test {
			adm := &linkedca.Admin{
				Subject: "step",
			}
			ctx := context.Background()
			ctx = linkedca.NewContextWithAdmin(ctx, adm)
			policy := &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns: []string{"*.local"},
					},
					DisableSubjectCommonNameVerification: false,
				},
			}
			body, err := protojson.Marshal(policy)
			assert.FatalError(t, err)
			return test{
				ctx: ctx,
				auth: &mockAdminAuthority{
					MockGetAuthorityPolicy: func(ctx context.Context) (*linkedca.Policy, error) {
						return nil, admin.NewError(admin.ErrorNotFoundType, "not found")
					},
					MockCreateAuthorityPolicy: func(ctx context.Context, adm *linkedca.Admin, policy *linkedca.Policy) (*linkedca.Policy, error) {
						return policy, nil
					},
				},
				adminDB: &admin.MockDB{
					MockGetAdmins: func(ctx context.Context) ([]*linkedca.Admin, error) {
						return []*linkedca.Admin{
							adm,
							{
								Subject: "anotherAdmin",
							},
						}, nil
					},
				},
				body:       body,
				policy:     policy,
				statusCode: 201,
			}
		},
	}
	for name, prep := range tests {
		tc := prep(t)
		t.Run(name, func(t *testing.T) {
			par := &PolicyAdminResponder{
				auth:           tc.auth,
				adminDB:        tc.adminDB,
				acmeDB:         tc.acmeDB,
				deploymentType: tc.deploymentType,
			}

			req := httptest.NewRequest("POST", "/foo", io.NopCloser(bytes.NewBuffer(tc.body)))
			req = req.WithContext(tc.ctx)
			w := httptest.NewRecorder()

			par.CreateAuthorityPolicy(w, req)
			res := w.Result()

			assert.Equals(t, tc.statusCode, res.StatusCode)

			if res.StatusCode >= 400 {

				body, err := io.ReadAll(res.Body)
				res.Body.Close()
				assert.FatalError(t, err)

				ae := admin.Error{}
				assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &ae))

				assert.Equals(t, tc.err.Type, ae.Type)
				assert.Equals(t, tc.err.StatusCode(), res.StatusCode)
				assert.Equals(t, tc.err.Detail, ae.Detail)
				assert.Equals(t, []string{"application/json"}, res.Header["Content-Type"])

				// when the error message starts with "proto", we expect it to have
				// a syntax error (in the tests). If the message doesn't start with "proto",
				// we expect a full string match.
				if strings.HasPrefix(tc.err.Message, "proto:") {
					assert.True(t, strings.Contains(tc.err.Message, "syntax error"))
				} else {
					assert.Equals(t, tc.err.Message, ae.Message)
				}

				return
			}

			p := &linkedca.Policy{}
			assert.FatalError(t, readProtoJSON(res.Body, p))
			assert.Equals(t, tc.policy, p)

		})
	}
}

func TestPolicyAdminResponder_UpdateAuthorityPolicy(t *testing.T) {
	type test struct {
		auth           adminAuthority
		deploymentType string
		adminDB        admin.DB
		body           []byte
		ctx            context.Context
		acmeDB         acme.DB
		err            *admin.Error
		policy         *linkedca.Policy
		statusCode     int
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/linkedca": func(t *testing.T) test {
			ctx := context.Background()
			err := admin.NewError(admin.ErrorNotImplementedType, "policy operations not yet supported in linked deployments")
			err.Message = "policy operations not yet supported in linked deployments"
			return test{
				ctx:            ctx,
				deploymentType: "linked",
				err:            err,
				statusCode:     501,
			}
		},
		"fail/auth.GetAuthorityPolicy-error": func(t *testing.T) test {
			ctx := context.Background()
			err := admin.WrapErrorISE(errors.New("force"), "error retrieving authority policy")
			err.Message = "error retrieving authority policy: force"
			return test{
				ctx: ctx,
				auth: &mockAdminAuthority{
					MockGetAuthorityPolicy: func(ctx context.Context) (*linkedca.Policy, error) {
						return nil, admin.NewError(admin.ErrorServerInternalType, "force")
					},
				},
				err:        err,
				statusCode: 500,
			}
		},
		"fail/no-existing-policy": func(t *testing.T) test {
			ctx := context.Background()
			err := admin.NewError(admin.ErrorNotFoundType, "authority policy does not exist")
			err.Message = "authority policy does not exist"
			err.Status = http.StatusNotFound
			return test{
				ctx: ctx,
				auth: &mockAdminAuthority{
					MockGetAuthorityPolicy: func(ctx context.Context) (*linkedca.Policy, error) {
						return nil, nil
					},
				},
				err:        err,
				statusCode: 404,
			}
		},
		"fail/read.ProtoJSON": func(t *testing.T) test {
			policy := &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns: []string{"*.local"},
					},
				},
			}
			ctx := context.Background()
			adminErr := admin.NewError(admin.ErrorBadRequestType, "proto: syntax error (line 1:2): invalid value ?")
			adminErr.Message = "proto: syntax error (line 1:2): invalid value ?"
			body := []byte("{?}")
			return test{
				ctx: ctx,
				auth: &mockAdminAuthority{
					MockGetAuthorityPolicy: func(ctx context.Context) (*linkedca.Policy, error) {
						return policy, nil
					},
				},
				body:       body,
				err:        adminErr,
				statusCode: 400,
			}
		},
		"fail/UpdateAuthorityPolicy-policy-admin-lockout-error": func(t *testing.T) test {
			adm := &linkedca.Admin{
				Subject: "step",
			}
			ctx := context.Background()
			ctx = linkedca.NewContextWithAdmin(ctx, adm)
			adminErr := admin.NewError(admin.ErrorBadRequestType, "error updating authority policy: force")
			adminErr.Message = "error updating authority policy: admin lock out"
			policy := &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns: []string{"*.local"},
					},
				},
			}
			body, err := protojson.Marshal(policy)
			assert.FatalError(t, err)
			return test{
				ctx: ctx,
				auth: &mockAdminAuthority{
					MockGetAuthorityPolicy: func(ctx context.Context) (*linkedca.Policy, error) {
						return policy, nil
					},
					MockUpdateAuthorityPolicy: func(ctx context.Context, adm *linkedca.Admin, policy *linkedca.Policy) (*linkedca.Policy, error) {
						return nil, &authority.PolicyError{
							Typ: authority.AdminLockOut,
							Err: errors.New("admin lock out"),
						}
					},
				},
				adminDB: &admin.MockDB{
					MockGetAdmins: func(ctx context.Context) ([]*linkedca.Admin, error) {
						return []*linkedca.Admin{
							adm,
							{
								Subject: "anotherAdmin",
							},
						}, nil
					},
				},
				body:       body,
				err:        adminErr,
				statusCode: 400,
			}
		},
		"fail/UpdateAuthorityPolicy-error": func(t *testing.T) test {
			adm := &linkedca.Admin{
				Subject: "step",
			}
			ctx := context.Background()
			ctx = linkedca.NewContextWithAdmin(ctx, adm)
			adminErr := admin.NewError(admin.ErrorServerInternalType, "error updating authority policy: force")
			adminErr.Message = "error updating authority policy: force"
			policy := &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns: []string{"*.local"},
					},
				},
			}
			body, err := protojson.Marshal(policy)
			assert.FatalError(t, err)
			return test{
				ctx: ctx,
				auth: &mockAdminAuthority{
					MockGetAuthorityPolicy: func(ctx context.Context) (*linkedca.Policy, error) {
						return policy, nil
					},
					MockUpdateAuthorityPolicy: func(ctx context.Context, adm *linkedca.Admin, policy *linkedca.Policy) (*linkedca.Policy, error) {
						return nil, &authority.PolicyError{
							Typ: authority.StoreFailure,
							Err: errors.New("force"),
						}
					},
				},
				adminDB: &admin.MockDB{
					MockGetAdmins: func(ctx context.Context) ([]*linkedca.Admin, error) {
						return []*linkedca.Admin{
							adm,
							{
								Subject: "anotherAdmin",
							},
						}, nil
					},
				},
				body:       body,
				err:        adminErr,
				statusCode: 500,
			}
		},
		"ok": func(t *testing.T) test {
			adm := &linkedca.Admin{
				Subject: "step",
			}
			ctx := context.Background()
			ctx = linkedca.NewContextWithAdmin(ctx, adm)
			policy := &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns: []string{"*.local"},
					},
				},
			}
			body, err := protojson.Marshal(policy)
			assert.FatalError(t, err)
			return test{
				ctx: ctx,
				auth: &mockAdminAuthority{
					MockGetAuthorityPolicy: func(ctx context.Context) (*linkedca.Policy, error) {
						return policy, nil
					},
					MockUpdateAuthorityPolicy: func(ctx context.Context, adm *linkedca.Admin, policy *linkedca.Policy) (*linkedca.Policy, error) {
						return policy, nil
					},
				},
				adminDB: &admin.MockDB{
					MockGetAdmins: func(ctx context.Context) ([]*linkedca.Admin, error) {
						return []*linkedca.Admin{
							adm,
							{
								Subject: "anotherAdmin",
							},
						}, nil
					},
				},
				body:       body,
				policy:     policy,
				statusCode: 200,
			}
		},
	}
	for name, prep := range tests {
		tc := prep(t)
		t.Run(name, func(t *testing.T) {
			par := &PolicyAdminResponder{
				auth:           tc.auth,
				adminDB:        tc.adminDB,
				acmeDB:         tc.acmeDB,
				deploymentType: tc.deploymentType,
			}

			req := httptest.NewRequest("POST", "/foo", io.NopCloser(bytes.NewBuffer(tc.body)))
			req = req.WithContext(tc.ctx)
			w := httptest.NewRecorder()

			par.UpdateAuthorityPolicy(w, req)
			res := w.Result()

			assert.Equals(t, tc.statusCode, res.StatusCode)

			if res.StatusCode >= 400 {

				body, err := io.ReadAll(res.Body)
				res.Body.Close()
				assert.FatalError(t, err)

				ae := admin.Error{}
				assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &ae))

				assert.Equals(t, tc.err.Type, ae.Type)
				assert.Equals(t, tc.err.StatusCode(), res.StatusCode)
				assert.Equals(t, tc.err.Detail, ae.Detail)
				assert.Equals(t, []string{"application/json"}, res.Header["Content-Type"])

				// when the error message starts with "proto", we expect it to have
				// a syntax error (in the tests). If the message doesn't start with "proto",
				// we expect a full string match.
				if strings.HasPrefix(tc.err.Message, "proto:") {
					assert.True(t, strings.Contains(tc.err.Message, "syntax error"))
				} else {
					assert.Equals(t, tc.err.Message, ae.Message)
				}

				return
			}

			p := &linkedca.Policy{}
			assert.FatalError(t, readProtoJSON(res.Body, p))
			assert.Equals(t, tc.policy, p)

		})
	}
}

func TestPolicyAdminResponder_DeleteAuthorityPolicy(t *testing.T) {
	type test struct {
		auth           adminAuthority
		deploymentType string
		adminDB        admin.DB
		body           []byte
		ctx            context.Context
		acmeDB         acme.DB
		err            *admin.Error
		statusCode     int
	}

	var tests = map[string]func(t *testing.T) test{
		"fail/linkedca": func(t *testing.T) test {
			ctx := context.Background()
			err := admin.NewError(admin.ErrorNotImplementedType, "policy operations not yet supported in linked deployments")
			err.Message = "policy operations not yet supported in linked deployments"
			return test{
				ctx:            ctx,
				deploymentType: "linked",
				err:            err,
				statusCode:     501,
			}
		},
		"fail/auth.GetAuthorityPolicy-error": func(t *testing.T) test {
			ctx := context.Background()
			err := admin.WrapErrorISE(errors.New("force"), "error retrieving authority policy")
			err.Message = "error retrieving authority policy: force"
			return test{
				ctx: ctx,
				auth: &mockAdminAuthority{
					MockGetAuthorityPolicy: func(ctx context.Context) (*linkedca.Policy, error) {
						return nil, admin.NewError(admin.ErrorServerInternalType, "force")
					},
				},
				err:        err,
				statusCode: 500,
			}
		},
		"fail/no-existing-policy": func(t *testing.T) test {
			ctx := context.Background()
			err := admin.NewError(admin.ErrorNotFoundType, "authority policy does not exist")
			err.Message = "authority policy does not exist"
			err.Status = http.StatusNotFound
			return test{
				ctx: ctx,
				auth: &mockAdminAuthority{
					MockGetAuthorityPolicy: func(ctx context.Context) (*linkedca.Policy, error) {
						return nil, nil
					},
				},
				err:        err,
				statusCode: 404,
			}
		},
		"fail/auth.RemoveAuthorityPolicy-error": func(t *testing.T) test {
			policy := &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns: []string{"*.local"},
					},
				},
			}
			ctx := context.Background()
			err := admin.NewErrorISE("error deleting authority policy: force")
			err.Message = "error deleting authority policy: force"
			return test{
				ctx: ctx,
				auth: &mockAdminAuthority{
					MockGetAuthorityPolicy: func(ctx context.Context) (*linkedca.Policy, error) {
						return policy, nil
					},
					MockRemoveAuthorityPolicy: func(ctx context.Context) error {
						return errors.New("force")
					},
				},
				err:        err,
				statusCode: 500,
			}
		},
		"ok": func(t *testing.T) test {
			policy := &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns: []string{"*.local"},
					},
				},
			}
			ctx := context.Background()
			return test{
				ctx: ctx,
				auth: &mockAdminAuthority{
					MockGetAuthorityPolicy: func(ctx context.Context) (*linkedca.Policy, error) {
						return policy, nil
					},
					MockRemoveAuthorityPolicy: func(ctx context.Context) error {
						return nil
					},
				},
				statusCode: 200,
			}
		},
	}
	for name, prep := range tests {
		tc := prep(t)
		t.Run(name, func(t *testing.T) {
			par := &PolicyAdminResponder{
				auth:           tc.auth,
				adminDB:        tc.adminDB,
				acmeDB:         tc.acmeDB,
				deploymentType: tc.deploymentType,
			}

			req := httptest.NewRequest("POST", "/foo", io.NopCloser(bytes.NewBuffer(tc.body)))
			req = req.WithContext(tc.ctx)
			w := httptest.NewRecorder()

			par.DeleteAuthorityPolicy(w, req)
			res := w.Result()

			assert.Equals(t, tc.statusCode, res.StatusCode)

			if res.StatusCode >= 400 {

				body, err := io.ReadAll(res.Body)
				res.Body.Close()
				assert.FatalError(t, err)

				ae := admin.Error{}
				assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &ae))

				assert.Equals(t, tc.err.Type, ae.Type)
				assert.Equals(t, tc.err.Message, ae.Message)
				assert.Equals(t, tc.err.StatusCode(), res.StatusCode)
				assert.Equals(t, tc.err.Detail, ae.Detail)
				assert.Equals(t, []string{"application/json"}, res.Header["Content-Type"])
				return
			}

			body, err := io.ReadAll(res.Body)
			assert.FatalError(t, err)
			res.Body.Close()
			response := DeleteResponse{}
			assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &response))
			assert.Equals(t, "ok", response.Status)
			assert.Equals(t, []string{"application/json"}, res.Header["Content-Type"])

		})
	}
}

func TestPolicyAdminResponder_GetProvisionerPolicy(t *testing.T) {
	type test struct {
		auth           adminAuthority
		deploymentType string
		adminDB        admin.DB
		ctx            context.Context
		acmeDB         acme.DB
		err            *admin.Error
		policy         *linkedca.Policy
		statusCode     int
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/linkedca": func(t *testing.T) test {
			ctx := context.Background()
			err := admin.NewError(admin.ErrorNotImplementedType, "policy operations not yet supported in linked deployments")
			err.Message = "policy operations not yet supported in linked deployments"
			return test{
				ctx:            ctx,
				deploymentType: "linked",
				err:            err,
				statusCode:     501,
			}
		},
		"fail/prov-no-policy": func(t *testing.T) test {
			prov := &linkedca.Provisioner{}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			err := admin.NewError(admin.ErrorNotFoundType, "provisioner policy does not exist")
			err.Message = "provisioner policy does not exist"
			return test{
				ctx:        ctx,
				err:        err,
				statusCode: 404,
			}
		},
		"ok": func(t *testing.T) test {
			policy := &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns: []string{"*.local"},
					},
				},
			}
			prov := &linkedca.Provisioner{
				Policy: policy,
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			return test{
				ctx:        ctx,
				policy:     policy,
				statusCode: 200,
			}
		},
	}
	for name, prep := range tests {
		tc := prep(t)
		t.Run(name, func(t *testing.T) {
			par := &PolicyAdminResponder{
				auth:           tc.auth,
				adminDB:        tc.adminDB,
				acmeDB:         tc.acmeDB,
				deploymentType: tc.deploymentType,
			}

			req := httptest.NewRequest("GET", "/foo", nil)
			req = req.WithContext(tc.ctx)
			w := httptest.NewRecorder()

			par.GetProvisionerPolicy(w, req)
			res := w.Result()

			assert.Equals(t, tc.statusCode, res.StatusCode)

			if res.StatusCode >= 400 {

				body, err := io.ReadAll(res.Body)
				res.Body.Close()
				assert.FatalError(t, err)

				ae := admin.Error{}
				assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &ae))

				assert.Equals(t, tc.err.Type, ae.Type)
				assert.Equals(t, tc.err.Message, ae.Message)
				assert.Equals(t, tc.err.StatusCode(), res.StatusCode)
				assert.Equals(t, tc.err.Detail, ae.Detail)
				assert.Equals(t, []string{"application/json"}, res.Header["Content-Type"])
				return
			}

			p := &linkedca.Policy{}
			assert.FatalError(t, readProtoJSON(res.Body, p))
			assert.Equals(t, tc.policy, p)

		})
	}
}

func TestPolicyAdminResponder_CreateProvisionerPolicy(t *testing.T) {
	type test struct {
		auth           adminAuthority
		deploymentType string
		body           []byte
		ctx            context.Context
		err            *admin.Error
		policy         *linkedca.Policy
		statusCode     int
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/linkedca": func(t *testing.T) test {
			ctx := context.Background()
			err := admin.NewError(admin.ErrorNotImplementedType, "policy operations not yet supported in linked deployments")
			err.Message = "policy operations not yet supported in linked deployments"
			return test{
				ctx:            ctx,
				deploymentType: "linked",
				err:            err,
				statusCode:     501,
			}
		},
		"fail/existing-policy": func(t *testing.T) test {
			policy := &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns: []string{"*.local"},
					},
				},
			}
			prov := &linkedca.Provisioner{
				Name:   "provName",
				Policy: policy,
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			err := admin.NewError(admin.ErrorConflictType, "provisioner provName already has a policy")
			err.Message = "provisioner provName already has a policy"
			return test{
				ctx:        ctx,
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
		"fail/auth.UpdateProvisioner-policy-admin-lockout-error": func(t *testing.T) test {
			adm := &linkedca.Admin{
				Subject: "step",
			}
			prov := &linkedca.Provisioner{
				Name: "provName",
			}
			ctx := linkedca.NewContextWithAdmin(context.Background(), adm)
			ctx = linkedca.NewContextWithProvisioner(ctx, prov)
			adminErr := admin.NewError(admin.ErrorBadRequestType, "error creating provisioner policy")
			adminErr.Message = "error creating provisioner policy: admin lock out"
			policy := &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns: []string{"*.local"},
					},
				},
			}
			body, err := protojson.Marshal(policy)
			assert.FatalError(t, err)
			return test{
				ctx: ctx,
				auth: &mockAdminAuthority{
					MockUpdateProvisioner: func(ctx context.Context, nu *linkedca.Provisioner) error {
						return &authority.PolicyError{
							Typ: authority.AdminLockOut,
							Err: errors.New("admin lock out"),
						}
					},
				},
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
			adminErr := admin.NewError(admin.ErrorServerInternalType, "error creating provisioner policy: force")
			adminErr.Message = "error creating provisioner policy: force"
			policy := &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns: []string{"*.local"},
					},
				},
			}
			body, err := protojson.Marshal(policy)
			assert.FatalError(t, err)
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
			adm := &linkedca.Admin{
				Subject: "step",
			}
			prov := &linkedca.Provisioner{
				Name: "provName",
			}
			ctx := linkedca.NewContextWithAdmin(context.Background(), adm)
			ctx = linkedca.NewContextWithProvisioner(ctx, prov)
			policy := &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns: []string{"*.local"},
					},
					DisableSubjectCommonNameVerification: false,
				},
			}
			body, err := protojson.Marshal(policy)
			assert.FatalError(t, err)
			return test{
				ctx: ctx,
				auth: &mockAdminAuthority{
					MockUpdateProvisioner: func(ctx context.Context, nu *linkedca.Provisioner) error {
						return nil
					},
				},
				body:       body,
				policy:     policy,
				statusCode: 201,
			}
		},
	}
	for name, prep := range tests {
		tc := prep(t)
		t.Run(name, func(t *testing.T) {
			par := &PolicyAdminResponder{
				auth:           tc.auth,
				deploymentType: tc.deploymentType,
			}

			req := httptest.NewRequest("POST", "/foo", io.NopCloser(bytes.NewBuffer(tc.body)))
			req = req.WithContext(tc.ctx)
			w := httptest.NewRecorder()

			par.CreateProvisionerPolicy(w, req)
			res := w.Result()

			assert.Equals(t, tc.statusCode, res.StatusCode)

			if res.StatusCode >= 400 {

				body, err := io.ReadAll(res.Body)
				res.Body.Close()
				assert.FatalError(t, err)

				ae := admin.Error{}
				assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &ae))

				assert.Equals(t, tc.err.Type, ae.Type)
				assert.Equals(t, tc.err.StatusCode(), res.StatusCode)
				assert.Equals(t, tc.err.Detail, ae.Detail)
				assert.Equals(t, []string{"application/json"}, res.Header["Content-Type"])

				// when the error message starts with "proto", we expect it to have
				// a syntax error (in the tests). If the message doesn't start with "proto",
				// we expect a full string match.
				if strings.HasPrefix(tc.err.Message, "proto:") {
					assert.True(t, strings.Contains(tc.err.Message, "syntax error"))
				} else {
					assert.Equals(t, tc.err.Message, ae.Message)
				}

				return
			}

			p := &linkedca.Policy{}
			assert.FatalError(t, readProtoJSON(res.Body, p))
			assert.Equals(t, tc.policy, p)

		})
	}
}

func TestPolicyAdminResponder_UpdateProvisionerPolicy(t *testing.T) {
	type test struct {
		auth           adminAuthority
		deploymentType string
		body           []byte
		ctx            context.Context
		err            *admin.Error
		policy         *linkedca.Policy
		statusCode     int
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/linkedca": func(t *testing.T) test {
			ctx := context.Background()
			err := admin.NewError(admin.ErrorNotImplementedType, "policy operations not yet supported in linked deployments")
			err.Message = "policy operations not yet supported in linked deployments"
			return test{
				ctx:            ctx,
				deploymentType: "linked",
				err:            err,
				statusCode:     501,
			}
		},
		"fail/no-existing-policy": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Name: "provName",
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			err := admin.NewError(admin.ErrorNotFoundType, "provisioner policy does not exist")
			err.Message = "provisioner policy does not exist"
			return test{
				ctx:        ctx,
				err:        err,
				statusCode: 404,
			}
		},
		"fail/read.ProtoJSON": func(t *testing.T) test {
			policy := &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns: []string{"*.local"},
					},
				},
			}
			prov := &linkedca.Provisioner{
				Name:   "provName",
				Policy: policy,
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
		"fail/auth.UpdateProvisioner-policy-admin-lockout-error": func(t *testing.T) test {
			adm := &linkedca.Admin{
				Subject: "step",
			}
			policy := &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns: []string{"*.local"},
					},
				},
			}
			prov := &linkedca.Provisioner{
				Name:   "provName",
				Policy: policy,
			}
			ctx := linkedca.NewContextWithAdmin(context.Background(), adm)
			ctx = linkedca.NewContextWithProvisioner(ctx, prov)
			adminErr := admin.NewError(admin.ErrorBadRequestType, "error updating provisioner policy")
			adminErr.Message = "error updating provisioner policy: admin lock out"
			body, err := protojson.Marshal(policy)
			assert.FatalError(t, err)
			return test{
				ctx: ctx,
				auth: &mockAdminAuthority{
					MockUpdateProvisioner: func(ctx context.Context, nu *linkedca.Provisioner) error {
						return &authority.PolicyError{
							Typ: authority.AdminLockOut,
							Err: errors.New("admin lock out"),
						}
					},
				},
				body:       body,
				err:        adminErr,
				statusCode: 400,
			}
		},
		"fail/auth.UpdateProvisioner-error": func(t *testing.T) test {
			adm := &linkedca.Admin{
				Subject: "step",
			}
			policy := &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns: []string{"*.local"},
					},
				},
			}
			prov := &linkedca.Provisioner{
				Name:   "provName",
				Policy: policy,
			}
			ctx := linkedca.NewContextWithAdmin(context.Background(), adm)
			ctx = linkedca.NewContextWithProvisioner(ctx, prov)
			adminErr := admin.NewError(admin.ErrorServerInternalType, "error updating provisioner policy: force")
			adminErr.Message = "error updating provisioner policy: force"
			body, err := protojson.Marshal(policy)
			assert.FatalError(t, err)
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
			adm := &linkedca.Admin{
				Subject: "step",
			}
			policy := &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns: []string{"*.local"},
					},
				},
			}
			prov := &linkedca.Provisioner{
				Name:   "provName",
				Policy: policy,
			}
			ctx := linkedca.NewContextWithAdmin(context.Background(), adm)
			ctx = linkedca.NewContextWithProvisioner(ctx, prov)
			body, err := protojson.Marshal(policy)
			assert.FatalError(t, err)
			return test{
				ctx: ctx,
				auth: &mockAdminAuthority{
					MockUpdateProvisioner: func(ctx context.Context, nu *linkedca.Provisioner) error {
						return nil
					},
				},
				body:       body,
				policy:     policy,
				statusCode: 200,
			}
		},
	}
	for name, prep := range tests {
		tc := prep(t)
		t.Run(name, func(t *testing.T) {
			par := &PolicyAdminResponder{
				auth:           tc.auth,
				deploymentType: tc.deploymentType,
			}

			req := httptest.NewRequest("POST", "/foo", io.NopCloser(bytes.NewBuffer(tc.body)))
			req = req.WithContext(tc.ctx)
			w := httptest.NewRecorder()

			par.UpdateProvisionerPolicy(w, req)
			res := w.Result()

			assert.Equals(t, tc.statusCode, res.StatusCode)

			if res.StatusCode >= 400 {

				body, err := io.ReadAll(res.Body)
				res.Body.Close()
				assert.FatalError(t, err)

				ae := admin.Error{}
				assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &ae))

				assert.Equals(t, tc.err.Type, ae.Type)
				assert.Equals(t, tc.err.StatusCode(), res.StatusCode)
				assert.Equals(t, tc.err.Detail, ae.Detail)
				assert.Equals(t, []string{"application/json"}, res.Header["Content-Type"])

				// when the error message starts with "proto", we expect it to have
				// a syntax error (in the tests). If the message doesn't start with "proto",
				// we expect a full string match.
				if strings.HasPrefix(tc.err.Message, "proto:") {
					assert.True(t, strings.Contains(tc.err.Message, "syntax error"))
				} else {
					assert.Equals(t, tc.err.Message, ae.Message)
				}

				return
			}

			p := &linkedca.Policy{}
			assert.FatalError(t, readProtoJSON(res.Body, p))
			assert.Equals(t, tc.policy, p)

		})
	}
}

func TestPolicyAdminResponder_DeleteProvisionerPolicy(t *testing.T) {
	type test struct {
		auth           adminAuthority
		deploymentType string
		adminDB        admin.DB
		body           []byte
		ctx            context.Context
		acmeDB         acme.DB
		err            *admin.Error
		statusCode     int
	}

	var tests = map[string]func(t *testing.T) test{
		"fail/linkedca": func(t *testing.T) test {
			ctx := context.Background()
			err := admin.NewError(admin.ErrorNotImplementedType, "policy operations not yet supported in linked deployments")
			err.Message = "policy operations not yet supported in linked deployments"
			return test{
				ctx:            ctx,
				deploymentType: "linked",
				err:            err,
				statusCode:     501,
			}
		},
		"fail/no-existing-policy": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Name: "provName",
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			err := admin.NewError(admin.ErrorNotFoundType, "provisioner policy does not exist")
			err.Message = "provisioner policy does not exist"
			return test{
				ctx:        ctx,
				err:        err,
				statusCode: 404,
			}
		},
		"fail/auth.UpdateProvisioner-error": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Name:   "provName",
				Policy: &linkedca.Policy{},
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			err := admin.NewErrorISE("error deleting provisioner policy: force")
			err.Message = "error deleting provisioner policy: force"
			return test{
				ctx: ctx,
				auth: &mockAdminAuthority{
					MockUpdateProvisioner: func(ctx context.Context, nu *linkedca.Provisioner) error {
						return errors.New("force")
					},
				},
				err:        err,
				statusCode: 500,
			}
		},
		"ok": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Name:   "provName",
				Policy: &linkedca.Policy{},
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			return test{
				ctx: ctx,
				auth: &mockAdminAuthority{
					MockUpdateProvisioner: func(ctx context.Context, nu *linkedca.Provisioner) error {
						return nil
					},
				},
				statusCode: 200,
			}
		},
	}
	for name, prep := range tests {
		tc := prep(t)
		t.Run(name, func(t *testing.T) {
			par := &PolicyAdminResponder{
				auth:           tc.auth,
				adminDB:        tc.adminDB,
				acmeDB:         tc.acmeDB,
				deploymentType: tc.deploymentType,
			}

			req := httptest.NewRequest("POST", "/foo", io.NopCloser(bytes.NewBuffer(tc.body)))
			req = req.WithContext(tc.ctx)
			w := httptest.NewRecorder()

			par.DeleteProvisionerPolicy(w, req)
			res := w.Result()

			assert.Equals(t, tc.statusCode, res.StatusCode)

			if res.StatusCode >= 400 {

				body, err := io.ReadAll(res.Body)
				res.Body.Close()
				assert.FatalError(t, err)

				ae := admin.Error{}
				assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &ae))

				assert.Equals(t, tc.err.Type, ae.Type)
				assert.Equals(t, tc.err.Message, ae.Message)
				assert.Equals(t, tc.err.StatusCode(), res.StatusCode)
				assert.Equals(t, tc.err.Detail, ae.Detail)
				assert.Equals(t, []string{"application/json"}, res.Header["Content-Type"])
				return
			}

			body, err := io.ReadAll(res.Body)
			assert.FatalError(t, err)
			res.Body.Close()
			response := DeleteResponse{}
			assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &response))
			assert.Equals(t, "ok", response.Status)
			assert.Equals(t, []string{"application/json"}, res.Header["Content-Type"])

		})
	}
}

func TestPolicyAdminResponder_GetACMEAccountPolicy(t *testing.T) {
	type test struct {
		deploymentType string
		ctx            context.Context
		acmeDB         acme.DB
		err            *admin.Error
		policy         *linkedca.Policy
		statusCode     int
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/linkedca": func(t *testing.T) test {
			ctx := context.Background()
			err := admin.NewError(admin.ErrorNotImplementedType, "policy operations not yet supported in linked deployments")
			err.Message = "policy operations not yet supported in linked deployments"
			return test{
				ctx:            ctx,
				deploymentType: "linked",
				err:            err,
				statusCode:     501,
			}
		},
		"fail/no-policy": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Name: "provName",
			}
			eak := &linkedca.EABKey{
				Id: "eakID",
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			ctx = linkedca.NewContextWithExternalAccountKey(ctx, eak)
			err := admin.NewError(admin.ErrorNotFoundType, "ACME EAK policy does not exist")
			err.Message = "ACME EAK policy does not exist"
			return test{
				ctx:        ctx,
				err:        err,
				statusCode: 404,
			}
		},
		"ok": func(t *testing.T) test {
			policy := &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns: []string{"*.local"},
					},
				},
			}
			prov := &linkedca.Provisioner{
				Name: "provName",
			}
			eak := &linkedca.EABKey{
				Id:     "eakID",
				Policy: policy,
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			ctx = linkedca.NewContextWithExternalAccountKey(ctx, eak)
			return test{
				ctx:        ctx,
				policy:     policy,
				statusCode: 200,
			}
		},
	}
	for name, prep := range tests {
		tc := prep(t)
		t.Run(name, func(t *testing.T) {
			par := &PolicyAdminResponder{
				acmeDB:         tc.acmeDB,
				deploymentType: tc.deploymentType,
			}

			req := httptest.NewRequest("GET", "/foo", nil)
			req = req.WithContext(tc.ctx)
			w := httptest.NewRecorder()

			par.GetACMEAccountPolicy(w, req)
			res := w.Result()

			assert.Equals(t, tc.statusCode, res.StatusCode)

			if res.StatusCode >= 400 {

				body, err := io.ReadAll(res.Body)
				res.Body.Close()
				assert.FatalError(t, err)

				ae := admin.Error{}
				assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &ae))

				assert.Equals(t, tc.err.Type, ae.Type)
				assert.Equals(t, tc.err.Message, ae.Message)
				assert.Equals(t, tc.err.StatusCode(), res.StatusCode)
				assert.Equals(t, tc.err.Detail, ae.Detail)
				assert.Equals(t, []string{"application/json"}, res.Header["Content-Type"])
				return
			}

			p := &linkedca.Policy{}
			assert.FatalError(t, readProtoJSON(res.Body, p))
			assert.Equals(t, tc.policy, p)

		})
	}
}

func TestPolicyAdminResponder_CreateACMEAccountPolicy(t *testing.T) {
	type test struct {
		deploymentType string
		acmeDB         acme.DB
		body           []byte
		ctx            context.Context
		err            *admin.Error
		policy         *linkedca.Policy
		statusCode     int
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/linkedca": func(t *testing.T) test {
			ctx := context.Background()
			err := admin.NewError(admin.ErrorNotImplementedType, "policy operations not yet supported in linked deployments")
			err.Message = "policy operations not yet supported in linked deployments"
			return test{
				ctx:            ctx,
				deploymentType: "linked",
				err:            err,
				statusCode:     501,
			}
		},
		"fail/existing-policy": func(t *testing.T) test {
			policy := &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns: []string{"*.local"},
					},
				},
			}
			prov := &linkedca.Provisioner{
				Name: "provName",
			}
			eak := &linkedca.EABKey{
				Id:     "eakID",
				Policy: policy,
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			ctx = linkedca.NewContextWithExternalAccountKey(ctx, eak)
			err := admin.NewError(admin.ErrorConflictType, "ACME EAK eakID already has a policy")
			err.Message = "ACME EAK eakID already has a policy"
			return test{
				ctx:        ctx,
				err:        err,
				statusCode: 409,
			}
		},
		"fail/read.ProtoJSON": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Name: "provName",
			}
			eak := &linkedca.EABKey{
				Id: "eakID",
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			ctx = linkedca.NewContextWithExternalAccountKey(ctx, eak)
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
		"fail/acmeDB.UpdateExternalAccountKey-error": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Id:   "provID",
				Name: "provName",
			}
			eak := &linkedca.EABKey{
				Id: "eakID",
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			ctx = linkedca.NewContextWithExternalAccountKey(ctx, eak)
			adminErr := admin.NewError(admin.ErrorServerInternalType, "error creating ACME EAK policy")
			adminErr.Message = "error creating ACME EAK policy: force"
			policy := &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns: []string{"*.local"},
					},
				},
			}
			body, err := protojson.Marshal(policy)
			assert.FatalError(t, err)
			return test{
				ctx: ctx,
				acmeDB: &acme.MockDB{
					MockUpdateExternalAccountKey: func(ctx context.Context, provisionerID string, eak *acme.ExternalAccountKey) error {
						assert.Equals(t, "provID", provisionerID)
						assert.Equals(t, "eakID", eak.ID)
						return errors.New("force")
					},
				},
				body:       body,
				err:        adminErr,
				statusCode: 500,
			}
		},
		"ok": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Id:   "provID",
				Name: "provName",
			}
			eak := &linkedca.EABKey{
				Id: "eakID",
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			ctx = linkedca.NewContextWithExternalAccountKey(ctx, eak)
			policy := &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns: []string{"*.local"},
					},
				},
			}
			body, err := protojson.Marshal(policy)
			assert.FatalError(t, err)
			return test{
				ctx: ctx,
				acmeDB: &acme.MockDB{
					MockUpdateExternalAccountKey: func(ctx context.Context, provisionerID string, eak *acme.ExternalAccountKey) error {
						assert.Equals(t, "provID", provisionerID)
						assert.Equals(t, "eakID", eak.ID)
						return nil
					},
				},
				body:       body,
				policy:     policy,
				statusCode: 201,
			}
		},
	}
	for name, prep := range tests {
		tc := prep(t)
		t.Run(name, func(t *testing.T) {
			par := &PolicyAdminResponder{
				acmeDB:         tc.acmeDB,
				deploymentType: tc.deploymentType,
			}

			req := httptest.NewRequest("POST", "/foo", io.NopCloser(bytes.NewBuffer(tc.body)))
			req = req.WithContext(tc.ctx)
			w := httptest.NewRecorder()

			par.CreateACMEAccountPolicy(w, req)
			res := w.Result()

			assert.Equals(t, tc.statusCode, res.StatusCode)

			if res.StatusCode >= 400 {

				body, err := io.ReadAll(res.Body)
				res.Body.Close()
				assert.FatalError(t, err)

				ae := admin.Error{}
				assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &ae))

				assert.Equals(t, tc.err.Type, ae.Type)
				assert.Equals(t, tc.err.StatusCode(), res.StatusCode)
				assert.Equals(t, tc.err.Detail, ae.Detail)
				assert.Equals(t, []string{"application/json"}, res.Header["Content-Type"])

				// when the error message starts with "proto", we expect it to have
				// a syntax error (in the tests). If the message doesn't start with "proto",
				// we expect a full string match.
				if strings.HasPrefix(tc.err.Message, "proto:") {
					assert.True(t, strings.Contains(tc.err.Message, "syntax error"))
				} else {
					assert.Equals(t, tc.err.Message, ae.Message)
				}

				return
			}

			p := &linkedca.Policy{}
			assert.FatalError(t, readProtoJSON(res.Body, p))
			assert.Equals(t, tc.policy, p)

		})
	}
}

func TestPolicyAdminResponder_UpdateACMEAccountPolicy(t *testing.T) {
	type test struct {
		deploymentType string
		acmeDB         acme.DB
		body           []byte
		ctx            context.Context
		err            *admin.Error
		policy         *linkedca.Policy
		statusCode     int
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/linkedca": func(t *testing.T) test {
			ctx := context.Background()
			err := admin.NewError(admin.ErrorNotImplementedType, "policy operations not yet supported in linked deployments")
			err.Message = "policy operations not yet supported in linked deployments"
			return test{
				ctx:            ctx,
				deploymentType: "linked",
				err:            err,
				statusCode:     501,
			}
		},
		"fail/no-existing-policy": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Name: "provName",
			}
			eak := &linkedca.EABKey{
				Id: "eakID",
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			ctx = linkedca.NewContextWithExternalAccountKey(ctx, eak)
			err := admin.NewError(admin.ErrorNotFoundType, "ACME EAK policy does not exist")
			err.Message = "ACME EAK policy does not exist"
			return test{
				ctx:        ctx,
				err:        err,
				statusCode: 404,
			}
		},
		"fail/read.ProtoJSON": func(t *testing.T) test {
			policy := &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns: []string{"*.local"},
					},
				},
			}
			prov := &linkedca.Provisioner{
				Name: "provName",
			}
			eak := &linkedca.EABKey{
				Id:     "eakID",
				Policy: policy,
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			ctx = linkedca.NewContextWithExternalAccountKey(ctx, eak)
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
		"fail/acmeDB.UpdateExternalAccountKey-error": func(t *testing.T) test {
			policy := &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns: []string{"*.local"},
					},
				},
			}
			prov := &linkedca.Provisioner{
				Name: "provName",
				Id:   "provID",
			}
			eak := &linkedca.EABKey{
				Id:     "eakID",
				Policy: policy,
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			ctx = linkedca.NewContextWithExternalAccountKey(ctx, eak)
			adminErr := admin.NewError(admin.ErrorServerInternalType, "error updating ACME EAK policy: force")
			adminErr.Message = "error updating ACME EAK policy: force"
			body, err := protojson.Marshal(policy)
			assert.FatalError(t, err)
			return test{
				ctx: ctx,
				acmeDB: &acme.MockDB{
					MockUpdateExternalAccountKey: func(ctx context.Context, provisionerID string, eak *acme.ExternalAccountKey) error {
						assert.Equals(t, "provID", provisionerID)
						assert.Equals(t, "eakID", eak.ID)
						return errors.New("force")
					},
				},
				body:       body,
				err:        adminErr,
				statusCode: 500,
			}
		},
		"ok": func(t *testing.T) test {
			policy := &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns: []string{"*.local"},
					},
				},
			}
			prov := &linkedca.Provisioner{
				Name: "provName",
				Id:   "provID",
			}
			eak := &linkedca.EABKey{
				Id:     "eakID",
				Policy: policy,
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			ctx = linkedca.NewContextWithExternalAccountKey(ctx, eak)
			body, err := protojson.Marshal(policy)
			assert.FatalError(t, err)
			return test{
				ctx: ctx,
				acmeDB: &acme.MockDB{
					MockUpdateExternalAccountKey: func(ctx context.Context, provisionerID string, eak *acme.ExternalAccountKey) error {
						assert.Equals(t, "provID", provisionerID)
						assert.Equals(t, "eakID", eak.ID)
						return nil
					},
				},
				body:       body,
				policy:     policy,
				statusCode: 200,
			}
		},
	}
	for name, prep := range tests {
		tc := prep(t)
		t.Run(name, func(t *testing.T) {
			par := &PolicyAdminResponder{
				acmeDB:         tc.acmeDB,
				deploymentType: tc.deploymentType,
			}

			req := httptest.NewRequest("POST", "/foo", io.NopCloser(bytes.NewBuffer(tc.body)))
			req = req.WithContext(tc.ctx)
			w := httptest.NewRecorder()

			par.UpdateACMEAccountPolicy(w, req)
			res := w.Result()

			assert.Equals(t, tc.statusCode, res.StatusCode)

			if res.StatusCode >= 400 {

				body, err := io.ReadAll(res.Body)
				res.Body.Close()
				assert.FatalError(t, err)

				ae := admin.Error{}
				assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &ae))

				assert.Equals(t, tc.err.Type, ae.Type)
				assert.Equals(t, tc.err.StatusCode(), res.StatusCode)
				assert.Equals(t, tc.err.Detail, ae.Detail)
				assert.Equals(t, []string{"application/json"}, res.Header["Content-Type"])

				// when the error message starts with "proto", we expect it to have
				// a syntax error (in the tests). If the message doesn't start with "proto",
				// we expect a full string match.
				if strings.HasPrefix(tc.err.Message, "proto:") {
					assert.True(t, strings.Contains(tc.err.Message, "syntax error"))
				} else {
					assert.Equals(t, tc.err.Message, ae.Message)
				}

				return
			}

			p := &linkedca.Policy{}
			assert.FatalError(t, readProtoJSON(res.Body, p))
			assert.Equals(t, tc.policy, p)

		})
	}
}

func TestPolicyAdminResponder_DeleteACMEAccountPolicy(t *testing.T) {
	type test struct {
		deploymentType string
		body           []byte
		ctx            context.Context
		acmeDB         acme.DB
		err            *admin.Error
		statusCode     int
	}

	var tests = map[string]func(t *testing.T) test{
		"fail/linkedca": func(t *testing.T) test {
			ctx := context.Background()
			err := admin.NewError(admin.ErrorNotImplementedType, "policy operations not yet supported in linked deployments")
			err.Message = "policy operations not yet supported in linked deployments"
			return test{
				ctx:            ctx,
				deploymentType: "linked",
				err:            err,
				statusCode:     501,
			}
		},
		"fail/no-existing-policy": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Name: "provName",
			}
			eak := &linkedca.EABKey{
				Id: "eakID",
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			ctx = linkedca.NewContextWithExternalAccountKey(ctx, eak)
			err := admin.NewError(admin.ErrorNotFoundType, "ACME EAK policy does not exist")
			err.Message = "ACME EAK policy does not exist"
			return test{
				ctx:        ctx,
				err:        err,
				statusCode: 404,
			}
		},
		"fail/acmeDB.UpdateExternalAccountKey-error": func(t *testing.T) test {
			policy := &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns: []string{"*.local"},
					},
				},
			}
			prov := &linkedca.Provisioner{
				Name: "provName",
				Id:   "provID",
			}
			eak := &linkedca.EABKey{
				Id:     "eakID",
				Policy: policy,
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			ctx = linkedca.NewContextWithExternalAccountKey(ctx, eak)
			err := admin.NewErrorISE("error deleting ACME EAK policy: force")
			err.Message = "error deleting ACME EAK policy: force"
			return test{
				ctx: ctx,
				acmeDB: &acme.MockDB{
					MockUpdateExternalAccountKey: func(ctx context.Context, provisionerID string, eak *acme.ExternalAccountKey) error {
						assert.Equals(t, "provID", provisionerID)
						assert.Equals(t, "eakID", eak.ID)
						return errors.New("force")
					},
				},
				err:        err,
				statusCode: 500,
			}
		},
		"ok": func(t *testing.T) test {
			policy := &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns: []string{"*.local"},
					},
				},
			}
			prov := &linkedca.Provisioner{
				Name: "provName",
				Id:   "provID",
			}
			eak := &linkedca.EABKey{
				Id:     "eakID",
				Policy: policy,
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			ctx = linkedca.NewContextWithExternalAccountKey(ctx, eak)
			return test{
				ctx: ctx,
				acmeDB: &acme.MockDB{
					MockUpdateExternalAccountKey: func(ctx context.Context, provisionerID string, eak *acme.ExternalAccountKey) error {
						assert.Equals(t, "provID", provisionerID)
						assert.Equals(t, "eakID", eak.ID)
						return nil
					},
				},
				statusCode: 200,
			}
		},
	}
	for name, prep := range tests {
		tc := prep(t)
		t.Run(name, func(t *testing.T) {
			par := &PolicyAdminResponder{
				acmeDB:         tc.acmeDB,
				deploymentType: tc.deploymentType,
			}

			req := httptest.NewRequest("POST", "/foo", io.NopCloser(bytes.NewBuffer(tc.body)))
			req = req.WithContext(tc.ctx)
			w := httptest.NewRecorder()

			par.DeleteACMEAccountPolicy(w, req)
			res := w.Result()

			assert.Equals(t, tc.statusCode, res.StatusCode)

			if res.StatusCode >= 400 {

				body, err := io.ReadAll(res.Body)
				res.Body.Close()
				assert.FatalError(t, err)

				ae := admin.Error{}
				assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &ae))

				assert.Equals(t, tc.err.Type, ae.Type)
				assert.Equals(t, tc.err.Message, ae.Message)
				assert.Equals(t, tc.err.StatusCode(), res.StatusCode)
				assert.Equals(t, tc.err.Detail, ae.Detail)
				assert.Equals(t, []string{"application/json"}, res.Header["Content-Type"])
				return
			}

			body, err := io.ReadAll(res.Body)
			assert.FatalError(t, err)
			res.Body.Close()
			response := DeleteResponse{}
			assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &response))
			assert.Equals(t, "ok", response.Status)
			assert.Equals(t, []string{"application/json"}, res.Header["Content-Type"])

		})
	}
}

func Test_isBadRequest(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil",
			err:  nil,
			want: false,
		},
		{
			name: "no-policy-error",
			err:  errors.New("some error"),
			want: false,
		},
		{
			name: "no-bad-request",
			err: &authority.PolicyError{
				Typ: authority.InternalFailure,
				Err: errors.New("error"),
			},
			want: false,
		},
		{
			name: "bad-request",
			err: &authority.PolicyError{
				Typ: authority.AdminLockOut,
				Err: errors.New("admin lock out"),
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isBadRequest(tt.err); got != tt.want {
				t.Errorf("isBadRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}
