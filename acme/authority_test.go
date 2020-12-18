package acme

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/nosql/database"
	"go.step.sm/crypto/jose"
)

func TestAuthorityGetLink(t *testing.T) {
	auth, err := NewAuthority(new(db.MockNoSQLDB), "ca.smallstep.com", "acme", nil)
	assert.FatalError(t, err)
	prov := newProv()
	provName := url.PathEscape(prov.GetName())
	baseURL := &url.URL{Scheme: "https", Host: "test.ca.smallstep.com"}
	ctx := context.WithValue(context.Background(), ProvisionerContextKey, prov)
	ctx = context.WithValue(ctx, BaseURLContextKey, baseURL)
	type test struct {
		auth   *Authority
		typ    Link
		abs    bool
		inputs []string
		res    string
	}
	tests := map[string]func(t *testing.T) test{
		"ok/new-account/abs": func(t *testing.T) test {
			return test{
				auth: auth,
				typ:  NewAccountLink,
				abs:  true,
				res:  fmt.Sprintf("%s/acme/%s/new-account", baseURL.String(), provName),
			}
		},
		"ok/new-account/no-abs": func(t *testing.T) test {
			return test{
				auth: auth,
				typ:  NewAccountLink,
				abs:  false,
				res:  fmt.Sprintf("/%s/new-account", provName),
			}
		},
		"ok/order/abs": func(t *testing.T) test {
			return test{
				auth:   auth,
				typ:    OrderLink,
				abs:    true,
				inputs: []string{"foo"},
				res:    fmt.Sprintf("%s/acme/%s/order/foo", baseURL.String(), provName),
			}
		},
		"ok/order/no-abs": func(t *testing.T) test {
			return test{
				auth:   auth,
				typ:    OrderLink,
				abs:    false,
				inputs: []string{"foo"},
				res:    fmt.Sprintf("/%s/order/foo", provName),
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			link := tc.auth.GetLink(ctx, tc.typ, tc.abs, tc.inputs...)
			assert.Equals(t, tc.res, link)
		})
	}
}

func TestAuthorityGetDirectory(t *testing.T) {
	auth, err := NewAuthority(new(db.MockNoSQLDB), "ca.smallstep.com", "acme", nil)
	assert.FatalError(t, err)

	prov := newProv()
	baseURL := &url.URL{Scheme: "https", Host: "test.ca.smallstep.com"}
	ctx := context.WithValue(context.Background(), ProvisionerContextKey, prov)
	ctx = context.WithValue(ctx, BaseURLContextKey, baseURL)

	type test struct {
		ctx context.Context
		err *Error
	}
	tests := map[string]func(t *testing.T) test{
		"ok/empty-provisioner": func(t *testing.T) test {
			return test{
				ctx: context.Background(),
			}
		},
		"ok/no-baseURL": func(t *testing.T) test {
			return test{
				ctx: context.WithValue(context.Background(), ProvisionerContextKey, prov),
			}
		},
		"ok/baseURL": func(t *testing.T) test {
			return test{
				ctx: ctx,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if dir, err := auth.GetDirectory(tc.ctx); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					bu := BaseURLFromContext(tc.ctx)
					if bu == nil {
						bu = &url.URL{Scheme: "https", Host: "ca.smallstep.com"}
					}

					var provName string
					prov, err := ProvisionerFromContext(tc.ctx)
					if err != nil {
						provName = ""
					} else {
						provName = url.PathEscape(prov.GetName())
					}

					assert.Equals(t, dir.NewNonce, fmt.Sprintf("%s/acme/%s/new-nonce", bu.String(), provName))
					assert.Equals(t, dir.NewAccount, fmt.Sprintf("%s/acme/%s/new-account", bu.String(), provName))
					assert.Equals(t, dir.NewOrder, fmt.Sprintf("%s/acme/%s/new-order", bu.String(), provName))
					assert.Equals(t, dir.RevokeCert, fmt.Sprintf("%s/acme/%s/revoke-cert", bu.String(), provName))
					assert.Equals(t, dir.KeyChange, fmt.Sprintf("%s/acme/%s/key-change", bu.String(), provName))
				}
			}
		})
	}
}

func TestAuthorityNewNonce(t *testing.T) {
	type test struct {
		auth *Authority
		res  *string
		err  *Error
	}
	tests := map[string]func(t *testing.T) test{
		"fail/newNonce-error": func(t *testing.T) test {
			auth, err := NewAuthority(&db.MockNoSQLDB{
				MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
					return nil, false, errors.New("force")
				},
			}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth: auth,
				res:  nil,
				err:  ServerInternalErr(errors.New("error storing nonce: force")),
			}
		},
		"ok": func(t *testing.T) test {
			var _res string
			res := &_res
			auth, err := NewAuthority(&db.MockNoSQLDB{
				MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
					*res = string(key)
					return nil, true, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth: auth,
				res:  res,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if nonce, err := tc.auth.NewNonce(); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, nonce, *tc.res)
				}
			}
		})
	}
}

func TestAuthorityUseNonce(t *testing.T) {
	type test struct {
		auth *Authority
		err  *Error
	}
	tests := map[string]func(t *testing.T) test{
		"fail/newNonce-error": func(t *testing.T) test {
			auth, err := NewAuthority(&db.MockNoSQLDB{
				MUpdate: func(tx *database.Tx) error {
					return errors.New("force")
				},
			}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth: auth,
				err:  ServerInternalErr(errors.New("error deleting nonce foo: force")),
			}
		},
		"ok": func(t *testing.T) test {
			auth, err := NewAuthority(&db.MockNoSQLDB{
				MUpdate: func(tx *database.Tx) error {
					return nil
				},
			}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth: auth,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if err := tc.auth.UseNonce("foo"); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

func TestAuthorityNewAccount(t *testing.T) {
	jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
	assert.FatalError(t, err)
	ops := AccountOptions{
		Key: jwk, Contact: []string{"foo", "bar"},
	}
	prov := newProv()
	ctx := context.WithValue(context.Background(), ProvisionerContextKey, prov)
	ctx = context.WithValue(ctx, BaseURLContextKey, "https://test.ca.smallstep.com:8080")
	type test struct {
		auth *Authority
		ops  AccountOptions
		err  *Error
		acc  **Account
	}
	tests := map[string]func(t *testing.T) test{
		"fail/newAccount-error": func(t *testing.T) test {
			auth, err := NewAuthority(&db.MockNoSQLDB{
				MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
					return nil, false, errors.New("force")
				},
			}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth: auth,
				ops:  ops,
				err:  ServerInternalErr(errors.New("error setting key-id to account-id index: force")),
			}
		},
		"ok": func(t *testing.T) test {
			var (
				_acmeacc = &Account{}
				acmeacc  = &_acmeacc
				count    = 0
				dir      = newDirectory("ca.smallstep.com", "acme")
			)
			auth, err := NewAuthority(&db.MockNoSQLDB{
				MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
					if count == 1 {
						var acc *account
						assert.FatalError(t, json.Unmarshal(newval, &acc))
						*acmeacc, err = acc.toACME(ctx, nil, dir)
						return nil, true, nil
					}
					count++
					return nil, true, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth: auth,
				ops:  ops,
				acc:  acmeacc,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if acmeAcc, err := tc.auth.NewAccount(ctx, tc.ops); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					gotb, err := json.Marshal(acmeAcc)
					assert.FatalError(t, err)
					expb, err := json.Marshal(*tc.acc)
					assert.FatalError(t, err)
					assert.Equals(t, expb, gotb)
				}
			}
		})
	}
}

func TestAuthorityGetAccount(t *testing.T) {
	prov := newProv()
	ctx := context.WithValue(context.Background(), ProvisionerContextKey, prov)
	ctx = context.WithValue(ctx, BaseURLContextKey, "https://test.ca.smallstep.com:8080")
	type test struct {
		auth *Authority
		id   string
		err  *Error
		acc  *account
	}
	tests := map[string]func(t *testing.T) test{
		"fail/getAccount-error": func(t *testing.T) test {
			id := "foo"
			auth, err := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, accountTable)
					assert.Equals(t, key, []byte(id))
					return nil, errors.New("force")
				},
			}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth: auth,
				id:   id,
				err:  ServerInternalErr(errors.Errorf("error loading account %s: force", id)),
			}
		},
		"ok": func(t *testing.T) test {
			acc, err := newAcc()
			assert.FatalError(t, err)
			b, err := json.Marshal(acc)
			assert.FatalError(t, err)
			auth, err := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					return b, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth: auth,
				id:   acc.ID,
				acc:  acc,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if acmeAcc, err := tc.auth.GetAccount(ctx, tc.id); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					gotb, err := json.Marshal(acmeAcc)
					assert.FatalError(t, err)

					acmeExp, err := tc.acc.toACME(ctx, nil, tc.auth.dir)
					assert.FatalError(t, err)
					expb, err := json.Marshal(acmeExp)
					assert.FatalError(t, err)

					assert.Equals(t, expb, gotb)
				}
			}
		})
	}
}

func TestAuthorityGetAccountByKey(t *testing.T) {
	prov := newProv()
	ctx := context.WithValue(context.Background(), ProvisionerContextKey, prov)
	ctx = context.WithValue(ctx, BaseURLContextKey, "https://test.ca.smallstep.com:8080")
	type test struct {
		auth *Authority
		jwk  *jose.JSONWebKey
		err  *Error
		acc  *account
	}
	tests := map[string]func(t *testing.T) test{
		"fail/generate-thumbprint-error": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			jwk.Key = "foo"
			auth, err := NewAuthority(new(db.MockNoSQLDB), "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth: auth,
				jwk:  jwk,
				err:  ServerInternalErr(errors.New("error generating jwk thumbprint: square/go-jose: unknown key type 'string'")),
			}
		},
		"fail/getAccount-error": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			kid, err := keyToID(jwk)
			assert.FatalError(t, err)
			auth, err := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, accountByKeyIDTable)
					assert.Equals(t, key, []byte(kid))
					return nil, errors.New("force")
				},
			}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth: auth,
				jwk:  jwk,
				err:  ServerInternalErr(errors.New("error loading key-account index: force")),
			}
		},
		"ok": func(t *testing.T) test {
			acc, err := newAcc()
			assert.FatalError(t, err)
			b, err := json.Marshal(acc)
			assert.FatalError(t, err)
			count := 0
			kid, err := keyToID(acc.Key)
			assert.FatalError(t, err)
			auth, err := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					var ret []byte
					switch {
					case count == 0:
						assert.Equals(t, bucket, accountByKeyIDTable)
						assert.Equals(t, key, []byte(kid))
						ret = []byte(acc.ID)
					case count == 1:
						assert.Equals(t, bucket, accountTable)
						assert.Equals(t, key, []byte(acc.ID))
						ret = b
					}
					count++
					return ret, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth: auth,
				jwk:  acc.Key,
				acc:  acc,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if acmeAcc, err := tc.auth.GetAccountByKey(ctx, tc.jwk); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					gotb, err := json.Marshal(acmeAcc)
					assert.FatalError(t, err)

					acmeExp, err := tc.acc.toACME(ctx, nil, tc.auth.dir)
					assert.FatalError(t, err)
					expb, err := json.Marshal(acmeExp)
					assert.FatalError(t, err)

					assert.Equals(t, expb, gotb)
				}
			}
		})
	}
}

func TestAuthorityGetOrder(t *testing.T) {
	prov := newProv()
	ctx := context.WithValue(context.Background(), ProvisionerContextKey, prov)
	ctx = context.WithValue(ctx, BaseURLContextKey, "https://test.ca.smallstep.com:8080")
	type test struct {
		auth      *Authority
		id, accID string
		err       *Error
		o         *order
	}
	tests := map[string]func(t *testing.T) test{
		"fail/getOrder-error": func(t *testing.T) test {
			id := "foo"
			auth, err := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, orderTable)
					assert.Equals(t, key, []byte(id))
					return nil, errors.New("force")
				},
			}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth: auth,
				id:   id,
				err:  ServerInternalErr(errors.New("error loading order foo: force")),
			}
		},
		"fail/order-not-owned-by-account": func(t *testing.T) test {
			o, err := newO()
			assert.FatalError(t, err)
			b, err := json.Marshal(o)
			assert.FatalError(t, err)
			auth, err := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, orderTable)
					assert.Equals(t, key, []byte(o.ID))
					return b, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth:  auth,
				id:    o.ID,
				accID: "foo",
				err:   UnauthorizedErr(errors.New("account does not own order")),
			}
		},
		"fail/updateStatus-error": func(t *testing.T) test {
			o, err := newO()
			assert.FatalError(t, err)
			b, err := json.Marshal(o)
			assert.FatalError(t, err)
			i := 0
			auth, err := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					switch {
					case i == 0:
						i++
						assert.Equals(t, bucket, orderTable)
						assert.Equals(t, key, []byte(o.ID))
						return b, nil
					default:
						assert.Equals(t, bucket, authzTable)
						assert.Equals(t, key, []byte(o.Authorizations[0]))
						return nil, ServerInternalErr(errors.New("force"))
					}
				},
			}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth:  auth,
				id:    o.ID,
				accID: o.AccountID,
				err:   ServerInternalErr(errors.Errorf("error loading authz %s: force", o.Authorizations[0])),
			}
		},
		"ok": func(t *testing.T) test {
			o, err := newO()
			assert.FatalError(t, err)
			o.Status = "valid"
			b, err := json.Marshal(o)
			assert.FatalError(t, err)
			auth, err := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, orderTable)
					assert.Equals(t, key, []byte(o.ID))
					return b, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth:  auth,
				id:    o.ID,
				accID: o.AccountID,
				o:     o,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if acmeO, err := tc.auth.GetOrder(ctx, tc.accID, tc.id); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					gotb, err := json.Marshal(acmeO)
					assert.FatalError(t, err)

					acmeExp, err := tc.o.toACME(ctx, nil, tc.auth.dir)
					assert.FatalError(t, err)
					expb, err := json.Marshal(acmeExp)
					assert.FatalError(t, err)

					assert.Equals(t, expb, gotb)
				}
			}
		})
	}
}

func TestAuthorityGetCertificate(t *testing.T) {
	type test struct {
		auth      *Authority
		id, accID string
		err       *Error
		cert      *certificate
	}
	tests := map[string]func(t *testing.T) test{
		"fail/getCertificate-error": func(t *testing.T) test {
			id := "foo"
			auth, err := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, certTable)
					assert.Equals(t, key, []byte(id))
					return nil, errors.New("force")
				},
			}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth: auth,
				id:   id,
				err:  ServerInternalErr(errors.New("error loading certificate: force")),
			}
		},
		"fail/certificate-not-owned-by-account": func(t *testing.T) test {
			cert, err := newcert()
			assert.FatalError(t, err)
			b, err := json.Marshal(cert)
			assert.FatalError(t, err)
			auth, err := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, certTable)
					assert.Equals(t, key, []byte(cert.ID))
					return b, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth:  auth,
				id:    cert.ID,
				accID: "foo",
				err:   UnauthorizedErr(errors.New("account does not own certificate")),
			}
		},
		"ok": func(t *testing.T) test {
			cert, err := newcert()
			assert.FatalError(t, err)
			b, err := json.Marshal(cert)
			assert.FatalError(t, err)
			auth, err := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, certTable)
					assert.Equals(t, key, []byte(cert.ID))
					return b, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth:  auth,
				id:    cert.ID,
				accID: cert.AccountID,
				cert:  cert,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if acmeCert, err := tc.auth.GetCertificate(tc.accID, tc.id); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					gotb, err := json.Marshal(acmeCert)
					assert.FatalError(t, err)

					acmeExp, err := tc.cert.toACME(nil, tc.auth.dir)
					assert.FatalError(t, err)
					expb, err := json.Marshal(acmeExp)
					assert.FatalError(t, err)

					assert.Equals(t, expb, gotb)
				}
			}
		})
	}
}

func TestAuthorityGetAuthz(t *testing.T) {
	prov := newProv()
	ctx := context.WithValue(context.Background(), ProvisionerContextKey, prov)
	ctx = context.WithValue(ctx, BaseURLContextKey, "https://test.ca.smallstep.com:8080")
	type test struct {
		auth      *Authority
		id, accID string
		err       *Error
		acmeAz    *Authz
	}
	tests := map[string]func(t *testing.T) test{
		"fail/getAuthz-error": func(t *testing.T) test {
			id := "foo"
			auth, err := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, authzTable)
					assert.Equals(t, key, []byte(id))
					return nil, errors.New("force")
				},
			}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth: auth,
				id:   id,
				err:  ServerInternalErr(errors.Errorf("error loading authz %s: force", id)),
			}
		},
		"fail/authz-not-owned-by-account": func(t *testing.T) test {
			az, err := newAz()
			assert.FatalError(t, err)
			b, err := json.Marshal(az)
			assert.FatalError(t, err)
			auth, err := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, authzTable)
					assert.Equals(t, key, []byte(az.getID()))
					return b, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth:  auth,
				id:    az.getID(),
				accID: "foo",
				err:   UnauthorizedErr(errors.New("account does not own authz")),
			}
		},
		"fail/update-status-error": func(t *testing.T) test {
			az, err := newAz()
			assert.FatalError(t, err)
			b, err := json.Marshal(az)
			assert.FatalError(t, err)
			count := 0
			auth, err := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					var ret []byte
					switch count {
					case 0:
						assert.Equals(t, bucket, authzTable)
						assert.Equals(t, key, []byte(az.getID()))
						ret = b
					case 1:
						assert.Equals(t, bucket, challengeTable)
						assert.Equals(t, key, []byte(az.getChallenges()[0]))
						return nil, errors.New("force")
					}
					count++
					return ret, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth:  auth,
				id:    az.getID(),
				accID: az.getAccountID(),
				err:   ServerInternalErr(errors.New("error updating authz status: error loading challenge")),
			}
		},
		"ok": func(t *testing.T) test {
			var ch1B, ch2B, ch3B = &[]byte{}, &[]byte{}, &[]byte{}
			count := 0
			mockdb := &db.MockNoSQLDB{
				MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
					switch count {
					case 0:
						*ch1B = newval
					case 1:
						*ch2B = newval
					case 2:
						*ch3B = newval
					}
					count++
					return nil, true, nil
				},
			}
			az, err := newAuthz(mockdb, "1234", Identifier{
				Type: "dns", Value: "acme.example.com",
			})
			assert.FatalError(t, err)
			_az, ok := az.(*dnsAuthz)
			assert.Fatal(t, ok)
			_az.baseAuthz.Status = StatusValid
			b, err := json.Marshal(az)
			assert.FatalError(t, err)

			ch1, err := unmarshalChallenge(*ch1B)
			assert.FatalError(t, err)
			ch2, err := unmarshalChallenge(*ch2B)
			assert.FatalError(t, err)
			ch3, err := unmarshalChallenge(*ch3B)
			assert.FatalError(t, err)
			count = 0
			mockdb = &db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					var ret []byte
					switch count {
					case 0:
						assert.Equals(t, bucket, challengeTable)
						assert.Equals(t, key, []byte(ch1.getID()))
						ret = *ch1B
					case 1:
						assert.Equals(t, bucket, challengeTable)
						assert.Equals(t, key, []byte(ch2.getID()))
						ret = *ch2B
					case 2:
						assert.Equals(t, bucket, challengeTable)
						assert.Equals(t, key, []byte(ch3.getID()))
						ret = *ch3B
					}
					count++
					return ret, nil
				},
			}
			acmeAz, err := az.toACME(ctx, mockdb, newDirectory("ca.smallstep.com", "acme"))
			assert.FatalError(t, err)

			count = 0
			auth, err := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					var ret []byte
					switch count {
					case 0:
						assert.Equals(t, bucket, authzTable)
						assert.Equals(t, key, []byte(az.getID()))
						ret = b
					case 1:
						assert.Equals(t, bucket, challengeTable)
						assert.Equals(t, key, []byte(ch1.getID()))
						ret = *ch1B
					case 2:
						assert.Equals(t, bucket, challengeTable)
						assert.Equals(t, key, []byte(ch2.getID()))
						ret = *ch2B
					case 3:
						assert.Equals(t, bucket, challengeTable)
						assert.Equals(t, key, []byte(ch3.getID()))
						ret = *ch3B
					}
					count++
					return ret, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth:   auth,
				id:     az.getID(),
				accID:  az.getAccountID(),
				acmeAz: acmeAz,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if acmeAz, err := tc.auth.GetAuthz(ctx, tc.accID, tc.id); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					gotb, err := json.Marshal(acmeAz)
					assert.FatalError(t, err)

					expb, err := json.Marshal(tc.acmeAz)
					assert.FatalError(t, err)

					assert.Equals(t, expb, gotb)
				}
			}
		})
	}
}

func TestAuthorityNewOrder(t *testing.T) {
	prov := newProv()
	ctx := context.WithValue(context.Background(), ProvisionerContextKey, prov)
	ctx = context.WithValue(ctx, BaseURLContextKey, "https://test.ca.smallstep.com:8080")
	type test struct {
		auth *Authority
		ops  OrderOptions
		ctx  context.Context
		err  *Error
		o    **Order
	}
	tests := map[string]func(t *testing.T) test{
		"fail/no-provisioner": func(t *testing.T) test {
			auth, err := NewAuthority(&db.MockNoSQLDB{}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth: auth,
				ops:  defaultOrderOps(),
				ctx:  context.Background(),
				err:  ServerInternalErr(errors.New("provisioner expected in request context")),
			}
		},
		"fail/newOrder-error": func(t *testing.T) test {
			auth, err := NewAuthority(&db.MockNoSQLDB{
				MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
					return nil, false, errors.New("force")
				},
			}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth: auth,
				ops:  defaultOrderOps(),
				ctx:  ctx,
				err:  ServerInternalErr(errors.New("error creating order: error creating http challenge: error saving acme challenge: force")),
			}
		},
		"ok": func(t *testing.T) test {
			var (
				_acmeO = &Order{}
				acmeO  = &_acmeO
				count  = 0
				dir    = newDirectory("ca.smallstep.com", "acme")
				err    error
				_accID string
				accID  = &_accID
			)
			auth, err := NewAuthority(&db.MockNoSQLDB{
				MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
					switch count {
					case 0:
						assert.Equals(t, bucket, challengeTable)
					case 1:
						assert.Equals(t, bucket, challengeTable)
					case 2:
						assert.Equals(t, bucket, challengeTable)
					case 3:
						assert.Equals(t, bucket, authzTable)
					case 4:
						assert.Equals(t, bucket, challengeTable)
					case 5:
						assert.Equals(t, bucket, challengeTable)
					case 6:
						assert.Equals(t, bucket, challengeTable)
					case 7:
						assert.Equals(t, bucket, authzTable)
					case 8:
						assert.Equals(t, bucket, orderTable)
						var o order
						assert.FatalError(t, json.Unmarshal(newval, &o))
						*acmeO, err = o.toACME(ctx, nil, dir)
						assert.FatalError(t, err)
						*accID = o.AccountID
					case 9:
						assert.Equals(t, bucket, ordersByAccountIDTable)
						assert.Equals(t, string(key), *accID)
					}
					count++
					return nil, true, nil
				},
				MGet: func(bucket, key []byte) ([]byte, error) {
					return nil, database.ErrNotFound
				},
			}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth: auth,
				ops:  defaultOrderOps(),
				ctx:  ctx,
				o:    acmeO,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if acmeO, err := tc.auth.NewOrder(tc.ctx, tc.ops); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					gotb, err := json.Marshal(acmeO)
					assert.FatalError(t, err)
					expb, err := json.Marshal(*tc.o)
					assert.FatalError(t, err)
					assert.Equals(t, expb, gotb)
				}
			}
		})
	}
}

func TestAuthorityGetOrdersByAccount(t *testing.T) {
	prov := newProv()
	provName := url.PathEscape(prov.GetName())
	baseURL := &url.URL{Scheme: "https", Host: "test.ca.smallstep.com"}
	ctx := context.WithValue(context.Background(), ProvisionerContextKey, prov)
	ctx = context.WithValue(ctx, BaseURLContextKey, baseURL)
	type test struct {
		auth *Authority
		id   string
		err  *Error
		res  []string
	}
	tests := map[string]func(t *testing.T) test{
		"fail/getOrderIDsByAccount-error": func(t *testing.T) test {
			id := "foo"
			auth, err := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, ordersByAccountIDTable)
					assert.Equals(t, key, []byte(id))
					return nil, errors.New("force")
				},
			}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth: auth,
				id:   id,
				err:  ServerInternalErr(errors.New("error loading orderIDs for account foo: force")),
			}
		},
		"fail/getOrder-error": func(t *testing.T) test {
			var (
				id    = "zap"
				oids  = []string{"foo", "bar"}
				count = 0
				err   error
			)
			auth, err := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					var ret []byte
					switch count {
					case 0:
						assert.Equals(t, bucket, ordersByAccountIDTable)
						assert.Equals(t, key, []byte(id))
						ret, err = json.Marshal(oids)
						assert.FatalError(t, err)
					case 1:
						assert.Equals(t, bucket, orderTable)
						assert.Equals(t, key, []byte(oids[0]))
						return nil, errors.New("force")
					}
					count++
					return ret, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth: auth,
				id:   id,
				err:  ServerInternalErr(errors.New("error loading order foo for account zap: error loading order foo: force")),
			}
		},
		"ok": func(t *testing.T) test {
			accID := "zap"

			foo, err := newO()
			assert.FatalError(t, err)
			bfoo, err := json.Marshal(foo)
			assert.FatalError(t, err)

			bar, err := newO()
			assert.FatalError(t, err)
			bar.Status = StatusInvalid
			bbar, err := json.Marshal(bar)
			assert.FatalError(t, err)

			zap, err := newO()
			assert.FatalError(t, err)
			bzap, err := json.Marshal(zap)
			assert.FatalError(t, err)

			az, err := newAz()
			assert.FatalError(t, err)
			baz, err := json.Marshal(az)
			assert.FatalError(t, err)

			ch, err := newDNSCh()
			assert.FatalError(t, err)
			bch, err := json.Marshal(ch)
			assert.FatalError(t, err)

			dbGetOrder := 0
			auth, err := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					switch string(bucket) {
					case string(orderTable):
						dbGetOrder++
						switch dbGetOrder {
						case 1:
							return bfoo, nil
						case 2:
							return bbar, nil
						case 3:
							return bzap, nil
						}
					case string(ordersByAccountIDTable):
						assert.Equals(t, bucket, ordersByAccountIDTable)
						assert.Equals(t, key, []byte(accID))
						ret, err := json.Marshal([]string{foo.ID, bar.ID, zap.ID})
						assert.FatalError(t, err)
						return ret, nil
					case string(challengeTable):
						return bch, nil
					case string(authzTable):
						return baz, nil
					}
					return nil, errors.Errorf("should not be query db table %s", bucket)
				},
				MCmpAndSwap: func(bucket, key, old, newVal []byte) ([]byte, bool, error) {
					assert.Equals(t, bucket, ordersByAccountIDTable)
					assert.Equals(t, string(key), accID)
					return nil, true, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth: auth,
				id:   accID,
				res: []string{
					fmt.Sprintf("%s/acme/%s/order/%s", baseURL.String(), provName, foo.ID),
					fmt.Sprintf("%s/acme/%s/order/%s", baseURL.String(), provName, zap.ID),
				},
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if orderLinks, err := tc.auth.GetOrdersByAccount(ctx, tc.id); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, tc.res, orderLinks)
				}
			}
		})
	}
}

func TestAuthorityFinalizeOrder(t *testing.T) {
	prov := newProv()
	ctx := context.WithValue(context.Background(), ProvisionerContextKey, prov)
	ctx = context.WithValue(ctx, BaseURLContextKey, "https://test.ca.smallstep.com:8080")
	type test struct {
		auth      *Authority
		id, accID string
		ctx       context.Context
		err       *Error
		o         *order
	}
	tests := map[string]func(t *testing.T) test{
		"fail/no-provisioner": func(t *testing.T) test {
			auth, err := NewAuthority(&db.MockNoSQLDB{}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth: auth,
				id:   "foo",
				ctx:  context.Background(),
				err:  ServerInternalErr(errors.New("provisioner expected in request context")),
			}
		},
		"fail/getOrder-error": func(t *testing.T) test {
			id := "foo"
			auth, err := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, orderTable)
					assert.Equals(t, key, []byte(id))
					return nil, errors.New("force")
				},
			}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth: auth,
				id:   id,
				ctx:  ctx,
				err:  ServerInternalErr(errors.New("error loading order foo: force")),
			}
		},
		"fail/order-not-owned-by-account": func(t *testing.T) test {
			o, err := newO()
			assert.FatalError(t, err)
			b, err := json.Marshal(o)
			assert.FatalError(t, err)
			auth, err := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, orderTable)
					assert.Equals(t, key, []byte(o.ID))
					return b, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth:  auth,
				id:    o.ID,
				accID: "foo",
				ctx:   ctx,
				err:   UnauthorizedErr(errors.New("account does not own order")),
			}
		},
		"fail/finalize-error": func(t *testing.T) test {
			o, err := newO()
			assert.FatalError(t, err)
			o.Expires = time.Now().Add(-time.Minute)
			b, err := json.Marshal(o)
			assert.FatalError(t, err)
			auth, err := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, orderTable)
					assert.Equals(t, key, []byte(o.ID))
					return b, nil
				},
				MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
					assert.Equals(t, bucket, orderTable)
					assert.Equals(t, key, []byte(o.ID))
					return nil, false, errors.New("force")
				},
			}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth:  auth,
				id:    o.ID,
				accID: o.AccountID,
				ctx:   ctx,
				err:   ServerInternalErr(errors.New("error finalizing order: error storing order: force")),
			}
		},
		"ok": func(t *testing.T) test {
			o, err := newO()
			assert.FatalError(t, err)
			o.Status = StatusValid
			o.Certificate = "certID"
			b, err := json.Marshal(o)
			assert.FatalError(t, err)
			auth, err := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, orderTable)
					assert.Equals(t, key, []byte(o.ID))
					return b, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth:  auth,
				id:    o.ID,
				accID: o.AccountID,
				ctx:   ctx,
				o:     o,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if acmeO, err := tc.auth.FinalizeOrder(tc.ctx, tc.accID, tc.id, nil); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					gotb, err := json.Marshal(acmeO)
					assert.FatalError(t, err)

					acmeExp, err := tc.o.toACME(ctx, nil, tc.auth.dir)
					assert.FatalError(t, err)
					expb, err := json.Marshal(acmeExp)
					assert.FatalError(t, err)

					assert.Equals(t, expb, gotb)
				}
			}
		})
	}
}

func TestAuthorityValidateChallenge(t *testing.T) {
	prov := newProv()
	ctx := context.WithValue(context.Background(), ProvisionerContextKey, prov)
	ctx = context.WithValue(ctx, BaseURLContextKey, "https://test.ca.smallstep.com:8080")

	type test struct {
		auth      *Authority
		id, accID string
		err       *Error
		ch        challenge
		jwk       *jose.JSONWebKey
		server    *httptest.Server
	}
	tests := map[string]func(t *testing.T) test{
		"fail/getChallenge-error": func(t *testing.T) test {
			id := "foo"
			auth, err := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, challengeTable)
					assert.Equals(t, key, []byte(id))
					return nil, errors.New("force")
				},
			}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth: auth,
				id:   id,
				err:  ServerInternalErr(errors.Errorf("error loading challenge %s: force", id)),
			}
		},
		"fail/challenge-not-owned-by-account": func(t *testing.T) test {
			ch, err := newHTTPCh()
			assert.FatalError(t, err)
			b, err := json.Marshal(ch)
			assert.FatalError(t, err)
			auth, err := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, challengeTable)
					assert.Equals(t, key, []byte(ch.getID()))
					return b, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth:  auth,
				id:    ch.getID(),
				accID: "foo",
				err:   UnauthorizedErr(errors.New("account does not own challenge")),
			}
		},
		"fail/validate-error": func(t *testing.T) test {
			keyauth := "temp"
			keyauthp := &keyauth
			// Create test server that returns challenge auth
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, "%s\r\n", *keyauthp)
			}))
			t.Cleanup(func() { ts.Close() })

			ch, err := newHTTPChWithServer(strings.TrimPrefix(ts.URL, "http://"))
			assert.FatalError(t, err)

			jwk, _, err := jose.GenerateDefaultKeyPair([]byte("pass"))
			assert.FatalError(t, err)

			thumbprint, err := jwk.Thumbprint(crypto.SHA256)
			assert.FatalError(t, err)
			encPrint := base64.RawURLEncoding.EncodeToString(thumbprint)
			*keyauthp = fmt.Sprintf("%s.%s", ch.getToken(), encPrint)

			b, err := json.Marshal(ch)
			assert.FatalError(t, err)
			auth, err := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, challengeTable)
					assert.Equals(t, key, []byte(ch.getID()))
					return b, nil
				},
				MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
					assert.Equals(t, bucket, challengeTable)
					assert.Equals(t, key, []byte(ch.getID()))
					return nil, false, errors.New("force")
				},
			}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth:   auth,
				id:     ch.getID(),
				accID:  ch.getAccountID(),
				jwk:    jwk,
				server: ts,
				err:    ServerInternalErr(errors.New("error attempting challenge validation: error saving acme challenge: force")),
			}
		},
		"ok/already-valid": func(t *testing.T) test {
			ch, err := newHTTPCh()
			assert.FatalError(t, err)
			_ch, ok := ch.(*http01Challenge)
			assert.Fatal(t, ok)
			_ch.baseChallenge.Status = StatusValid
			_ch.baseChallenge.Validated = clock.Now()
			b, err := json.Marshal(ch)
			assert.FatalError(t, err)
			auth, err := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, challengeTable)
					assert.Equals(t, key, []byte(ch.getID()))
					return b, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth:  auth,
				id:    ch.getID(),
				accID: ch.getAccountID(),
				ch:    ch,
			}
		},
		"ok": func(t *testing.T) test {
			keyauth := "temp"
			keyauthp := &keyauth
			// Create test server that returns challenge auth
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, "%s\r\n", *keyauthp)
			}))
			t.Cleanup(func() { ts.Close() })

			ch, err := newHTTPChWithServer(strings.TrimPrefix(ts.URL, "http://"))
			assert.FatalError(t, err)

			jwk, _, err := jose.GenerateDefaultKeyPair([]byte("pass"))
			assert.FatalError(t, err)

			thumbprint, err := jwk.Thumbprint(crypto.SHA256)
			assert.FatalError(t, err)
			encPrint := base64.RawURLEncoding.EncodeToString(thumbprint)
			*keyauthp = fmt.Sprintf("%s.%s", ch.getToken(), encPrint)

			b, err := json.Marshal(ch)
			assert.FatalError(t, err)
			auth, err := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, challengeTable)
					assert.Equals(t, key, []byte(ch.getID()))
					return b, nil
				},
				MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
					assert.Equals(t, bucket, challengeTable)
					assert.Equals(t, key, []byte(ch.getID()))
					return nil, true, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth:   auth,
				id:     ch.getID(),
				accID:  ch.getAccountID(),
				jwk:    jwk,
				server: ts,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if acmeCh, err := tc.auth.ValidateChallenge(ctx, tc.accID, tc.id, tc.jwk); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					gotb, err := json.Marshal(acmeCh)
					assert.FatalError(t, err)

					if tc.ch != nil {
						acmeExp, err := tc.ch.toACME(ctx, nil, tc.auth.dir)
						assert.FatalError(t, err)
						expb, err := json.Marshal(acmeExp)
						assert.FatalError(t, err)

						assert.Equals(t, expb, gotb)
					}
				}
			}
		})
	}
}

func TestAuthorityUpdateAccount(t *testing.T) {
	contact := []string{"baz", "zap"}
	prov := newProv()
	ctx := context.WithValue(context.Background(), ProvisionerContextKey, prov)
	ctx = context.WithValue(ctx, BaseURLContextKey, "https://test.ca.smallstep.com:8080")
	type test struct {
		auth    *Authority
		id      string
		contact []string
		acc     *account
		err     *Error
	}
	tests := map[string]func(t *testing.T) test{
		"fail/getAccount-error": func(t *testing.T) test {
			id := "foo"
			auth, err := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, accountTable)
					assert.Equals(t, key, []byte(id))
					return nil, errors.New("force")
				},
			}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth:    auth,
				id:      id,
				contact: contact,
				err:     ServerInternalErr(errors.Errorf("error loading account %s: force", id)),
			}
		},
		"fail/update-error": func(t *testing.T) test {
			acc, err := newAcc()
			assert.FatalError(t, err)
			b, err := json.Marshal(acc)
			assert.FatalError(t, err)

			auth, err := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					return b, nil
				},
				MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
					return nil, false, errors.New("force")
				},
			}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth:    auth,
				id:      acc.ID,
				contact: contact,
				err:     ServerInternalErr(errors.New("error storing account: force")),
			}
		},

		"ok": func(t *testing.T) test {
			acc, err := newAcc()
			assert.FatalError(t, err)
			b, err := json.Marshal(acc)
			assert.FatalError(t, err)

			_acc := *acc
			clone := &_acc
			clone.Contact = contact
			auth, err := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					return b, nil
				},
				MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
					assert.Equals(t, bucket, accountTable)
					assert.Equals(t, key, []byte(acc.ID))
					return nil, true, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth:    auth,
				id:      acc.ID,
				contact: contact,
				acc:     clone,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if acmeAcc, err := tc.auth.UpdateAccount(ctx, tc.id, tc.contact); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					gotb, err := json.Marshal(acmeAcc)
					assert.FatalError(t, err)

					acmeExp, err := tc.acc.toACME(ctx, nil, tc.auth.dir)
					assert.FatalError(t, err)
					expb, err := json.Marshal(acmeExp)
					assert.FatalError(t, err)

					assert.Equals(t, expb, gotb)
				}
			}
		})
	}
}

func TestAuthorityDeactivateAccount(t *testing.T) {
	prov := newProv()
	ctx := context.WithValue(context.Background(), ProvisionerContextKey, prov)
	ctx = context.WithValue(ctx, BaseURLContextKey, "https://test.ca.smallstep.com:8080")
	type test struct {
		auth *Authority
		id   string
		acc  *account
		err  *Error
	}
	tests := map[string]func(t *testing.T) test{
		"fail/getAccount-error": func(t *testing.T) test {
			id := "foo"
			auth, err := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, accountTable)
					assert.Equals(t, key, []byte(id))
					return nil, errors.New("force")
				},
			}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth: auth,
				id:   id,
				err:  ServerInternalErr(errors.Errorf("error loading account %s: force", id)),
			}
		},
		"fail/deactivate-error": func(t *testing.T) test {
			acc, err := newAcc()
			assert.FatalError(t, err)
			b, err := json.Marshal(acc)
			assert.FatalError(t, err)

			auth, err := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					return b, nil
				},
				MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
					return nil, false, errors.New("force")
				},
			}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth: auth,
				id:   acc.ID,
				err:  ServerInternalErr(errors.New("error storing account: force")),
			}
		},

		"ok": func(t *testing.T) test {
			acc, err := newAcc()
			assert.FatalError(t, err)
			b, err := json.Marshal(acc)
			assert.FatalError(t, err)

			_acc := *acc
			clone := &_acc
			clone.Status = StatusDeactivated
			clone.Deactivated = clock.Now()
			auth, err := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					return b, nil
				},
				MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
					assert.Equals(t, bucket, accountTable)
					assert.Equals(t, key, []byte(acc.ID))
					return nil, true, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			assert.FatalError(t, err)
			return test{
				auth: auth,
				id:   acc.ID,
				acc:  clone,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if acmeAcc, err := tc.auth.DeactivateAccount(ctx, tc.id); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					gotb, err := json.Marshal(acmeAcc)
					assert.FatalError(t, err)

					acmeExp, err := tc.acc.toACME(ctx, nil, tc.auth.dir)
					assert.FatalError(t, err)
					expb, err := json.Marshal(acmeExp)
					assert.FatalError(t, err)

					assert.Equals(t, expb, gotb)
				}
			}
		})
	}
}
