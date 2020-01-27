package authority

import (
	"net/http"
	"testing"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/errs"
)

func TestGetEncryptedKey(t *testing.T) {
	type ek struct {
		a    *Authority
		kid  string
		err  error
		code int
	}
	tests := map[string]func(t *testing.T) *ek{
		"ok": func(t *testing.T) *ek {
			c, err := LoadConfiguration("../ca/testdata/ca.json")
			assert.FatalError(t, err)
			a, err := New(c)
			assert.FatalError(t, err)
			return &ek{
				a:   a,
				kid: c.AuthorityConfig.Provisioners[1].(*provisioner.JWK).Key.KeyID,
			}
		},
		"fail-not-found": func(t *testing.T) *ek {
			c, err := LoadConfiguration("../ca/testdata/ca.json")
			assert.FatalError(t, err)
			a, err := New(c)
			assert.FatalError(t, err)
			return &ek{
				a:    a,
				kid:  "foo",
				err:  errors.New("encrypted key with kid foo was not found"),
				code: http.StatusNotFound,
			}
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)

			ek, err := tc.a.GetEncryptedKey(tc.kid)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					sc, ok := err.(errs.StatusCoder)
					assert.Fatal(t, ok, "error does not implement StatusCoder interface")
					assert.Equals(t, sc.StatusCode(), tc.code)
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					val, ok := tc.a.provisioners.Load("max:" + tc.kid)
					assert.Fatal(t, ok)
					p, ok := val.(*provisioner.JWK)
					assert.Fatal(t, ok)
					assert.Equals(t, p.EncryptedKey, ek)
				}
			}
		})
	}
}

func TestGetProvisioners(t *testing.T) {
	type gp struct {
		a    *Authority
		err  error
		code int
	}
	tests := map[string]func(t *testing.T) *gp{
		"ok": func(t *testing.T) *gp {
			c, err := LoadConfiguration("../ca/testdata/ca.json")
			assert.FatalError(t, err)
			a, err := New(c)
			assert.FatalError(t, err)
			return &gp{a: a}
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)

			ps, next, err := tc.a.GetProvisioners("", 0)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					sc, ok := err.(errs.StatusCoder)
					assert.Fatal(t, ok, "error does not implement StatusCoder interface")
					assert.Equals(t, sc.StatusCode(), tc.code)
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, ps, tc.a.config.AuthorityConfig.Provisioners)
					assert.Equals(t, "", next)
				}
			}
		})
	}
}
