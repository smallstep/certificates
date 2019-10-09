package authority

import (
	"net/http"
	"testing"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/authority/provisioner"
)

func TestGetEncryptedKey(t *testing.T) {
	type ek struct {
		a   *Authority
		kid string
		err *apiError
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
				a:   a,
				kid: "foo",
				err: &apiError{errors.Errorf("encrypted key with kid foo was not found"),
					http.StatusNotFound, apiCtx{}},
			}
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)

			ek, err := tc.a.GetEncryptedKey(tc.kid)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					switch v := err.(type) {
					case *apiError:
						assert.HasPrefix(t, v.err.Error(), tc.err.Error())
						assert.Equals(t, v.code, tc.err.code)
						assert.Equals(t, v.context, tc.err.context)
					default:
						t.Errorf("unexpected error type: %T", v)
					}
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
		a   *Authority
		err *apiError
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
					switch v := err.(type) {
					case *apiError:
						assert.HasPrefix(t, v.err.Error(), tc.err.Error())
						assert.Equals(t, v.code, tc.err.code)
						assert.Equals(t, v.context, tc.err.context)
					default:
						t.Errorf("unexpected error type: %T", v)
					}
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
