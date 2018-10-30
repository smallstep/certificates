package authority

import (
	"errors"
	"testing"

	"github.com/smallstep/assert"
	jose "gopkg.in/square/go-jose.v2"
)

func TestProvisionerInit(t *testing.T) {
	type ProvisionerValidateTest struct {
		p   *Provisioner
		err error
	}
	tests := map[string]func(*testing.T) ProvisionerValidateTest{
		"fail-empty-name": func(t *testing.T) ProvisionerValidateTest {
			return ProvisionerValidateTest{
				p:   &Provisioner{},
				err: errors.New("provisioner name cannot be empty"),
			}
		},
		"fail-empty-type": func(t *testing.T) ProvisionerValidateTest {
			return ProvisionerValidateTest{
				p:   &Provisioner{Name: "foo"},
				err: errors.New("provisioner type cannot be empty"),
			}
		},
		"fail-empty-key": func(t *testing.T) ProvisionerValidateTest {
			return ProvisionerValidateTest{
				p:   &Provisioner{Name: "foo", Type: "bar"},
				err: errors.New("provisioner key cannot be empty"),
			}
		},
		"ok": func(t *testing.T) ProvisionerValidateTest {
			return ProvisionerValidateTest{
				p: &Provisioner{Name: "foo", Type: "bar", Key: &jose.JSONWebKey{}},
			}
		},
	}

	for name, get := range tests {
		t.Run(name, func(t *testing.T) {
			tc := get(t)
			err := tc.p.Init(&globalProvisionerClaims)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					assert.Equals(t, tc.err.Error(), err.Error())
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}
