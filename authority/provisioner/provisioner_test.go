package provisioner

import (
	"testing"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
)

func TestType_String(t *testing.T) {
	tests := []struct {
		name string
		t    Type
		want string
	}{
		{"JWK", TypeJWK, "JWK"},
		{"OIDC", TypeOIDC, "OIDC"},
		{"AWS", TypeAWS, "AWS"},
		{"Azure", TypeAzure, "Azure"},
		{"GCP", TypeGCP, "GCP"},
		{"noop", noopType, ""},
		{"notFound", 1000, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.t.String(); got != tt.want {
				t.Errorf("Type.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSanitizeSSHUserPrincipal(t *testing.T) {
	type args struct {
		email string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"simple", args{"foobar"}, "foobar"},
		{"camelcase", args{"FooBar"}, "foobar"},
		{"email", args{"foo@example.com"}, "foo"},
		{"email with dots", args{"foo.bar.zar@example.com"}, "foobarzar"},
		{"email with dashes", args{"foo-bar-zar@example.com"}, "foo-bar-zar"},
		{"email with underscores", args{"foo_bar_zar@example.com"}, "foo_bar_zar"},
		{"email with symbols", args{"Foo.Bar0123456789!#$%&'*+-/=?^_`{|}~;@example.com"}, "foobar0123456789________-___________"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SanitizeSSHUserPrincipal(tt.args.email); got != tt.want {
				t.Errorf("SanitizeSSHUserPrincipal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDefaultIdentityFunc(t *testing.T) {
	type test struct {
		p        Interface
		email    string
		err      error
		identity *Identity
	}
	tests := map[string]func(*testing.T) test{
		"fail/unsupported-provisioner": func(t *testing.T) test {
			return test{
				p:   &X5C{},
				err: errors.New("provisioner type '*provisioner.X5C' not supported by identity function"),
			}
		},
		"fail/bad-ssh-regex": func(t *testing.T) test {
			return test{
				p:     &OIDC{},
				email: "$%^#_>@smallstep.com",
				err:   errors.New("invalid principal '______' from email '$%^#_>@smallstep.com'"),
			}
		},
		"ok": func(t *testing.T) test {
			return test{
				p:        &OIDC{},
				email:    "max.furman@smallstep.com",
				identity: &Identity{Usernames: []string{"maxfurman", "max.furman@smallstep.com"}},
			}
		},
	}
	for name, get := range tests {
		t.Run(name, func(t *testing.T) {
			tc := get(t)
			identity, err := DefaultIdentityFunc(tc.p, tc.email)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					assert.Equals(t, tc.err.Error(), err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, identity.Usernames, tc.identity.Usernames)
				}
			}
		})
	}
}
