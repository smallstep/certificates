package provisioner

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/api/render"
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
		p         Interface
		email     string
		usernames []string
		err       error
		identity  *Identity
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
				identity: &Identity{Usernames: []string{"maxfurman", "max.furman", "max.furman@smallstep.com"}},
			}
		},
		"ok letter case": func(t *testing.T) test {
			return test{
				p:        &OIDC{},
				email:    "Max.Furman@smallstep.com",
				identity: &Identity{Usernames: []string{"maxfurman", "Max.Furman", "Max.Furman@smallstep.com"}},
			}
		},
		"ok simple": func(t *testing.T) test {
			return test{
				p:        &OIDC{},
				email:    "john@smallstep.com",
				identity: &Identity{Usernames: []string{"john", "john@smallstep.com"}},
			}
		},
		"ok simple letter case": func(t *testing.T) test {
			return test{
				p:        &OIDC{},
				email:    "John@smallstep.com",
				identity: &Identity{Usernames: []string{"john", "John", "John@smallstep.com"}},
			}
		},
		"ok symbol": func(t *testing.T) test {
			return test{
				p:        &OIDC{},
				email:    "John+Doe@smallstep.com",
				identity: &Identity{Usernames: []string{"john_doe", "John+Doe", "John+Doe@smallstep.com"}},
			}
		},
		"ok username": func(t *testing.T) test {
			return test{
				p:         &OIDC{},
				email:     "john@smallstep.com",
				usernames: []string{"johnny"},
				identity:  &Identity{Usernames: []string{"john", "john@smallstep.com"}},
			}
		},
		"ok usernames": func(t *testing.T) test {
			return test{
				p:         &OIDC{},
				email:     "john@smallstep.com",
				usernames: []string{"johnny", "js", "", "johnny", ""},
				identity:  &Identity{Usernames: []string{"john", "john@smallstep.com"}},
			}
		},
		"ok empty username": func(t *testing.T) test {
			return test{
				p:         &OIDC{},
				email:     "john@smallstep.com",
				usernames: []string{""},
				identity:  &Identity{Usernames: []string{"john", "john@smallstep.com"}},
			}
		},
	}
	for name, get := range tests {
		t.Run(name, func(t *testing.T) {
			tc := get(t)
			identity, err := DefaultIdentityFunc(context.Background(), tc.p, tc.email)
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

func TestUnimplementedMethods(t *testing.T) {
	tests := []struct {
		name   string
		p      Interface
		method Method
	}{
		{"jwk/sshRekey", &JWK{}, SSHRekeyMethod},
		{"jwk/sshRenew", &JWK{}, SSHRenewMethod},
		{"aws/revoke", &AWS{}, RevokeMethod},
		{"aws/sshRenew", &AWS{}, SSHRenewMethod},
		{"aws/rekey", &AWS{}, SSHRekeyMethod},
		{"aws/sshRevoke", &AWS{}, SSHRevokeMethod},
		{"azure/revoke", &Azure{}, RevokeMethod},
		{"azure/sshRenew", &Azure{}, SSHRenewMethod},
		{"azure/sshRekey", &Azure{}, SSHRekeyMethod},
		{"azure/sshRevoke", &Azure{}, SSHRevokeMethod},
		{"gcp/revoke", &GCP{}, RevokeMethod},
		{"gcp/sshRenew", &GCP{}, SSHRenewMethod},
		{"gcp/sshRekey", &GCP{}, SSHRekeyMethod},
		{"gcp/sshRevoke", &GCP{}, SSHRevokeMethod},
		{"oidc/sshRenew", &OIDC{}, SSHRenewMethod},
		{"oidc/sshRekey", &OIDC{}, SSHRekeyMethod},
		{"x5c/sshRenew", &X5C{}, SSHRenewMethod},
		{"x5c/sshRekey", &X5C{}, SSHRekeyMethod},
		{"x5c/sshRevoke", &X5C{}, SSHRekeyMethod},
		{"acme/sshSign", &ACME{}, SSHSignMethod},
		{"acme/sshRekey", &ACME{}, SSHRekeyMethod},
		{"acme/sshRenew", &ACME{}, SSHRenewMethod},
		{"acme/sshRevoke", &ACME{}, SSHRevokeMethod},
		{"sshpop/sign", &SSHPOP{}, SignMethod},
		{"sshpop/renew", &SSHPOP{}, RenewMethod},
		{"sshpop/revoke", &SSHPOP{}, RevokeMethod},
		{"sshpop/sshSign", &SSHPOP{}, SSHSignMethod},
		{"k8ssa/sshRekey", &K8sSA{}, SSHRekeyMethod},
		{"k8ssa/sshRenew", &K8sSA{}, SSHRenewMethod},
		{"k8ssa/sshRevoke", &K8sSA{}, SSHRevokeMethod},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				err error
				msg string
			)

			switch tt.method {
			case SignMethod:
				var signOpts []SignOption
				signOpts, err = tt.p.AuthorizeSign(context.Background(), "")
				assert.Nil(t, signOpts)
				msg = "provisioner.AuthorizeSign not implemented"
			case RenewMethod:
				err = tt.p.AuthorizeRenew(context.Background(), nil)
				msg = "provisioner.AuthorizeRenew not implemented"
			case RevokeMethod:
				err = tt.p.AuthorizeRevoke(context.Background(), "")
				msg = "provisioner.AuthorizeRevoke not implemented"
			case SSHSignMethod:
				var signOpts []SignOption
				signOpts, err = tt.p.AuthorizeSSHSign(context.Background(), "")
				assert.Nil(t, signOpts)
				msg = "provisioner.AuthorizeSSHSign not implemented"
			case SSHRenewMethod:
				var cert *ssh.Certificate
				cert, err = tt.p.AuthorizeSSHRenew(context.Background(), "")
				assert.Nil(t, cert)
				msg = "provisioner.AuthorizeSSHRenew not implemented"
			case SSHRekeyMethod:
				var (
					cert     *ssh.Certificate
					signOpts []SignOption
				)
				cert, signOpts, err = tt.p.AuthorizeSSHRekey(context.Background(), "")
				assert.Nil(t, cert)
				assert.Nil(t, signOpts)
				msg = "provisioner.AuthorizeSSHRekey not implemented"
			case SSHRevokeMethod:
				err = tt.p.AuthorizeSSHRevoke(context.Background(), "")
				msg = "provisioner.AuthorizeSSHRevoke not implemented"
			default:
				t.Errorf("unexpected method %s", tt.method)
			}
			var sc render.StatusCodedError
			if assert.True(t, errors.As(err, &sc), "error does not implement StatusCodedError interface") {
				assert.Equals(t, sc.StatusCode(), http.StatusUnauthorized)
			}
			assert.Equals(t, err.Error(), msg)
		})
	}
}
