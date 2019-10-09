package provisioner

import (
	"testing"
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
