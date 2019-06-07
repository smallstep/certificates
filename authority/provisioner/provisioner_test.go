package provisioner

import "testing"

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
