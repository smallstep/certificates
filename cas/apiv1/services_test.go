package apiv1

import "testing"

func TestType_String(t *testing.T) {
	tests := []struct {
		name string
		t    Type
		want string
	}{
		{"default", "", "softcas"},
		{"SoftCAS", SoftCAS, "softcas"},
		{"CloudCAS", CloudCAS, "cloudcas"},
		{"UnknownCAS", "UnknownCAS", "unknowncas"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.t.String(); got != tt.want {
				t.Errorf("Type.String() = %v, want %v", got, tt.want)
			}
		})
	}
}
