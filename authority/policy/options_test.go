package policy

import (
	"testing"
)

func TestX509PolicyOptions_IsWildcardLiteralAllowed(t *testing.T) {
	tests := []struct {
		name    string
		options *X509PolicyOptions
		want    bool
	}{
		{
			name:    "nil-options",
			options: nil,
			want:    true,
		},
		{
			name:    "not-set",
			options: &X509PolicyOptions{},
			want:    false,
		},
		{
			name: "set-true",
			options: &X509PolicyOptions{
				AllowWildcardNames: true,
			},
			want: true,
		},
		{
			name: "set-false",
			options: &X509PolicyOptions{
				AllowWildcardNames: false,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.options.AreWildcardNamesAllowed(); got != tt.want {
				t.Errorf("X509PolicyOptions.IsWildcardLiteralAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}
