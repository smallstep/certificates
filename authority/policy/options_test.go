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
				AllowWildcardLiteral: true,
			},
			want: true,
		},
		{
			name: "set-false",
			options: &X509PolicyOptions{
				AllowWildcardLiteral: false,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.options.IsWildcardLiteralAllowed(); got != tt.want {
				t.Errorf("X509PolicyOptions.IsWildcardLiteralAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestX509PolicyOptions_ShouldVerifySubjectCommonName(t *testing.T) {
	tests := []struct {
		name    string
		options *X509PolicyOptions
		want    bool
	}{
		{
			name:    "nil-options",
			options: nil,
			want:    false,
		},
		{
			name:    "not-set",
			options: &X509PolicyOptions{},
			want:    true,
		},
		{
			name: "set-true",
			options: &X509PolicyOptions{
				DisableCommonNameVerification: true,
			},
			want: false,
		},
		{
			name: "set-false",
			options: &X509PolicyOptions{
				DisableCommonNameVerification: false,
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.options.ShouldVerifyCommonName(); got != tt.want {
				t.Errorf("X509PolicyOptions.ShouldVerifySubjectCommonName() = %v, want %v", got, tt.want)
			}
		})
	}
}
