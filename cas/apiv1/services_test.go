package apiv1

import (
	"testing"
)

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

func TestNotImplementedError_Error(t *testing.T) {
	type fields struct {
		Message string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{"default", fields{""}, "not implemented"},
		{"with message", fields{"method not supported"}, "method not supported"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NotImplementedError{
				Message: tt.fields.Message,
			}
			if got := e.Error(); got != tt.want {
				t.Errorf("NotImplementedError.Error() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNotImplementedError_StatusCode(t *testing.T) {
	type fields struct {
		Message string
	}
	tests := []struct {
		name   string
		fields fields
		want   int
	}{
		{"default", fields{""}, 501},
		{"with message", fields{"method not supported"}, 501},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NotImplementedError{
				Message: tt.fields.Message,
			}
			if got := s.StatusCode(); got != tt.want {
				t.Errorf("NotImplementedError.StatusCode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidationError_Error(t *testing.T) {
	type fields struct {
		Message string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{"default", fields{""}, "bad request"},
		{"with message", fields{"token is empty"}, "token is empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := ValidationError{
				Message: tt.fields.Message,
			}
			if got := e.Error(); got != tt.want {
				t.Errorf("ValidationError.Error() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidationError_StatusCode(t *testing.T) {
	type fields struct {
		Message string
	}
	tests := []struct {
		name   string
		fields fields
		want   int
	}{
		{"default", fields{""}, 400},
		{"with message", fields{"token is empty"}, 400},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := ValidationError{
				Message: tt.fields.Message,
			}
			if got := e.StatusCode(); got != tt.want {
				t.Errorf("ValidationError.StatusCode() = %v, want %v", got, tt.want)
			}
		})
	}
}
