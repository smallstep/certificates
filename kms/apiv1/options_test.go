package apiv1

import (
	"testing"
)

func TestOptions_Validate(t *testing.T) {
	tests := []struct {
		name    string
		options *Options
		wantErr bool
	}{
		{"nil", nil, false},
		{"softkms", &Options{Type: "softkms"}, false},
		{"cloudkms", &Options{Type: "cloudkms"}, false},
		{"awskms", &Options{Type: "awskms"}, false},
		{"sshagentkms", &Options{Type: "sshagentkms"}, false},
		{"pkcs11", &Options{Type: "pkcs11"}, false},
		{"unsupported", &Options{Type: "unsupported"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.options.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Options.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestErrNotImplemented_Error(t *testing.T) {
	type fields struct {
		msg string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{"default", fields{}, "not implemented"},
		{"custom", fields{"custom message: not implemented"}, "custom message: not implemented"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := ErrNotImplemented{
				Message: tt.fields.msg,
			}
			if got := e.Error(); got != tt.want {
				t.Errorf("ErrNotImplemented.Error() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestErrAlreadyExists_Error(t *testing.T) {
	type fields struct {
		msg string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{"default", fields{}, "key already exists"},
		{"custom", fields{"custom message: key already exists"}, "custom message: key already exists"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := ErrAlreadyExists{
				Message: tt.fields.msg,
			}
			if got := e.Error(); got != tt.want {
				t.Errorf("ErrAlreadyExists.Error() = %v, want %v", got, tt.want)
			}
		})
	}
}
