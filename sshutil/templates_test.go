package sshutil

import (
	"reflect"
	"testing"
)

func TestTemplateError_Error(t *testing.T) {
	type fields struct {
		Message string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{"ok", fields{"message"}, "message"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &TemplateError{
				Message: tt.fields.Message,
			}
			if got := e.Error(); got != tt.want {
				t.Errorf("TemplateError.Error() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCreateTemplateData(t *testing.T) {
	type args struct {
		ct         CertType
		keyID      string
		principals []string
	}
	tests := []struct {
		name string
		args args
		want TemplateData
	}{
		{"user", args{UserCert, "john@doe.com", []string{"john", "john@doe.com"}}, TemplateData{
			TypeKey:       "user",
			KeyIDKey:      "john@doe.com",
			PrincipalsKey: []string{"john", "john@doe.com"},
			ExtensionsKey: map[string]interface{}{
				"permit-X11-forwarding":   "",
				"permit-agent-forwarding": "",
				"permit-port-forwarding":  "",
				"permit-pty":              "",
				"permit-user-rc":          "",
			},
		}},
		{"host", args{HostCert, "foo", []string{"foo.internal"}}, TemplateData{
			TypeKey:       "host",
			KeyIDKey:      "foo",
			PrincipalsKey: []string{"foo.internal"},
			ExtensionsKey: map[string]interface{}(nil),
		}},
		{"other", args{100, "foo", []string{"foo.internal"}}, TemplateData{
			TypeKey:       "",
			KeyIDKey:      "foo",
			PrincipalsKey: []string{"foo.internal"},
			ExtensionsKey: map[string]interface{}(nil),
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CreateTemplateData(tt.args.ct, tt.args.keyID, tt.args.principals); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CreateTemplateData() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDefaultExtensions(t *testing.T) {
	type args struct {
		ct CertType
	}
	tests := []struct {
		name string
		args args
		want map[string]interface{}
	}{
		{"user", args{UserCert}, map[string]interface{}{
			"permit-X11-forwarding":   "",
			"permit-agent-forwarding": "",
			"permit-port-forwarding":  "",
			"permit-pty":              "",
			"permit-user-rc":          "",
		}},
		{"host", args{HostCert}, nil},
		{"other", args{100}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DefaultExtensions(tt.args.ct); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DefaultExtensions() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewTemplateData(t *testing.T) {
	tests := []struct {
		name string
		want TemplateData
	}{
		{"ok", TemplateData{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewTemplateData(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewTemplateData() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTemplateData_AddExtension(t *testing.T) {
	type args struct {
		key   string
		value string
	}
	tests := []struct {
		name string
		t    TemplateData
		args args
		want TemplateData
	}{
		{"empty", TemplateData{}, args{"key", "value"}, TemplateData{
			ExtensionsKey: map[string]interface{}{"key": "value"},
		}},
		{"overwrite", TemplateData{
			ExtensionsKey: map[string]interface{}{"key": "value"},
		}, args{"key", "value"}, TemplateData{
			ExtensionsKey: map[string]interface{}{
				"key": "value",
			},
		}},
		{"add", TemplateData{
			ExtensionsKey: map[string]interface{}{"foo": "bar"},
		}, args{"key", "value"}, TemplateData{
			ExtensionsKey: map[string]interface{}{
				"key": "value",
				"foo": "bar",
			},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.t.AddExtension(tt.args.key, tt.args.value)
			if !reflect.DeepEqual(tt.t, tt.want) {
				t.Errorf("AddExtension() = %v, want %v", tt.t, tt.want)
			}
		})
	}
}

func TestTemplateData_AddCriticalOption(t *testing.T) {
	type args struct {
		key   string
		value string
	}
	tests := []struct {
		name string
		t    TemplateData
		args args
		want TemplateData
	}{
		{"empty", TemplateData{}, args{"key", "value"}, TemplateData{
			CriticalOptionsKey: map[string]interface{}{"key": "value"},
		}},
		{"overwrite", TemplateData{
			CriticalOptionsKey: map[string]interface{}{"key": "value"},
		}, args{"key", "value"}, TemplateData{
			CriticalOptionsKey: map[string]interface{}{
				"key": "value",
			},
		}},
		{"add", TemplateData{
			CriticalOptionsKey: map[string]interface{}{"foo": "bar"},
		}, args{"key", "value"}, TemplateData{
			CriticalOptionsKey: map[string]interface{}{
				"key": "value",
				"foo": "bar",
			},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.t.AddCriticalOption(tt.args.key, tt.args.value)
			if !reflect.DeepEqual(tt.t, tt.want) {
				t.Errorf("AddCriticalOption() = %v, want %v", tt.t, tt.want)
			}
		})
	}
}

func TestTemplateData_Set(t *testing.T) {
	type args struct {
		key string
		v   interface{}
	}
	tests := []struct {
		name string
		t    TemplateData
		args args
		want TemplateData
	}{
		{"ok", TemplateData{}, args{"foo", "bar"}, TemplateData{
			"foo": "bar",
		}},
		{"overwrite", TemplateData{}, args{"foo", "bar"}, TemplateData{
			"foo": "bar",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.t.Set(tt.args.key, tt.args.v)
			if !reflect.DeepEqual(tt.t, tt.want) {
				t.Errorf("Set() = %v, want %v", tt.t, tt.want)
			}
		})
	}
}

func TestTemplateData_SetInsecure(t *testing.T) {
	type args struct {
		key string
		v   interface{}
	}
	tests := []struct {
		name string
		td   TemplateData
		args args
		want TemplateData
	}{
		{"empty", TemplateData{}, args{"foo", "bar"}, TemplateData{InsecureKey: TemplateData{"foo": "bar"}}},
		{"overwrite", TemplateData{InsecureKey: TemplateData{"foo": "bar"}}, args{"foo", "zar"}, TemplateData{InsecureKey: TemplateData{"foo": "zar"}}},
		{"add", TemplateData{InsecureKey: TemplateData{"foo": "bar"}}, args{"bar", "foo"}, TemplateData{InsecureKey: TemplateData{"foo": "bar", "bar": "foo"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.td.SetInsecure(tt.args.key, tt.args.v)
			if !reflect.DeepEqual(tt.td, tt.want) {
				t.Errorf("TemplateData.SetInsecure() = %v, want %v", tt.td, tt.want)
			}
		})
	}
}

func TestTemplateData_SetType(t *testing.T) {
	type args struct {
		typ CertType
	}
	tests := []struct {
		name string
		t    TemplateData
		args args
		want TemplateData
	}{
		{"user", TemplateData{}, args{UserCert}, TemplateData{
			TypeKey: "user",
		}},
		{"host", TemplateData{}, args{HostCert}, TemplateData{
			TypeKey: "host",
		}},
		{"overwrite", TemplateData{
			TypeKey: "host",
		}, args{UserCert}, TemplateData{
			TypeKey: "user",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.t.SetType(tt.args.typ)
			if !reflect.DeepEqual(tt.t, tt.want) {
				t.Errorf("SetType() = %v, want %v", tt.t, tt.want)
			}
		})
	}
}

func TestTemplateData_SetKeyID(t *testing.T) {
	type args struct {
		id string
	}
	tests := []struct {
		name string
		t    TemplateData
		args args
		want TemplateData
	}{
		{"ok", TemplateData{}, args{"key-id"}, TemplateData{
			KeyIDKey: "key-id",
		}},
		{"overwrite", TemplateData{}, args{"key-id-2"}, TemplateData{
			KeyIDKey: "key-id-2",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.t.SetKeyID(tt.args.id)
			if !reflect.DeepEqual(tt.t, tt.want) {
				t.Errorf("SetKeyID() = %v, want %v", tt.t, tt.want)
			}
		})
	}
}

func TestTemplateData_SetPrincipals(t *testing.T) {
	type args struct {
		p []string
	}
	tests := []struct {
		name string
		t    TemplateData
		args args
		want TemplateData
	}{
		{"ok", TemplateData{}, args{[]string{"jane"}}, TemplateData{
			PrincipalsKey: []string{"jane"},
		}},
		{"overwrite", TemplateData{}, args{[]string{"john", "john@doe.com"}}, TemplateData{
			PrincipalsKey: []string{"john", "john@doe.com"},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.t.SetPrincipals(tt.args.p)
			if !reflect.DeepEqual(tt.t, tt.want) {
				t.Errorf("SetPrincipals() = %v, want %v", tt.t, tt.want)
			}
		})
	}
}

func TestTemplateData_SetExtensions(t *testing.T) {
	type args struct {
		e map[string]interface{}
	}
	tests := []struct {
		name string
		t    TemplateData
		args args
		want TemplateData
	}{
		{"ok", TemplateData{}, args{map[string]interface{}{"foo": "bar"}}, TemplateData{
			ExtensionsKey: map[string]interface{}{"foo": "bar"},
		}},
		{"overwrite", TemplateData{
			ExtensionsKey: map[string]interface{}{"foo": "bar"},
		}, args{map[string]interface{}{"key": "value"}}, TemplateData{
			ExtensionsKey: map[string]interface{}{"key": "value"},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.t.SetExtensions(tt.args.e)
			if !reflect.DeepEqual(tt.t, tt.want) {
				t.Errorf("SetExtensions() = %v, want %v", tt.t, tt.want)
			}
		})
	}
}

func TestTemplateData_SetCriticalOptions(t *testing.T) {
	type args struct {
		e map[string]interface{}
	}
	tests := []struct {
		name string
		t    TemplateData
		args args
		want TemplateData
	}{
		{"ok", TemplateData{}, args{map[string]interface{}{"foo": "bar"}}, TemplateData{
			CriticalOptionsKey: map[string]interface{}{"foo": "bar"},
		}},
		{"overwrite", TemplateData{
			CriticalOptionsKey: map[string]interface{}{"foo": "bar"},
		}, args{map[string]interface{}{"key": "value"}}, TemplateData{
			CriticalOptionsKey: map[string]interface{}{"key": "value"},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.t.SetCriticalOptions(tt.args.e)
			if !reflect.DeepEqual(tt.t, tt.want) {
				t.Errorf("SetCriticalOptions() = %v, want %v", tt.t, tt.want)
			}
		})
	}
}

func TestTemplateData_SetToken(t *testing.T) {
	type args struct {
		v interface{}
	}
	tests := []struct {
		name string
		td   TemplateData
		args args
		want TemplateData
	}{
		{"ok", TemplateData{}, args{"token"}, TemplateData{TokenKey: "token"}},
		{"overwrite", TemplateData{TokenKey: "foo"}, args{"token"}, TemplateData{TokenKey: "token"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.td.SetToken(tt.args.v)
			if !reflect.DeepEqual(tt.td, tt.want) {
				t.Errorf("TemplateData.SetToken() = %v, want %v", tt.td, tt.want)
			}
		})
	}
}

func TestTemplateData_SetUserData(t *testing.T) {
	type args struct {
		v interface{}
	}
	tests := []struct {
		name string
		td   TemplateData
		args args
		want TemplateData
	}{
		{"ok", TemplateData{}, args{"userData"}, TemplateData{InsecureKey: TemplateData{UserKey: "userData"}}},
		{"overwrite", TemplateData{InsecureKey: TemplateData{UserKey: "foo"}}, args{"userData"}, TemplateData{InsecureKey: TemplateData{UserKey: "userData"}}},
		{"existing", TemplateData{InsecureKey: TemplateData{"foo": "bar"}}, args{"userData"}, TemplateData{InsecureKey: TemplateData{"foo": "bar", UserKey: "userData"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.td.SetUserData(tt.args.v)
			if !reflect.DeepEqual(tt.td, tt.want) {
				t.Errorf("TemplateData.SetUserData() = %v, want %v", tt.td, tt.want)
			}
		})
	}
}

func TestTemplateData_SetCertificateRequest(t *testing.T) {
	cr1 := CertificateRequest{Key: mustGeneratePublicKey(t)}
	cr2 := CertificateRequest{Key: mustGeneratePublicKey(t)}
	type args struct {
		cr CertificateRequest
	}
	tests := []struct {
		name string
		t    TemplateData
		args args
		want TemplateData
	}{
		{"ok", TemplateData{}, args{cr1}, TemplateData{
			InsecureKey: TemplateData{
				CertificateRequestKey: cr1,
			},
		}},
		{"overwrite", TemplateData{
			InsecureKey: TemplateData{
				UserKey:               "data",
				CertificateRequestKey: cr1,
			},
		}, args{cr2}, TemplateData{
			InsecureKey: TemplateData{
				UserKey:               "data",
				CertificateRequestKey: cr2,
			},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.t.SetCertificateRequest(tt.args.cr)
			if !reflect.DeepEqual(tt.t, tt.want) {
				t.Errorf("TemplateData.SetCertificateRequest() = %v, want %v", tt.t, tt.want)
			}
		})
	}
}
