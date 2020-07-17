package x509util

import (
	"crypto/x509"
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
		{"ok", fields{"an error"}, "an error"},
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

func TestCreateTemplateData(t *testing.T) {
	type args struct {
		commonName string
		sans       []string
	}
	tests := []struct {
		name string
		args args
		want TemplateData
	}{
		{"ok", args{"jane.doe.com", []string{"jane.doe.com", "jane@doe.com", "1.1.1.1", "mailto:jane@doe.com"}}, TemplateData{
			SubjectKey: Subject{CommonName: "jane.doe.com"},
			SANsKey: []SubjectAlternativeName{
				{Type: DNSType, Value: "jane.doe.com"},
				{Type: IPType, Value: "1.1.1.1"},
				{Type: EmailType, Value: "jane@doe.com"},
				{Type: URIType, Value: "mailto:jane@doe.com"},
			},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CreateTemplateData(tt.args.commonName, tt.args.sans); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CreateTemplateData() = %v, want %v", got, tt.want)
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
		{"existing", TemplateData{InsecureKey: TemplateData{"foo": "bar"}}, args{"bar", "foo"}, TemplateData{InsecureKey: TemplateData{"foo": "bar", "bar": "foo"}}},
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

func TestTemplateData_SetSubject(t *testing.T) {
	type args struct {
		v Subject
	}
	tests := []struct {
		name string
		td   TemplateData
		args args
		want TemplateData
	}{
		{"ok", TemplateData{}, args{Subject{CommonName: "foo"}}, TemplateData{SubjectKey: Subject{CommonName: "foo"}}},
		{"overwrite", TemplateData{SubjectKey: Subject{CommonName: "foo"}}, args{Subject{Province: []string{"CA"}}}, TemplateData{SubjectKey: Subject{Province: []string{"CA"}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.td.SetSubject(tt.args.v)
			if !reflect.DeepEqual(tt.td, tt.want) {
				t.Errorf("TemplateData.SetSubject() = %v, want %v", tt.td, tt.want)
			}
		})
	}
}

func TestTemplateData_SetCommonName(t *testing.T) {
	type args struct {
		cn string
	}
	tests := []struct {
		name string
		td   TemplateData
		args args
		want TemplateData
	}{
		{"ok", TemplateData{}, args{"commonName"}, TemplateData{SubjectKey: Subject{CommonName: "commonName"}}},
		{"overwrite", TemplateData{SubjectKey: Subject{CommonName: "foo", Province: []string{"CA"}}}, args{"commonName"}, TemplateData{SubjectKey: Subject{CommonName: "commonName", Province: []string{"CA"}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.td.SetCommonName(tt.args.cn)
			if !reflect.DeepEqual(tt.td, tt.want) {
				t.Errorf("TemplateData.SetCommonName() = %v, want %v", tt.td, tt.want)
			}
		})
	}
}

func TestTemplateData_SetSANs(t *testing.T) {
	type args struct {
		sans []string
	}
	tests := []struct {
		name string
		td   TemplateData
		args args
		want TemplateData
	}{
		{"ok", TemplateData{}, args{[]string{"jane.doe.com", "jane@doe.com", "1.1.1.1", "mailto:jane@doe.com"}}, TemplateData{
			SANsKey: []SubjectAlternativeName{
				{Type: DNSType, Value: "jane.doe.com"},
				{Type: IPType, Value: "1.1.1.1"},
				{Type: EmailType, Value: "jane@doe.com"},
				{Type: URIType, Value: "mailto:jane@doe.com"},
			}},
		},
		{"overwrite", TemplateData{}, args{[]string{"jane.doe.com"}}, TemplateData{
			SANsKey: []SubjectAlternativeName{
				{Type: DNSType, Value: "jane.doe.com"},
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.td.SetSANs(tt.args.sans)
			if !reflect.DeepEqual(tt.td, tt.want) {
				t.Errorf("TemplateData.SetSANs() = %v, want %v", tt.td, tt.want)
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
	cr := &x509.CertificateRequest{
		DNSNames: []string{"foo", "bar"},
	}
	cr1 := &CertificateRequest{
		DNSNames: []string{"foo", "bar"},
	}
	cr2 := &CertificateRequest{
		EmailAddresses: []string{"foo@bar.com"},
	}
	type args struct {
		cr *x509.CertificateRequest
	}
	tests := []struct {
		name string
		td   TemplateData
		args args
		want TemplateData
	}{
		{"ok", TemplateData{}, args{cr}, TemplateData{InsecureKey: TemplateData{CertificateRequestKey: cr1}}},
		{"overwrite", TemplateData{InsecureKey: TemplateData{CertificateRequestKey: cr2}}, args{cr}, TemplateData{InsecureKey: TemplateData{CertificateRequestKey: cr1}}},
		{"existing", TemplateData{InsecureKey: TemplateData{"foo": "bar"}}, args{cr}, TemplateData{InsecureKey: TemplateData{"foo": "bar", CertificateRequestKey: cr1}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.td.SetCertificateRequest(tt.args.cr)
			if !reflect.DeepEqual(tt.td, tt.want) {
				t.Errorf("TemplateData.SetCertificateRequest() = %v, want %v", tt.td, tt.want)
			}
		})
	}
}
