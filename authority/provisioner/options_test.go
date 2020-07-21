package provisioner

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/smallstep/certificates/x509util"
	"github.com/smallstep/cli/crypto/pemutil"
)

func parseCertificateRequest(t *testing.T, filename string) *x509.CertificateRequest {
	t.Helper()
	v, err := pemutil.Read(filename)
	if err != nil {
		t.Fatal(err)
	}
	csr, ok := v.(*x509.CertificateRequest)
	if !ok {
		t.Fatalf("%s is not a certificate request", filename)
	}
	return csr
}

func TestProvisionerOptions_HasTemplate(t *testing.T) {
	type fields struct {
		Template     string
		TemplateFile string
		TemplateData json.RawMessage
	}
	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{"template", fields{Template: "the template"}, true},
		{"templateFile", fields{TemplateFile: "the template file"}, true},
		{"false", fields{}, false},
		{"falseWithTemplateData", fields{TemplateData: []byte(`{"foo":"bar"}`)}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &ProvisionerOptions{
				Template:     tt.fields.Template,
				TemplateFile: tt.fields.TemplateFile,
				TemplateData: tt.fields.TemplateData,
			}
			if got := o.HasTemplate(); got != tt.want {
				t.Errorf("ProvisionerOptions.HasTemplate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTemplateOptions(t *testing.T) {
	csr := parseCertificateRequest(t, "testdata/certs/ecdsa.csr")
	data := x509util.TemplateData{
		x509util.SubjectKey: x509util.Subject{
			CommonName: "foobar",
		},
		x509util.SANsKey: []x509util.SubjectAlternativeName{
			{Type: "dns", Value: "foo.com"},
		},
	}
	type args struct {
		o    *ProvisionerOptions
		data x509util.TemplateData
	}
	tests := []struct {
		name    string
		args    args
		want    x509util.Options
		wantErr bool
	}{
		{"ok", args{nil, data}, x509util.Options{
			CertBuffer: bytes.NewBufferString(`{
	"subject": {"commonName":"foobar"},
	"sans": [{"type":"dns","value":"foo.com"}],
	"keyUsage": ["digitalSignature"],
	"extKeyUsage": ["serverAuth", "clientAuth"]
}`)}, false},
		{"okCustomTemplate", args{&ProvisionerOptions{Template: x509util.DefaultIIDLeafTemplate}, data}, x509util.Options{
			CertBuffer: bytes.NewBufferString(`{
	"subject": {"commonName":"foo"},
	"sans": [{"type":"dns","value":"foo.com"}],
	"keyUsage": ["digitalSignature"],
	"extKeyUsage": ["serverAuth", "clientAuth"]
}`)}, false},
		{"fail", args{&ProvisionerOptions{TemplateData: []byte(`{"badJSON`)}, data}, x509util.Options{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cof, err := TemplateOptions(tt.args.o, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("TemplateOptions() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			var opts x509util.Options
			if cof != nil {
				for _, fn := range cof.Options(Options{}) {
					if err := fn(csr, &opts); err != nil {
						t.Errorf("x509util.Options() error = %v", err)
						return
					}
				}
			}
			if !reflect.DeepEqual(opts, tt.want) {
				t.Errorf("x509util.Option = %v, want %v", opts, tt.want)
			}
		})
	}
}

func TestCustomTemplateOptions(t *testing.T) {
	csr := parseCertificateRequest(t, "testdata/certs/ecdsa.csr")
	csrCertificate := `{"version":0,"subject":{"commonName":"foo"},"dnsNames":["foo"],"emailAddresses":null,"ipAddresses":null,"uris":null,"extensions":[{"id":"2.5.29.17","critical":false,"value":"MAWCA2Zvbw=="}]}`
	data := x509util.TemplateData{
		x509util.SubjectKey: x509util.Subject{
			CommonName: "foobar",
		},
		x509util.SANsKey: []x509util.SubjectAlternativeName{
			{Type: "dns", Value: "foo.com"},
		},
	}
	type args struct {
		o               *ProvisionerOptions
		data            x509util.TemplateData
		defaultTemplate string
		userOptions     Options
	}
	tests := []struct {
		name    string
		args    args
		want    x509util.Options
		wantErr bool
	}{
		{"ok", args{nil, data, x509util.DefaultLeafTemplate, Options{}}, x509util.Options{
			CertBuffer: bytes.NewBufferString(`{
	"subject": {"commonName":"foobar"},
	"sans": [{"type":"dns","value":"foo.com"}],
	"keyUsage": ["digitalSignature"],
	"extKeyUsage": ["serverAuth", "clientAuth"]
}`)}, false},
		{"okIID", args{nil, data, x509util.DefaultIIDLeafTemplate, Options{}}, x509util.Options{
			CertBuffer: bytes.NewBufferString(`{
	"subject": {"commonName":"foo"},
	"sans": [{"type":"dns","value":"foo.com"}],
	"keyUsage": ["digitalSignature"],
	"extKeyUsage": ["serverAuth", "clientAuth"]
}`)}, false},
		{"okNoData", args{&ProvisionerOptions{}, nil, x509util.DefaultLeafTemplate, Options{}}, x509util.Options{
			CertBuffer: bytes.NewBufferString(`{
	"subject": null,
	"sans": null,
	"keyUsage": ["digitalSignature"],
	"extKeyUsage": ["serverAuth", "clientAuth"]
}`)}, false},
		{"okTemplateData", args{&ProvisionerOptions{TemplateData: []byte(`{"foo":"bar"}`)}, data, x509util.DefaultLeafTemplate, Options{}}, x509util.Options{
			CertBuffer: bytes.NewBufferString(`{
	"subject": {"commonName":"foobar"},
	"sans": [{"type":"dns","value":"foo.com"}],
	"keyUsage": ["digitalSignature"],
	"extKeyUsage": ["serverAuth", "clientAuth"]
}`)}, false},
		{"okTemplate", args{&ProvisionerOptions{Template: "{{ toJson .Insecure.CR }}"}, data, x509util.DefaultLeafTemplate, Options{}}, x509util.Options{
			CertBuffer: bytes.NewBufferString(csrCertificate)}, false},
		{"okFile", args{&ProvisionerOptions{TemplateFile: "./testdata/templates/cr.tpl"}, data, x509util.DefaultLeafTemplate, Options{}}, x509util.Options{
			CertBuffer: bytes.NewBufferString(csrCertificate)}, false},
		{"okBase64", args{&ProvisionerOptions{Template: "e3sgdG9Kc29uIC5JbnNlY3VyZS5DUiB9fQ=="}, data, x509util.DefaultLeafTemplate, Options{}}, x509util.Options{
			CertBuffer: bytes.NewBufferString(csrCertificate)}, false},
		{"okUserOptions", args{&ProvisionerOptions{Template: `{"foo": "{{.Insecure.User.foo}}"}`}, data, x509util.DefaultLeafTemplate, Options{TemplateData: []byte(`{"foo":"bar"}`)}}, x509util.Options{
			CertBuffer: bytes.NewBufferString(`{"foo": "bar"}`),
		}, false},
		{"okBadUserOptions", args{&ProvisionerOptions{Template: `{"foo": "{{.Insecure.User.foo}}"}`}, data, x509util.DefaultLeafTemplate, Options{TemplateData: []byte(`{"badJSON"}`)}}, x509util.Options{
			CertBuffer: bytes.NewBufferString(`{"foo": "<no value>"}`),
		}, false},
		{"fail", args{&ProvisionerOptions{TemplateData: []byte(`{"badJSON`)}, data, x509util.DefaultLeafTemplate, Options{}}, x509util.Options{}, true},
		{"failTemplateData", args{&ProvisionerOptions{TemplateData: []byte(`{"badJSON}`)}, data, x509util.DefaultLeafTemplate, Options{}}, x509util.Options{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cof, err := CustomTemplateOptions(tt.args.o, tt.args.data, tt.args.defaultTemplate)
			if (err != nil) != tt.wantErr {
				t.Errorf("CustomTemplateOptions() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			var opts x509util.Options
			if cof != nil {
				for _, fn := range cof.Options(tt.args.userOptions) {
					if err := fn(csr, &opts); err != nil {
						t.Errorf("x509util.Options() error = %v", err)
						return
					}
				}
			}
			if !reflect.DeepEqual(opts, tt.want) {
				t.Errorf("x509util.Option = %v, want %v", opts, tt.want)
			}
		})
	}
}

func Test_unsafeParseSigned(t *testing.T) {
	okToken := "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJqYW5lQGRvZS5jb20iLCJpc3MiOiJodHRwczovL2RvZS5jb20iLCJqdGkiOiI4ZmYzMjQ4MS1mZDVmLTRlMmUtOTZkZi05MDhjMTI3Yzg1ZjciLCJpYXQiOjE1OTUzNjAwMjgsImV4cCI6MTU5NTM2MzYyOH0.aid8UuhFucJOFHXaob9zpNtVvhul9ulTGsA52mU6XIw"
	type args struct {
		s string
	}
	tests := []struct {
		name    string
		args    args
		want    map[string]interface{}
		wantErr bool
	}{
		{"ok", args{okToken}, map[string]interface{}{
			"sub": "jane@doe.com",
			"iss": "https://doe.com",
			"jti": "8ff32481-fd5f-4e2e-96df-908c127c85f7",
			"iat": float64(1595360028),
			"exp": float64(1595363628),
		}, false},
		{"failToken", args{"foobar"}, nil, true},
		{"failPayload", args{"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.ew.aid8UuhFucJOFHXaob9zpNtVvhul9ulTGsA52mU6XIw"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := unsafeParseSigned(tt.args.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("unsafeParseSigned() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("unsafeParseSigned() = \n%v, want \n%v", got, tt.want)
			}
		})
	}
}
