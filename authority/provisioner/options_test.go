package provisioner

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"reflect"
	"testing"

	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/x509util"
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

func TestOptions_GetX509Options(t *testing.T) {
	type fields struct {
		o *Options
	}
	tests := []struct {
		name   string
		fields fields
		want   *X509Options
	}{
		{"ok", fields{&Options{X509: &X509Options{Template: "foo"}}}, &X509Options{Template: "foo"}},
		{"nil", fields{&Options{}}, nil},
		{"nilOptions", fields{nil}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.fields.o.GetX509Options(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Options.GetX509Options() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOptions_GetSSHOptions(t *testing.T) {
	type fields struct {
		o *Options
	}
	tests := []struct {
		name   string
		fields fields
		want   *SSHOptions
	}{
		{"ok", fields{&Options{SSH: &SSHOptions{Template: "foo"}}}, &SSHOptions{Template: "foo"}},
		{"nil", fields{&Options{}}, nil},
		{"nilOptions", fields{nil}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.fields.o.GetSSHOptions(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Options.GetSSHOptions() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOptions_GetWebhooks(t *testing.T) {
	type fields struct {
		o *Options
	}
	tests := []struct {
		name   string
		fields fields
		want   []*Webhook
	}{
		{"ok", fields{&Options{Webhooks: []*Webhook{
			{Name: "foo"},
			{Name: "bar"},
		}}},
			[]*Webhook{
				{Name: "foo"},
				{Name: "bar"},
			},
		},
		{"nil", fields{&Options{}}, nil},
		{"nilOptions", fields{nil}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.fields.o.GetWebhooks(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Options.GetWebhooks() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProvisionerX509Options_HasTemplate(t *testing.T) {
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
			o := &X509Options{
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
		o    *Options
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
		{"okCustomTemplate", args{&Options{X509: &X509Options{Template: x509util.DefaultIIDLeafTemplate}}, data}, x509util.Options{
			CertBuffer: bytes.NewBufferString(`{
	"subject": {"commonName": "foo"},
	"sans": [{"type":"dns","value":"foo.com"}],
	"keyUsage": ["digitalSignature"],
	"extKeyUsage": ["serverAuth", "clientAuth"]
}`)}, false},
		{"fail", args{&Options{X509: &X509Options{TemplateData: []byte(`{"badJSON`)}}, data}, x509util.Options{}, true},
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
				for _, fn := range cof.Options(SignOptions{}) {
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
	csrCertificate := `{"version":0,"subject":{"commonName":"foo"},"dnsNames":["foo"],"emailAddresses":null,"ipAddresses":null,"uris":null,"sans":null,"extensions":[{"id":"2.5.29.17","critical":false,"value":"MAWCA2Zvbw=="}],"signatureAlgorithm":""}`
	data := x509util.TemplateData{
		x509util.SubjectKey: x509util.Subject{
			CommonName: "foobar",
		},
		x509util.SANsKey: []x509util.SubjectAlternativeName{
			{Type: "dns", Value: "foo.com"},
		},
	}
	type args struct {
		o               *Options
		data            x509util.TemplateData
		defaultTemplate string
		userOptions     SignOptions
	}
	tests := []struct {
		name    string
		args    args
		want    x509util.Options
		wantErr bool
	}{
		{"ok", args{nil, data, x509util.DefaultLeafTemplate, SignOptions{}}, x509util.Options{
			CertBuffer: bytes.NewBufferString(`{
	"subject": {"commonName":"foobar"},
	"sans": [{"type":"dns","value":"foo.com"}],
	"keyUsage": ["digitalSignature"],
	"extKeyUsage": ["serverAuth", "clientAuth"]
}`)}, false},
		{"okIID", args{nil, data, x509util.DefaultIIDLeafTemplate, SignOptions{}}, x509util.Options{
			CertBuffer: bytes.NewBufferString(`{
	"subject": {"commonName": "foo"},
	"sans": [{"type":"dns","value":"foo.com"}],
	"keyUsage": ["digitalSignature"],
	"extKeyUsage": ["serverAuth", "clientAuth"]
}`)}, false},
		{"okNoData", args{&Options{}, nil, x509util.DefaultLeafTemplate, SignOptions{}}, x509util.Options{
			CertBuffer: bytes.NewBufferString(`{
	"subject": null,
	"sans": null,
	"keyUsage": ["digitalSignature"],
	"extKeyUsage": ["serverAuth", "clientAuth"]
}`)}, false},
		{"okTemplateData", args{&Options{X509: &X509Options{TemplateData: []byte(`{"foo":"bar"}`)}}, data, x509util.DefaultLeafTemplate, SignOptions{}}, x509util.Options{
			CertBuffer: bytes.NewBufferString(`{
	"subject": {"commonName":"foobar"},
	"sans": [{"type":"dns","value":"foo.com"}],
	"keyUsage": ["digitalSignature"],
	"extKeyUsage": ["serverAuth", "clientAuth"]
}`)}, false},
		{"okTemplate", args{&Options{X509: &X509Options{Template: "{{ toJson .Insecure.CR }}"}}, data, x509util.DefaultLeafTemplate, SignOptions{}}, x509util.Options{
			CertBuffer: bytes.NewBufferString(csrCertificate)}, false},
		{"okFile", args{&Options{X509: &X509Options{TemplateFile: "./testdata/templates/cr.tpl"}}, data, x509util.DefaultLeafTemplate, SignOptions{}}, x509util.Options{
			CertBuffer: bytes.NewBufferString(csrCertificate)}, false},
		{"okBase64", args{&Options{X509: &X509Options{Template: "e3sgdG9Kc29uIC5JbnNlY3VyZS5DUiB9fQ=="}}, data, x509util.DefaultLeafTemplate, SignOptions{}}, x509util.Options{
			CertBuffer: bytes.NewBufferString(csrCertificate)}, false},
		{"okUserOptions", args{&Options{X509: &X509Options{Template: `{"foo": "{{.Insecure.User.foo}}"}`}}, data, x509util.DefaultLeafTemplate, SignOptions{TemplateData: []byte(`{"foo":"bar"}`)}}, x509util.Options{
			CertBuffer: bytes.NewBufferString(`{"foo": "bar"}`),
		}, false},
		{"okBadUserOptions", args{&Options{X509: &X509Options{Template: `{"foo": "{{.Insecure.User.foo}}"}`}}, data, x509util.DefaultLeafTemplate, SignOptions{TemplateData: []byte(`{"badJSON"}`)}}, x509util.Options{
			CertBuffer: bytes.NewBufferString(`{"foo": "<no value>"}`),
		}, false},
		{"okNullTemplateData", args{&Options{X509: &X509Options{TemplateData: []byte(`null`)}}, data, x509util.DefaultLeafTemplate, SignOptions{}}, x509util.Options{
			CertBuffer: bytes.NewBufferString(`{
	"subject": {"commonName":"foobar"},
	"sans": [{"type":"dns","value":"foo.com"}],
	"keyUsage": ["digitalSignature"],
	"extKeyUsage": ["serverAuth", "clientAuth"]
}`)}, false},
		{"fail", args{&Options{X509: &X509Options{TemplateData: []byte(`{"badJSON`)}}, data, x509util.DefaultLeafTemplate, SignOptions{}}, x509util.Options{}, true},
		{"failTemplateData", args{&Options{X509: &X509Options{TemplateData: []byte(`{"badJSON}`)}}, data, x509util.DefaultLeafTemplate, SignOptions{}}, x509util.Options{}, true},
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
	//nolint:gosec // no credentials here
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

func TestX509Options_IsWildcardLiteralAllowed(t *testing.T) {
	tests := []struct {
		name    string
		options *X509Options
		want    bool
	}{
		{
			name:    "nil-options",
			options: nil,
			want:    true,
		},
		{
			name: "set-true",
			options: &X509Options{
				AllowWildcardNames: true,
			},
			want: true,
		},
		{
			name: "set-false",
			options: &X509Options{
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
