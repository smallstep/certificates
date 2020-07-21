package x509util

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"reflect"
	"testing"

	"github.com/pkg/errors"
)

func createRSACertificateRequest(t *testing.T, bits int, commonName string, sans []string) (*x509.CertificateRequest, crypto.Signer) {
	dnsNames, ips, emails, uris := SplitSANs(sans)
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	asn1Data, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: commonName},
		DNSNames:           dnsNames,
		IPAddresses:        ips,
		EmailAddresses:     emails,
		URIs:               uris,
		SignatureAlgorithm: x509.SHA256WithRSAPSS,
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	cr, err := x509.ParseCertificateRequest(asn1Data)
	if err != nil {
		t.Fatal(err)
	}
	return cr, priv
}

func Test_getFuncMap_fail(t *testing.T) {
	var failMesage string
	fns := getFuncMap(&failMesage)
	fail := fns["fail"].(func(s string) (string, error))
	s, err := fail("the fail message")
	if err == nil {
		t.Errorf("fail() error = %v, wantErr %v", err, errors.New("the fail message"))
	}
	if s != "" {
		t.Errorf("fail() = \"%s\", want \"the fail message\"", s)
	}
	if failMesage != "the fail message" {
		t.Errorf("fail() message = \"%s\", want \"the fail message\"", failMesage)
	}
}

func TestWithTemplate(t *testing.T) {
	cr, _ := createCertificateRequest(t, "foo", []string{"foo.com", "foo@foo.com", "::1", "https://foo.com"})
	crRSA, _ := createRSACertificateRequest(t, 2048, "foo", []string{"foo.com", "foo@foo.com", "::1", "https://foo.com"})
	type args struct {
		text string
		data TemplateData
		cr   *x509.CertificateRequest
	}
	tests := []struct {
		name    string
		args    args
		want    Options
		wantErr bool
	}{
		{"leaf", args{DefaultLeafTemplate, TemplateData{
			SubjectKey: Subject{CommonName: "foo"},
			SANsKey:    []SubjectAlternativeName{{Type: "dns", Value: "foo.com"}},
		}, cr}, Options{
			CertBuffer: bytes.NewBufferString(`{
	"subject": {"commonName":"foo"},
	"sans": [{"type":"dns","value":"foo.com"}],
	"keyUsage": ["digitalSignature"],
	"extKeyUsage": ["serverAuth", "clientAuth"]
}`),
		}, false},
		{"leafRSA", args{DefaultLeafTemplate, TemplateData{
			SubjectKey: Subject{CommonName: "foo"},
			SANsKey:    []SubjectAlternativeName{{Type: "dns", Value: "foo.com"}},
		}, crRSA}, Options{
			CertBuffer: bytes.NewBufferString(`{
	"subject": {"commonName":"foo"},
	"sans": [{"type":"dns","value":"foo.com"}],
	"keyUsage": ["keyEncipherment", "digitalSignature"],
	"extKeyUsage": ["serverAuth", "clientAuth"]
}`),
		}, false},
		{"iid", args{DefaultIIDLeafTemplate, TemplateData{}, cr}, Options{
			CertBuffer: bytes.NewBufferString(`{
	"subject": {"commonName":"foo"},
	"dnsNames": ["foo.com"],
	"emailAddresses": ["foo@foo.com"],
	"ipAddresses": ["::1"],
	"uris": ["https://foo.com"],
	"keyUsage": ["digitalSignature"],
	"extKeyUsage": ["serverAuth", "clientAuth"]
}`),
		}, false},
		{"iidRSAAndEnforced", args{DefaultIIDLeafTemplate, TemplateData{
			SANsKey: []SubjectAlternativeName{{Type: "dns", Value: "foo.com"}},
		}, crRSA}, Options{
			CertBuffer: bytes.NewBufferString(`{
	"subject": {"commonName":"foo"},
	"sans": [{"type":"dns","value":"foo.com"}],
	"keyUsage": ["keyEncipherment", "digitalSignature"],
	"extKeyUsage": ["serverAuth", "clientAuth"]
}`),
		}, false},
		{"fail", args{`{{ fail "a message" }}`, TemplateData{}, cr}, Options{}, true},
		{"error", args{`{{ mustHas 3 .Data }}`, TemplateData{
			"Data": 3,
		}, cr}, Options{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Options
			fn := WithTemplate(tt.args.text, tt.args.data)
			if err := fn(tt.args.cr, &got); (err != nil) != tt.wantErr {
				t.Errorf("WithTemplate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("WithTemplate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWithTemplateBase64(t *testing.T) {
	cr, _ := createCertificateRequest(t, "foo", []string{"foo.com", "foo@foo.com", "::1", "https://foo.com"})
	type args struct {
		s    string
		data TemplateData
		cr   *x509.CertificateRequest
	}
	tests := []struct {
		name    string
		args    args
		want    Options
		wantErr bool
	}{
		{"leaf", args{base64.StdEncoding.EncodeToString([]byte(DefaultLeafTemplate)), TemplateData{
			SubjectKey: Subject{CommonName: "foo"},
			SANsKey:    []SubjectAlternativeName{{Type: "dns", Value: "foo.com"}},
		}, cr}, Options{
			CertBuffer: bytes.NewBufferString(`{
	"subject": {"commonName":"foo"},
	"sans": [{"type":"dns","value":"foo.com"}],
	"keyUsage": ["digitalSignature"],
	"extKeyUsage": ["serverAuth", "clientAuth"]
}`),
		}, false},
		{"badBase64", args{"foobar", TemplateData{}, cr}, Options{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Options
			fn := WithTemplateBase64(tt.args.s, tt.args.data)
			if err := fn(tt.args.cr, &got); (err != nil) != tt.wantErr {
				t.Errorf("WithTemplateBase64() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("WithTemplateBase64() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWithTemplateFile(t *testing.T) {
	cr, _ := createCertificateRequest(t, "foo", []string{"foo.com", "foo@foo.com", "::1", "https://foo.com"})
	rsa2048, _ := createRSACertificateRequest(t, 2048, "foo", []string{"foo.com", "foo@foo.com", "::1", "https://foo.com"})
	rsa3072, _ := createRSACertificateRequest(t, 3072, "foo", []string{"foo.com", "foo@foo.com", "::1", "https://foo.com"})

	data := TemplateData{
		SANsKey: []SubjectAlternativeName{
			{Type: "dns", Value: "foo.com"},
			{Type: "email", Value: "root@foo.com"},
			{Type: "ip", Value: "127.0.0.1"},
			{Type: "uri", Value: "uri:foo:bar"},
		},
		TokenKey: map[string]interface{}{
			"iss": "https://iss",
			"sub": "sub",
		},
	}
	type args struct {
		path string
		data TemplateData
		cr   *x509.CertificateRequest
	}
	tests := []struct {
		name    string
		args    args
		want    Options
		wantErr bool
	}{
		{"example", args{"./testdata/example.tpl", data, cr}, Options{
			CertBuffer: bytes.NewBufferString(`{
	"subject": {"commonName":"foo"},
	"sans": [{"type":"dns","value":"foo.com"},{"type":"email","value":"root@foo.com"},{"type":"ip","value":"127.0.0.1"},{"type":"uri","value":"uri:foo:bar"}],
	"emailAddresses": ["foo@foo.com"],
	"uris": "https://iss#sub",
	"keyUsage": ["digitalSignature"],
	"extKeyUsage": ["serverAuth", "clientAuth"]
}`),
		}, false},
		{"exampleRSA3072", args{"./testdata/example.tpl", data, rsa3072}, Options{
			CertBuffer: bytes.NewBufferString(`{
	"subject": {"commonName":"foo"},
	"sans": [{"type":"dns","value":"foo.com"},{"type":"email","value":"root@foo.com"},{"type":"ip","value":"127.0.0.1"},{"type":"uri","value":"uri:foo:bar"}],
	"emailAddresses": ["foo@foo.com"],
	"uris": "https://iss#sub",
	"keyUsage": ["keyEncipherment", "digitalSignature"],
	"extKeyUsage": ["serverAuth", "clientAuth"]
}`),
		}, false},
		{"exampleRSA2048", args{"./testdata/example.tpl", data, rsa2048}, Options{}, true},
		{"missing", args{"./testdata/missing.tpl", data, cr}, Options{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Options
			fn := WithTemplateFile(tt.args.path, tt.args.data)
			if err := fn(tt.args.cr, &got); (err != nil) != tt.wantErr {
				t.Errorf("WithTemplateFile() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("WithTemplateFile() = %v, want %v", got, tt.want)
			}
		})
	}
}
