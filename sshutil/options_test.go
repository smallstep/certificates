package sshutil

import (
	"bytes"
	"encoding/base64"
	"reflect"
	"testing"

	"github.com/pkg/errors"
)

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
	key := mustGeneratePublicKey(t)
	cr := CertificateRequest{
		Key: key,
	}

	type args struct {
		text string
		data TemplateData
		cr   CertificateRequest
	}
	tests := []struct {
		name    string
		args    args
		want    Options
		wantErr bool
	}{
		{"user", args{DefaultCertificate, TemplateData{
			TypeKey:       "user",
			KeyIDKey:      "jane@doe.com",
			PrincipalsKey: []string{"jane", "jane@doe.com"},
			ExtensionsKey: DefaultExtensions(UserCert),
		}, cr}, Options{
			CertBuffer: bytes.NewBufferString(`{
	"type": "user",
	"keyId": "jane@doe.com",
	"principals": ["jane","jane@doe.com"],
	"extensions": {"permit-X11-forwarding":"","permit-agent-forwarding":"","permit-port-forwarding":"","permit-pty":"","permit-user-rc":""},
	"criticalOptions": null
}`)}, false},
		{"host", args{DefaultCertificate, TemplateData{
			TypeKey:            "host",
			KeyIDKey:           "foo",
			PrincipalsKey:      []string{"foo.internal"},
			CriticalOptionsKey: map[string]string{"foo": "bar"},
		}, cr}, Options{
			CertBuffer: bytes.NewBufferString(`{
	"type": "host",
	"keyId": "foo",
	"principals": ["foo.internal"],
	"extensions": null,
	"criticalOptions": {"foo":"bar"}
}`)}, false},
		{"fail", args{`{{ fail "a message" }}`, TemplateData{}, cr}, Options{}, true},
		{"failTemplate", args{`{{ fail "fatal error }}`, TemplateData{}, cr}, Options{}, true},
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
	key := mustGeneratePublicKey(t)
	cr := CertificateRequest{
		Key: key,
	}

	type args struct {
		s    string
		data TemplateData
		cr   CertificateRequest
	}
	tests := []struct {
		name    string
		args    args
		want    Options
		wantErr bool
	}{
		{"host", args{base64.StdEncoding.EncodeToString([]byte(DefaultCertificate)), TemplateData{
			TypeKey:            "host",
			KeyIDKey:           "foo.internal",
			PrincipalsKey:      []string{"foo.internal", "bar.internal"},
			ExtensionsKey:      map[string]interface{}{"foo": "bar"},
			CriticalOptionsKey: map[string]interface{}{"bar": "foo"},
		}, cr}, Options{
			CertBuffer: bytes.NewBufferString(`{
	"type": "host",
	"keyId": "foo.internal",
	"principals": ["foo.internal","bar.internal"],
	"extensions": {"foo":"bar"},
	"criticalOptions": {"bar":"foo"}
}`)}, false},
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
	key := mustGeneratePublicKey(t)
	cr := CertificateRequest{
		Key: key,
	}

	data := TemplateData{
		TypeKey:       "user",
		KeyIDKey:      "jane@doe.com",
		PrincipalsKey: []string{"jane", "jane@doe.com"},
		ExtensionsKey: DefaultExtensions(UserCert),
		InsecureKey: TemplateData{
			UserKey: map[string]interface{}{
				"username": "jane",
			},
		},
	}

	type args struct {
		path string
		data TemplateData
		cr   CertificateRequest
	}
	tests := []struct {
		name    string
		args    args
		want    Options
		wantErr bool
	}{
		{"github.com", args{"./testdata/github.tpl", data, cr}, Options{
			CertBuffer: bytes.NewBufferString(`{
	"type": "user",
	"keyId": "jane@doe.com",
	"principals": ["jane","jane@doe.com"],
	"extensions": {"login@github.com":"jane","permit-X11-forwarding":"","permit-agent-forwarding":"","permit-port-forwarding":"","permit-pty":"","permit-user-rc":""}
}`),
		}, false},
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
