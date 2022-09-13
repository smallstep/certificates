package provisioner

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/webhook"
	"go.step.sm/crypto/sshutil"
)

func TestCustomSSHTemplateOptions(t *testing.T) {
	cr := sshutil.CertificateRequest{
		Type:       "user",
		KeyID:      "foo@smallstep.com",
		Principals: []string{"foo"},
	}
	crCertificate := `{"Key":null,"Type":"user","KeyID":"foo@smallstep.com","Principals":["foo"]}`
	data := sshutil.CreateTemplateData(sshutil.HostCert, "smallstep.com", []string{"smallstep.com"})
	type args struct {
		o               *Options
		data            sshutil.TemplateData
		defaultTemplate string
		userOptions     SignSSHOptions
	}
	tests := []struct {
		name             string
		args             args
		want             sshutil.Options
		wantErr          bool
		webhookResponses []webhook.ResponseBody
		wantOptionsErr   bool
	}{
		{"ok", args{nil, data, sshutil.DefaultTemplate, SignSSHOptions{}}, sshutil.Options{
			CertBuffer: bytes.NewBufferString(`{
	"type": "host",
	"keyId": "smallstep.com",
	"principals": ["smallstep.com"],
	"extensions": null,
	"criticalOptions": null
}`),
		}, false, nil, false},
		{"okNoData", args{nil, nil, sshutil.DefaultTemplate, SignSSHOptions{}}, sshutil.Options{
			CertBuffer: bytes.NewBufferString(`{
	"type": null,
	"keyId": null,
	"principals": null,
	"extensions": null,
	"criticalOptions": null
}`),
		}, false, nil, false},
		{"okTemplateData", args{&Options{SSH: &SSHOptions{TemplateData: []byte(`{"foo":"bar"}`)}}, data, sshutil.DefaultTemplate, SignSSHOptions{}}, sshutil.Options{
			CertBuffer: bytes.NewBufferString(`{
	"type": "host",
	"keyId": "smallstep.com",
	"principals": ["smallstep.com"],
	"extensions": null,
	"criticalOptions": null
}`),
		}, false, nil, false},
		{"okNullTemplateData", args{&Options{SSH: &SSHOptions{TemplateData: []byte(`null`)}}, data, sshutil.DefaultTemplate, SignSSHOptions{}}, sshutil.Options{
			CertBuffer: bytes.NewBufferString(`{
	"type": "host",
	"keyId": "smallstep.com",
	"principals": ["smallstep.com"],
	"extensions": null,
	"criticalOptions": null
}`),
		}, false, nil, false},
		// Note: `{{ toJson .Insecure.CR }}` is not a valid ssh template
		{"okTemplate", args{&Options{SSH: &SSHOptions{Template: "{{ toJson .Insecure.CR }}"}}, data, sshutil.DefaultTemplate, SignSSHOptions{}}, sshutil.Options{
			CertBuffer: bytes.NewBufferString(crCertificate)}, false, nil, false},
		{"okFile", args{&Options{SSH: &SSHOptions{TemplateFile: "./testdata/templates/cr.tpl"}}, data, sshutil.DefaultTemplate, SignSSHOptions{}}, sshutil.Options{
			CertBuffer: bytes.NewBufferString(crCertificate)}, false, nil, false},
		{"okBase64", args{&Options{SSH: &SSHOptions{Template: "e3sgdG9Kc29uIC5JbnNlY3VyZS5DUiB9fQ=="}}, data, sshutil.DefaultTemplate, SignSSHOptions{}}, sshutil.Options{
			CertBuffer: bytes.NewBufferString(crCertificate)}, false, nil, false},
		{"okUserOptions", args{&Options{SSH: &SSHOptions{Template: `{"foo": "{{.Insecure.User.foo}}"}`}}, data, sshutil.DefaultTemplate, SignSSHOptions{TemplateData: []byte(`{"foo":"bar"}`)}}, sshutil.Options{
			CertBuffer: bytes.NewBufferString(`{"foo": "bar"}`),
		}, false, nil, false},
		{"okNulUserOptions", args{&Options{SSH: &SSHOptions{Template: `{"foo": "{{.Insecure.User.foo}}"}`}}, data, sshutil.DefaultTemplate, SignSSHOptions{TemplateData: []byte(`null`)}}, sshutil.Options{
			CertBuffer: bytes.NewBufferString(`{"foo": "<no value>"}`),
		}, false, nil, false},
		{"okBadUserOptions", args{&Options{SSH: &SSHOptions{Template: `{"foo": "{{.Insecure.User.foo}}"}`}}, data, sshutil.DefaultTemplate, SignSSHOptions{TemplateData: []byte(`{"badJSON"}`)}}, sshutil.Options{
			CertBuffer: bytes.NewBufferString(`{"foo": "<no value>"}`),
		}, false, nil, false},
		{"fail", args{&Options{SSH: &SSHOptions{TemplateData: []byte(`{"badJSON`)}}, data, sshutil.DefaultTemplate, SignSSHOptions{}}, sshutil.Options{}, true, nil, false},
		{"okWebhook",
			args{
				&Options{
					SSH: &SSHOptions{
						Template: `{"foo": "{{ .Webhooks.people.role }}"}`,
					},
					Webhooks: []*Webhook{{Name: "people", Kind: "ENRICHING"}}},
				sshutil.CreateTemplateData(sshutil.HostCert, "smallstep.com", []string{"smallstep.com"}),
				sshutil.DefaultTemplate,
				SignSSHOptions{
					WebhookClient: http.DefaultClient,
				},
			},
			sshutil.Options{
				CertBuffer: bytes.NewBufferString(`{"foo": "dba"}`),
			},
			false,
			[]webhook.ResponseBody{
				{
					Data: map[string]interface{}{
						"role": "dba",
					},
					Allow: true,
				},
			},
			false,
		},
		{"denyWebhook",
			args{
				&Options{
					SSH: &SSHOptions{
						Template: `{"foo": "{{ .Webhooks.people.role }}"}`,
					},
					Webhooks: []*Webhook{{Name: "people", Kind: "ENRICHING"}}},
				sshutil.CreateTemplateData(sshutil.HostCert, "smallstep.com", []string{"smallstep.com"}),
				sshutil.DefaultTemplate,
				SignSSHOptions{
					WebhookClient: http.DefaultClient,
				},
			},
			sshutil.Options{
				CertBuffer: nil,
			},
			false,
			[]webhook.ResponseBody{
				{
					Allow: false,
				},
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.args.o != nil {
				for i, wh := range tt.args.o.Webhooks {
					ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						err := json.NewEncoder(w).Encode(tt.webhookResponses[i])
						assert.FatalError(t, err)
					}))
					// nolint:gocritic // defer in loop isn't a resource leak
					defer ts.Close()
					wh.URL = ts.URL
				}
			}
			cof, err := CustomSSHTemplateOptions(tt.args.o, tt.args.data, tt.args.defaultTemplate)
			if (err != nil) != tt.wantErr {
				t.Errorf("CustomSSHTemplateOptions() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			var opts sshutil.Options
			if cof != nil {
				gotOptionErr := false
				for _, fn := range cof.Options(tt.args.userOptions) {
					if err := fn(cr, &opts); err != nil {
						if tt.wantOptionsErr {
							gotOptionErr = true
							continue
						}
						t.Errorf("x509util.Options() error = %v", err)
						return
					}
				}
				if tt.wantOptionsErr {
					assert.True(t, gotOptionErr)
				}
			}
			if !reflect.DeepEqual(opts, tt.want) {
				t.Errorf("CustomSSHTemplateOptions() = %v, want %v", opts, tt.want)
			}
		})
	}
}
