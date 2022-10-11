package pki

import (
	"bytes"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"

	"github.com/smallstep/certificates/cas/apiv1"
)

func TestPKI_WriteHelmTemplate(t *testing.T) {
	type fields struct {
		casOptions apiv1.Options
		pkiOptions []Option
	}
	tests := []struct {
		name     string
		fields   fields
		testFile string
		wantErr  bool
	}{
		{
			name: "ok/simple",
			fields: fields{
				pkiOptions: []Option{
					WithHelm(),
				},
				casOptions: apiv1.Options{
					Type:      "softcas",
					IsCreator: true,
				},
			},
			testFile: "testdata/helm/simple.yml",
			wantErr:  false,
		},
		{
			name: "ok/with-acme",
			fields: fields{
				pkiOptions: []Option{
					WithHelm(),
					WithACME(),
				},
				casOptions: apiv1.Options{
					Type:      "softcas",
					IsCreator: true,
				},
			},
			testFile: "testdata/helm/with-acme.yml",
			wantErr:  false,
		},
		{
			name: "ok/with-admin",
			fields: fields{
				pkiOptions: []Option{
					WithHelm(),
					WithAdmin(),
				},
				casOptions: apiv1.Options{
					Type:      "softcas",
					IsCreator: true,
				},
			},
			testFile: "testdata/helm/with-admin.yml",
			wantErr:  false,
		},
		{
			name: "ok/with-ssh",
			fields: fields{
				pkiOptions: []Option{
					WithHelm(),
					WithSSH(),
				},
				casOptions: apiv1.Options{
					Type:      "softcas",
					IsCreator: true,
				},
			},
			testFile: "testdata/helm/with-ssh.yml",
			wantErr:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := tt.fields.casOptions
			opts := tt.fields.pkiOptions
			// TODO(hs): invoking `New` doesn't perform all operations that are executed
			// when `ca init --helm` is executed. The list of provisioners on the authority
			// is not populated, for example, resulting in this test not being entirely
			// realistic. Ideally this logic should be handled in one place and probably
			// inside of the PKI initialization, but if that becomes messy, some more
			// logic needs to be performed here to get the PKI instance in good shape.
			p, err := New(o, opts...)
			assert.NoError(t, err)
			w := &bytes.Buffer{}
			if err := p.WriteHelmTemplate(w); (err != nil) != tt.wantErr {
				t.Errorf("PKI.WriteHelmTemplate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			wantBytes, err := os.ReadFile(tt.testFile)
			assert.NoError(t, err)
			if diff := cmp.Diff(wantBytes, w.Bytes()); diff != "" {
				t.Logf("Generated Helm template did not match reference %q\n", tt.testFile)
				t.Errorf("Diff follows:\n%s\n", diff)
			}
		})
	}
}
