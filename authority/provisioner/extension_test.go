package provisioner

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"reflect"
	"testing"

	"go.step.sm/crypto/pemutil"
)

func TestExtension_Marshal(t *testing.T) {
	type fields struct {
		Type          Type
		Name          string
		CredentialID  string
		KeyValuePairs []string
	}
	tests := []struct {
		name    string
		fields  fields
		want    []byte
		wantErr bool
	}{
		{"ok", fields{TypeJWK, "name", "credentialID", nil}, []byte{
			0x30, 0x17, 0x02, 0x01, 0x01, 0x04, 0x04, 0x6e,
			0x61, 0x6d, 0x65, 0x04, 0x0c, 0x63, 0x72, 0x65,
			0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x49,
			0x44,
		}, false},
		{"ok with pairs", fields{TypeJWK, "name", "credentialID", []string{"foo", "bar"}}, []byte{
			0x30, 0x23, 0x02, 0x01, 0x01, 0x04, 0x04, 0x6e,
			0x61, 0x6d, 0x65, 0x04, 0x0c, 0x63, 0x72, 0x65,
			0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x49,
			0x44, 0x30, 0x0a, 0x13, 0x03, 0x66, 0x6f, 0x6f,
			0x13, 0x03, 0x62, 0x61, 0x72,
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Extension{
				Type:          tt.fields.Type,
				Name:          tt.fields.Name,
				CredentialID:  tt.fields.CredentialID,
				KeyValuePairs: tt.fields.KeyValuePairs,
			}
			got, err := e.Marshal()
			if (err != nil) != tt.wantErr {
				t.Errorf("Extension.Marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Extension.Marshal() = %x, want %v", got, tt.want)
			}
		})
	}
}

func TestExtension_ToExtension(t *testing.T) {
	type fields struct {
		Type          Type
		Name          string
		CredentialID  string
		KeyValuePairs []string
	}
	tests := []struct {
		name    string
		fields  fields
		want    pkix.Extension
		wantErr bool
	}{
		{"ok", fields{TypeJWK, "name", "credentialID", nil}, pkix.Extension{
			Id: StepOIDProvisioner,
			Value: []byte{
				0x30, 0x17, 0x02, 0x01, 0x01, 0x04, 0x04, 0x6e,
				0x61, 0x6d, 0x65, 0x04, 0x0c, 0x63, 0x72, 0x65,
				0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x49,
				0x44,
			},
		}, false},
		{"ok empty pairs", fields{TypeJWK, "name", "credentialID", []string{}}, pkix.Extension{
			Id: StepOIDProvisioner,
			Value: []byte{
				0x30, 0x17, 0x02, 0x01, 0x01, 0x04, 0x04, 0x6e,
				0x61, 0x6d, 0x65, 0x04, 0x0c, 0x63, 0x72, 0x65,
				0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x49,
				0x44,
			},
		}, false},
		{"ok with pairs", fields{TypeJWK, "name", "credentialID", []string{"foo", "bar"}}, pkix.Extension{
			Id: StepOIDProvisioner,
			Value: []byte{
				0x30, 0x23, 0x02, 0x01, 0x01, 0x04, 0x04, 0x6e,
				0x61, 0x6d, 0x65, 0x04, 0x0c, 0x63, 0x72, 0x65,
				0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x49,
				0x44, 0x30, 0x0a, 0x13, 0x03, 0x66, 0x6f, 0x6f,
				0x13, 0x03, 0x62, 0x61, 0x72,
			},
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Extension{
				Type:          tt.fields.Type,
				Name:          tt.fields.Name,
				CredentialID:  tt.fields.CredentialID,
				KeyValuePairs: tt.fields.KeyValuePairs,
			}
			got, err := e.ToExtension()
			if (err != nil) != tt.wantErr {
				t.Errorf("Extension.ToExtension() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Extension.ToExtension() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetProvisionerExtension(t *testing.T) {
	mustCertificate := func(fn string) *x509.Certificate {
		cert, err := pemutil.ReadCertificate(fn)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}

	type args struct {
		cert *x509.Certificate
	}
	tests := []struct {
		name  string
		args  args
		want  *Extension
		want1 bool
	}{
		{"ok", args{mustCertificate("testdata/certs/good-extension.crt")}, &Extension{
			Type:         TypeJWK,
			Name:         "mariano@smallstep.com",
			CredentialID: "nvgnR8wSzpUlrt_tC3mvrhwhBx9Y7T1WL_JjcFVWYBQ",
		}, true},
		{"fail unmarshal", args{mustCertificate("testdata/certs/bad-extension.crt")}, nil, false},
		{"missing extension", args{mustCertificate("testdata/certs/aws.crt")}, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := GetProvisionerExtension(tt.args.cert)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetProvisionerExtension() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("GetProvisionerExtension() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
