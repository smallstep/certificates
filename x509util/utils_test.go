package x509util

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"reflect"
	"testing"
)

func decodeCertificateFile(t *testing.T, filename string) *x509.Certificate {
	t.Helper()
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatal("error decoding pem")
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return crt
}

func Test_generateSubjectKeyID(t *testing.T) {
	ecdsaCrt := decodeCertificateFile(t, "testdata/google.crt")
	rsaCrt := decodeCertificateFile(t, "testdata/smallstep.crt")
	ed25519Crt := decodeCertificateFile(t, "testdata/ed25519.crt")

	type args struct {
		pub crypto.PublicKey
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{"ecdsa", args{ecdsaCrt.PublicKey}, ecdsaCrt.SubjectKeyId, false},
		{"rsa", args{rsaCrt.PublicKey}, rsaCrt.SubjectKeyId, false},
		{"ed25519", args{ed25519Crt.PublicKey}, ed25519Crt.SubjectKeyId, false},
		{"fail", args{[]byte("fail")}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := generateSubjectKeyID(tt.args.pub)
			if (err != nil) != tt.wantErr {
				t.Errorf("generateSubjectKeyID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("generateSubjectKeyID() = %v, want %v", got, tt.want)
			}
		})
	}
}
