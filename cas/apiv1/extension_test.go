package apiv1

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"reflect"
	"testing"
)

func TestCreateCertificateAuthorityExtension(t *testing.T) {
	type args struct {
		typ           Type
		certificateID string
		keyValuePairs []string
	}
	tests := []struct {
		name    string
		args    args
		want    pkix.Extension
		wantErr bool
	}{
		{"ok", args{Type(CloudCAS), "1ac75689-cd3f-482e-a695-8a13daf39dc4", nil}, pkix.Extension{
			Id:       oidStepCertificateAuthority,
			Critical: false,
			Value: []byte{
				0x30, 0x30, 0x13, 0x08, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x63, 0x61, 0x73, 0x13, 0x24, 0x31, 0x61,
				0x63, 0x37, 0x35, 0x36, 0x38, 0x39, 0x2d, 0x63, 0x64, 0x33, 0x66, 0x2d, 0x34, 0x38, 0x32, 0x65,
				0x2d, 0x61, 0x36, 0x39, 0x35, 0x2d, 0x38, 0x61, 0x31, 0x33, 0x64, 0x61, 0x66, 0x33, 0x39, 0x64,
				0x63, 0x34,
			},
		}, false},
		{"ok", args{Type(CloudCAS), "1ac75689-cd3f-482e-a695-8a13daf39dc4", []string{"foo", "bar"}}, pkix.Extension{
			Id:       oidStepCertificateAuthority,
			Critical: false,
			Value: []byte{
				0x30, 0x3c, 0x13, 0x08, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x63, 0x61, 0x73, 0x13, 0x24, 0x31, 0x61,
				0x63, 0x37, 0x35, 0x36, 0x38, 0x39, 0x2d, 0x63, 0x64, 0x33, 0x66, 0x2d, 0x34, 0x38, 0x32, 0x65,
				0x2d, 0x61, 0x36, 0x39, 0x35, 0x2d, 0x38, 0x61, 0x31, 0x33, 0x64, 0x61, 0x66, 0x33, 0x39, 0x64,
				0x63, 0x34, 0x30, 0x0a, 0x13, 0x03, 0x66, 0x6f, 0x6f, 0x13, 0x03, 0x62, 0x61, 0x72,
			},
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CreateCertificateAuthorityExtension(tt.args.typ, tt.args.certificateID, tt.args.keyValuePairs...)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateCertificateAuthorityExtension() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CreateCertificateAuthorityExtension() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFindCertificateAuthorityExtension(t *testing.T) {
	expected := pkix.Extension{
		Id:    oidStepCertificateAuthority,
		Value: []byte("fake data"),
	}
	type args struct {
		cert *x509.Certificate
	}
	tests := []struct {
		name  string
		args  args
		want  pkix.Extension
		want1 bool
	}{
		{"first", args{&x509.Certificate{Extensions: []pkix.Extension{
			expected,
			{Id: []int{1, 2, 3, 4}},
		}}}, expected, true},
		{"last", args{&x509.Certificate{Extensions: []pkix.Extension{
			{Id: []int{1, 2, 3, 4}},
			{Id: []int{2, 3, 4, 5}},
			expected,
		}}}, expected, true},
		{"fail", args{&x509.Certificate{Extensions: []pkix.Extension{
			{Id: []int{1, 2, 3, 4}},
		}}}, pkix.Extension{}, false},
		{"fail ExtraExtensions", args{&x509.Certificate{ExtraExtensions: []pkix.Extension{
			expected,
			{Id: []int{1, 2, 3, 4}},
		}}}, pkix.Extension{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := FindCertificateAuthorityExtension(tt.args.cert)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FindCertificateAuthorityExtension() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("FindCertificateAuthorityExtension() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestRemoveCertificateAuthorityExtension(t *testing.T) {
	caExt := pkix.Extension{
		Id:    oidStepCertificateAuthority,
		Value: []byte("fake data"),
	}
	type args struct {
		cert *x509.Certificate
	}
	tests := []struct {
		name string
		args args
		want *x509.Certificate
	}{
		{"first", args{&x509.Certificate{ExtraExtensions: []pkix.Extension{
			caExt,
			{Id: []int{1, 2, 3, 4}},
		}}}, &x509.Certificate{ExtraExtensions: []pkix.Extension{
			{Id: []int{1, 2, 3, 4}},
		}}},
		{"last", args{&x509.Certificate{ExtraExtensions: []pkix.Extension{
			{Id: []int{1, 2, 3, 4}},
			caExt,
		}}}, &x509.Certificate{ExtraExtensions: []pkix.Extension{
			{Id: []int{1, 2, 3, 4}},
		}}},
		{"missing", args{&x509.Certificate{ExtraExtensions: []pkix.Extension{
			{Id: []int{1, 2, 3, 4}},
		}}}, &x509.Certificate{ExtraExtensions: []pkix.Extension{
			{Id: []int{1, 2, 3, 4}},
		}}},
		{"extensions", args{&x509.Certificate{Extensions: []pkix.Extension{
			caExt,
			{Id: []int{1, 2, 3, 4}},
		}}}, &x509.Certificate{Extensions: []pkix.Extension{
			caExt,
			{Id: []int{1, 2, 3, 4}},
		}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			RemoveCertificateAuthorityExtension(tt.args.cert)
			if !reflect.DeepEqual(tt.args.cert, tt.want) {
				t.Errorf("RemoveCertificateAuthorityExtension() cert = %v, want %v", tt.args.cert, tt.want)
			}
		})
	}
}
