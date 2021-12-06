package cloudkms

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"reflect"
	"testing"

	gax "github.com/googleapis/gax-go/v2"
	"go.step.sm/crypto/pemutil"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

func Test_newSigner(t *testing.T) {
	pemBytes, err := os.ReadFile("testdata/pub.pem")
	if err != nil {
		t.Fatal(err)
	}
	pk, err := pemutil.ParseKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		c          KeyManagementClient
		signingKey string
	}
	tests := []struct {
		name    string
		args    args
		want    *Signer
		wantErr bool
	}{
		{"ok", args{&MockClient{
			getPublicKey: func(_ context.Context, _ *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
				return &kmspb.PublicKey{Pem: string(pemBytes)}, nil
			},
		}, "signingKey"}, &Signer{client: &MockClient{}, signingKey: "signingKey", publicKey: pk}, false},
		{"fail get public key", args{&MockClient{
			getPublicKey: func(_ context.Context, _ *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
				return nil, fmt.Errorf("an error")
			},
		}, "signingKey"}, nil, true},
		{"fail parse pem", args{&MockClient{
			getPublicKey: func(_ context.Context, _ *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
				return &kmspb.PublicKey{Pem: string("bad pem")}, nil
			},
		}, "signingKey"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewSigner(tt.args.c, tt.args.signingKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSigner() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != nil {
				got.client = &MockClient{}
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewSigner() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_signer_Public(t *testing.T) {
	pemBytes, err := os.ReadFile("testdata/pub.pem")
	if err != nil {
		t.Fatal(err)
	}
	pk, err := pemutil.ParseKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}

	type fields struct {
		client     KeyManagementClient
		signingKey string
		publicKey  crypto.PublicKey
	}
	tests := []struct {
		name   string
		fields fields
		want   crypto.PublicKey
	}{
		{"ok", fields{&MockClient{}, "signingKey", pk}, pk},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Signer{
				client:     tt.fields.client,
				signingKey: tt.fields.signingKey,
				publicKey:  tt.fields.publicKey,
			}
			if got := s.Public(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("signer.Public() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_signer_Sign(t *testing.T) {
	keyName := "projects/p/locations/l/keyRings/k/cryptoKeys/c/cryptoKeyVersions/1"
	okClient := &MockClient{
		asymmetricSign: func(_ context.Context, _ *kmspb.AsymmetricSignRequest, _ ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error) {
			return &kmspb.AsymmetricSignResponse{Signature: []byte("ok signature")}, nil
		},
	}
	failClient := &MockClient{
		asymmetricSign: func(_ context.Context, _ *kmspb.AsymmetricSignRequest, _ ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error) {
			return nil, fmt.Errorf("an error")
		},
	}

	type fields struct {
		client     KeyManagementClient
		signingKey string
	}
	type args struct {
		rand   io.Reader
		digest []byte
		opts   crypto.SignerOpts
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		{"ok sha256", fields{okClient, keyName}, args{rand.Reader, []byte("digest"), crypto.SHA256}, []byte("ok signature"), false},
		{"ok sha384", fields{okClient, keyName}, args{rand.Reader, []byte("digest"), crypto.SHA384}, []byte("ok signature"), false},
		{"ok sha512", fields{okClient, keyName}, args{rand.Reader, []byte("digest"), crypto.SHA512}, []byte("ok signature"), false},
		{"fail MD5", fields{okClient, keyName}, args{rand.Reader, []byte("digest"), crypto.MD5}, nil, true},
		{"fail asymmetric sign", fields{failClient, keyName}, args{rand.Reader, []byte("digest"), crypto.SHA256}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Signer{
				client:     tt.fields.client,
				signingKey: tt.fields.signingKey,
			}
			got, err := s.Sign(tt.args.rand, tt.args.digest, tt.args.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("signer.Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("signer.Sign() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSigner_SignatureAlgorithm(t *testing.T) {
	pemBytes, err := os.ReadFile("testdata/pub.pem")
	if err != nil {
		t.Fatal(err)
	}

	client := &MockClient{
		getPublicKey: func(_ context.Context, req *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
			var algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
			switch req.Name {
			case "ECDSA-SHA256":
				algorithm = kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256
			case "ECDSA-SHA384":
				algorithm = kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384
			case "SHA256-RSA-2048":
				algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256
			case "SHA256-RSA-3072":
				algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256
			case "SHA256-RSA-4096":
				algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256
			case "SHA512-RSA-4096":
				algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512
			case "SHA256-RSAPSS-2048":
				algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256
			case "SHA256-RSAPSS-3072":
				algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256
			case "SHA256-RSAPSS-4096":
				algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256
			case "SHA512-RSAPSS-4096":
				algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512
			}
			return &kmspb.PublicKey{
				Pem:       string(pemBytes),
				Algorithm: algorithm,
			}, nil
		},
	}

	if err != nil {
		t.Fatal(err)
	}

	type fields struct {
		client     KeyManagementClient
		signingKey string
	}
	tests := []struct {
		name   string
		fields fields
		want   x509.SignatureAlgorithm
	}{
		{"ECDSA-SHA256", fields{client, "ECDSA-SHA256"}, x509.ECDSAWithSHA256},
		{"ECDSA-SHA384", fields{client, "ECDSA-SHA384"}, x509.ECDSAWithSHA384},
		{"SHA256-RSA-2048", fields{client, "SHA256-RSA-2048"}, x509.SHA256WithRSA},
		{"SHA256-RSA-3072", fields{client, "SHA256-RSA-3072"}, x509.SHA256WithRSA},
		{"SHA256-RSA-4096", fields{client, "SHA256-RSA-4096"}, x509.SHA256WithRSA},
		{"SHA512-RSA-4096", fields{client, "SHA512-RSA-4096"}, x509.SHA512WithRSA},
		{"SHA256-RSAPSS-2048", fields{client, "SHA256-RSAPSS-2048"}, x509.SHA256WithRSAPSS},
		{"SHA256-RSAPSS-3072", fields{client, "SHA256-RSAPSS-3072"}, x509.SHA256WithRSAPSS},
		{"SHA256-RSAPSS-4096", fields{client, "SHA256-RSAPSS-4096"}, x509.SHA256WithRSAPSS},
		{"SHA512-RSAPSS-4096", fields{client, "SHA512-RSAPSS-4096"}, x509.SHA512WithRSAPSS},
		{"unknown", fields{client, "UNKNOWN"}, x509.UnknownSignatureAlgorithm},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := NewSigner(tt.fields.client, tt.fields.signingKey)
			if err != nil {
				t.Errorf("NewSigner() error = %v", err)
			}
			if got := signer.SignatureAlgorithm(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Signer.SignatureAlgorithm() = %v, want %v", got, tt.want)
			}
		})
	}
}
