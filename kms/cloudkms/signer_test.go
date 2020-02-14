package cloudkms

import (
	"context"
	"crypto"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"reflect"
	"testing"

	gax "github.com/googleapis/gax-go/v2"
	"github.com/smallstep/cli/crypto/pemutil"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

func Test_newSigner(t *testing.T) {
	type args struct {
		c          KeyManagementClient
		signingKey string
	}
	tests := []struct {
		name string
		args args
		want *Signer
	}{
		{"ok", args{&MockClient{}, "signingKey"}, &Signer{client: &MockClient{}, signingKey: "signingKey"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewSigner(tt.args.c, tt.args.signingKey); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newSigner() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_signer_Public(t *testing.T) {
	keyName := "projects/p/locations/l/keyRings/k/cryptoKeys/c/cryptoKeyVersions/1"
	testError := fmt.Errorf("an error")

	pemBytes, err := ioutil.ReadFile("testdata/pub.pem")
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
	}
	tests := []struct {
		name    string
		fields  fields
		want    crypto.PublicKey
		wantErr bool
	}{
		{"ok", fields{&MockClient{
			getPublicKey: func(_ context.Context, _ *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
				return &kmspb.PublicKey{Pem: string(pemBytes)}, nil
			},
		}, keyName}, pk, false},
		{"fail get public key", fields{&MockClient{
			getPublicKey: func(_ context.Context, _ *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
				return nil, testError
			},
		}, keyName}, nil, true},
		{"fail parse pem", fields{
			&MockClient{
				getPublicKey: func(_ context.Context, _ *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
					return &kmspb.PublicKey{Pem: string("bad pem")}, nil
				},
			}, keyName}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Signer{
				client:     tt.fields.client,
				signingKey: tt.fields.signingKey,
			}
			got := s.Public()
			if _, ok := got.(error); ok != tt.wantErr {
				t.Errorf("signer.Public() error = %v, wantErr %v", got, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
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
