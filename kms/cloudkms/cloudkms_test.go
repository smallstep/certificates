package cloudkms

import (
	"context"
	"crypto"
	"fmt"
	"os"
	"reflect"
	"testing"

	gax "github.com/googleapis/gax-go/v2"
	"github.com/smallstep/certificates/kms/apiv1"
	"go.step.sm/crypto/pemutil"
	"google.golang.org/api/option"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestParent(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name  string
		args  args
		want  string
		want1 string
	}{
		{"zero", args{"child"}, "", "child"},
		{"one", args{"parent/child"}, "", "child"},
		{"two", args{"grandparent/parent/child"}, "grandparent", "child"},
		{"three", args{"great-grandparent/grandparent/parent/child"}, "great-grandparent/grandparent", "child"},
		{"empty", args{""}, "", ""},
		{"root", args{"/"}, "", ""},
		{"child", args{"/child"}, "", "child"},
		{"parent", args{"parent/"}, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := Parent(tt.args.name)
			if got != tt.want {
				t.Errorf("Parent() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("Parent() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestNew(t *testing.T) {
	tmp := newKeyManagementClient
	t.Cleanup(func() {
		newKeyManagementClient = tmp
	})
	newKeyManagementClient = func(ctx context.Context, opts ...option.ClientOption) (KeyManagementClient, error) {
		if len(opts) > 0 {
			return nil, fmt.Errorf("test error")
		}
		return &MockClient{}, nil
	}

	type args struct {
		ctx  context.Context
		opts apiv1.Options
	}
	tests := []struct {
		name    string
		args    args
		want    *CloudKMS
		wantErr bool
	}{
		{"ok", args{context.Background(), apiv1.Options{}}, &CloudKMS{client: &MockClient{}}, false},
		{"ok with uri", args{context.Background(), apiv1.Options{URI: "cloudkms:"}}, &CloudKMS{client: &MockClient{}}, false},
		{"fail credentials", args{context.Background(), apiv1.Options{CredentialsFile: "testdata/missing"}}, nil, true},
		{"fail with uri", args{context.Background(), apiv1.Options{URI: "cloudkms:credentials-file=testdata/missing"}}, nil, true},
		{"fail schema", args{context.Background(), apiv1.Options{URI: "pkcs11:"}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.args.ctx, tt.args.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNew_real(t *testing.T) {
	type args struct {
		ctx  context.Context
		opts apiv1.Options
	}
	tests := []struct {
		name    string
		args    args
		want    *CloudKMS
		wantErr bool
	}{
		{"fail credentials", args{context.Background(), apiv1.Options{CredentialsFile: "testdata/missing"}}, nil, true},
		{"fail with uri", args{context.Background(), apiv1.Options{URI: "cloudkms:credentials-file=testdata/missing"}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.args.ctx, tt.args.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewCloudKMS(t *testing.T) {
	type args struct {
		client KeyManagementClient
	}
	tests := []struct {
		name string
		args args
		want *CloudKMS
	}{
		{"ok", args{&MockClient{}}, &CloudKMS{&MockClient{}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewCloudKMS(tt.args.client); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewCloudKMS() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCloudKMS_Close(t *testing.T) {
	type fields struct {
		client KeyManagementClient
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{"ok", fields{&MockClient{close: func() error { return nil }}}, false},
		{"fail", fields{&MockClient{close: func() error { return fmt.Errorf("an error") }}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &CloudKMS{
				client: tt.fields.client,
			}
			if err := k.Close(); (err != nil) != tt.wantErr {
				t.Errorf("CloudKMS.Close() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCloudKMS_CreateSigner(t *testing.T) {
	keyName := "projects/p/locations/l/keyRings/k/cryptoKeys/c/cryptoKeyVersions/1"
	pemBytes, err := os.ReadFile("testdata/pub.pem")
	if err != nil {
		t.Fatal(err)
	}
	pk, err := pemutil.ParseKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}

	type fields struct {
		client KeyManagementClient
	}
	type args struct {
		req *apiv1.CreateSignerRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    crypto.Signer
		wantErr bool
	}{
		{"ok", fields{&MockClient{
			getPublicKey: func(_ context.Context, _ *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
				return &kmspb.PublicKey{Pem: string(pemBytes)}, nil
			},
		}}, args{&apiv1.CreateSignerRequest{SigningKey: keyName}}, &Signer{client: &MockClient{}, signingKey: keyName, publicKey: pk}, false},
		{"fail", fields{&MockClient{
			getPublicKey: func(_ context.Context, _ *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
				return nil, fmt.Errorf("test error")
			},
		}}, args{&apiv1.CreateSignerRequest{SigningKey: ""}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &CloudKMS{
				client: tt.fields.client,
			}
			got, err := k.CreateSigner(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("CloudKMS.CreateSigner() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if signer, ok := got.(*Signer); ok {
				signer.client = &MockClient{}
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CloudKMS.CreateSigner() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCloudKMS_CreateKey(t *testing.T) {
	keyName := "projects/p/locations/l/keyRings/k/cryptoKeys/c"
	testError := fmt.Errorf("an error")
	alreadyExists := status.Error(codes.AlreadyExists, "already exists")

	pemBytes, err := os.ReadFile("testdata/pub.pem")
	if err != nil {
		t.Fatal(err)
	}
	pk, err := pemutil.ParseKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}

	var retries int
	type fields struct {
		client KeyManagementClient
	}
	type args struct {
		req *apiv1.CreateKeyRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *apiv1.CreateKeyResponse
		wantErr bool
	}{
		{"ok", fields{
			&MockClient{
				getKeyRing: func(_ context.Context, _ *kmspb.GetKeyRingRequest, _ ...gax.CallOption) (*kmspb.KeyRing, error) {
					return &kmspb.KeyRing{}, nil
				},
				createCryptoKey: func(_ context.Context, _ *kmspb.CreateCryptoKeyRequest, _ ...gax.CallOption) (*kmspb.CryptoKey, error) {
					return &kmspb.CryptoKey{Name: keyName}, nil
				},
				getPublicKey: func(_ context.Context, _ *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
					return &kmspb.PublicKey{Pem: string(pemBytes)}, nil
				},
			}},
			args{&apiv1.CreateKeyRequest{Name: keyName, ProtectionLevel: apiv1.HSM, SignatureAlgorithm: apiv1.ECDSAWithSHA256}},
			&apiv1.CreateKeyResponse{Name: keyName + "/cryptoKeyVersions/1", PublicKey: pk, CreateSignerRequest: apiv1.CreateSignerRequest{SigningKey: keyName + "/cryptoKeyVersions/1"}}, false},
		{"ok new key ring", fields{
			&MockClient{
				getKeyRing: func(_ context.Context, _ *kmspb.GetKeyRingRequest, _ ...gax.CallOption) (*kmspb.KeyRing, error) {
					return nil, testError
				},
				createKeyRing: func(_ context.Context, _ *kmspb.CreateKeyRingRequest, _ ...gax.CallOption) (*kmspb.KeyRing, error) {
					return nil, alreadyExists
				},
				createCryptoKey: func(_ context.Context, _ *kmspb.CreateCryptoKeyRequest, _ ...gax.CallOption) (*kmspb.CryptoKey, error) {
					return &kmspb.CryptoKey{Name: keyName}, nil
				},
				getPublicKey: func(_ context.Context, _ *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
					return &kmspb.PublicKey{Pem: string(pemBytes)}, nil
				},
			}},
			args{&apiv1.CreateKeyRequest{Name: keyName, ProtectionLevel: apiv1.Software, SignatureAlgorithm: apiv1.SHA256WithRSA, Bits: 3072}},
			&apiv1.CreateKeyResponse{Name: keyName + "/cryptoKeyVersions/1", PublicKey: pk, CreateSignerRequest: apiv1.CreateSignerRequest{SigningKey: keyName + "/cryptoKeyVersions/1"}}, false},
		{"ok new key version", fields{
			&MockClient{
				getKeyRing: func(_ context.Context, _ *kmspb.GetKeyRingRequest, _ ...gax.CallOption) (*kmspb.KeyRing, error) {
					return &kmspb.KeyRing{}, nil
				},
				createCryptoKey: func(_ context.Context, _ *kmspb.CreateCryptoKeyRequest, _ ...gax.CallOption) (*kmspb.CryptoKey, error) {
					return nil, alreadyExists
				},
				createCryptoKeyVersion: func(_ context.Context, _ *kmspb.CreateCryptoKeyVersionRequest, _ ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
					return &kmspb.CryptoKeyVersion{Name: keyName + "/cryptoKeyVersions/2"}, nil
				},
				getPublicKey: func(_ context.Context, _ *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
					return &kmspb.PublicKey{Pem: string(pemBytes)}, nil
				},
			}},
			args{&apiv1.CreateKeyRequest{Name: keyName, ProtectionLevel: apiv1.HSM, SignatureAlgorithm: apiv1.ECDSAWithSHA256}},
			&apiv1.CreateKeyResponse{Name: keyName + "/cryptoKeyVersions/2", PublicKey: pk, CreateSignerRequest: apiv1.CreateSignerRequest{SigningKey: keyName + "/cryptoKeyVersions/2"}}, false},
		{"ok with retries", fields{
			&MockClient{
				getKeyRing: func(_ context.Context, _ *kmspb.GetKeyRingRequest, _ ...gax.CallOption) (*kmspb.KeyRing, error) {
					return &kmspb.KeyRing{}, nil
				},
				createCryptoKey: func(_ context.Context, _ *kmspb.CreateCryptoKeyRequest, _ ...gax.CallOption) (*kmspb.CryptoKey, error) {
					return &kmspb.CryptoKey{Name: keyName}, nil
				},
				getPublicKey: func(_ context.Context, _ *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
					if retries != 2 {
						retries++
						return nil, status.Error(codes.FailedPrecondition, "key is not enabled, current state is: PENDING_GENERATION")
					}
					return &kmspb.PublicKey{Pem: string(pemBytes)}, nil
				},
			}},
			args{&apiv1.CreateKeyRequest{Name: keyName, ProtectionLevel: apiv1.HSM, SignatureAlgorithm: apiv1.ECDSAWithSHA256}},
			&apiv1.CreateKeyResponse{Name: keyName + "/cryptoKeyVersions/1", PublicKey: pk, CreateSignerRequest: apiv1.CreateSignerRequest{SigningKey: keyName + "/cryptoKeyVersions/1"}}, false},
		{"fail name", fields{&MockClient{}}, args{&apiv1.CreateKeyRequest{}}, nil, true},
		{"fail protection level", fields{&MockClient{}}, args{&apiv1.CreateKeyRequest{Name: keyName, ProtectionLevel: apiv1.ProtectionLevel(100)}}, nil, true},
		{"fail signature algorithm", fields{&MockClient{}}, args{&apiv1.CreateKeyRequest{Name: keyName, ProtectionLevel: apiv1.Software, SignatureAlgorithm: apiv1.SignatureAlgorithm(100)}}, nil, true},
		{"fail number of bits", fields{&MockClient{}}, args{&apiv1.CreateKeyRequest{Name: keyName, ProtectionLevel: apiv1.Software, SignatureAlgorithm: apiv1.SHA256WithRSA, Bits: 1024}},
			nil, true},
		{"fail create key ring", fields{
			&MockClient{
				getKeyRing: func(_ context.Context, _ *kmspb.GetKeyRingRequest, _ ...gax.CallOption) (*kmspb.KeyRing, error) {
					return nil, testError
				},
				createKeyRing: func(_ context.Context, _ *kmspb.CreateKeyRingRequest, _ ...gax.CallOption) (*kmspb.KeyRing, error) {
					return nil, testError
				},
			}},
			args{&apiv1.CreateKeyRequest{Name: keyName, ProtectionLevel: apiv1.HSM, SignatureAlgorithm: apiv1.ECDSAWithSHA256}},
			nil, true},
		{"fail create key", fields{
			&MockClient{
				getKeyRing: func(_ context.Context, _ *kmspb.GetKeyRingRequest, _ ...gax.CallOption) (*kmspb.KeyRing, error) {
					return &kmspb.KeyRing{}, nil
				},
				createCryptoKey: func(_ context.Context, _ *kmspb.CreateCryptoKeyRequest, _ ...gax.CallOption) (*kmspb.CryptoKey, error) {
					return nil, testError
				},
			}},
			args{&apiv1.CreateKeyRequest{Name: keyName, ProtectionLevel: apiv1.HSM, SignatureAlgorithm: apiv1.ECDSAWithSHA256}},
			nil, true},
		{"fail create key version", fields{
			&MockClient{
				getKeyRing: func(_ context.Context, _ *kmspb.GetKeyRingRequest, _ ...gax.CallOption) (*kmspb.KeyRing, error) {
					return &kmspb.KeyRing{}, nil
				},
				createCryptoKey: func(_ context.Context, _ *kmspb.CreateCryptoKeyRequest, _ ...gax.CallOption) (*kmspb.CryptoKey, error) {
					return nil, alreadyExists
				},
				createCryptoKeyVersion: func(_ context.Context, _ *kmspb.CreateCryptoKeyVersionRequest, _ ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
					return nil, testError
				},
			}},
			args{&apiv1.CreateKeyRequest{Name: keyName, ProtectionLevel: apiv1.HSM, SignatureAlgorithm: apiv1.ECDSAWithSHA256}},
			nil, true},
		{"fail get public key", fields{
			&MockClient{
				getKeyRing: func(_ context.Context, _ *kmspb.GetKeyRingRequest, _ ...gax.CallOption) (*kmspb.KeyRing, error) {
					return &kmspb.KeyRing{}, nil
				},
				createCryptoKey: func(_ context.Context, _ *kmspb.CreateCryptoKeyRequest, _ ...gax.CallOption) (*kmspb.CryptoKey, error) {
					return &kmspb.CryptoKey{Name: keyName}, nil
				},
				getPublicKey: func(_ context.Context, _ *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
					return nil, testError
				},
			}},
			args{&apiv1.CreateKeyRequest{Name: keyName, ProtectionLevel: apiv1.HSM, SignatureAlgorithm: apiv1.ECDSAWithSHA256}},
			nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &CloudKMS{
				client: tt.fields.client,
			}
			got, err := k.CreateKey(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("CloudKMS.CreateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CloudKMS.CreateKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCloudKMS_GetPublicKey(t *testing.T) {
	keyName := "projects/p/locations/l/keyRings/k/cryptoKeys/c/cryptoKeyVersions/1"
	testError := fmt.Errorf("an error")

	pemBytes, err := os.ReadFile("testdata/pub.pem")
	if err != nil {
		t.Fatal(err)
	}
	pk, err := pemutil.ParseKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}

	var retries int
	type fields struct {
		client KeyManagementClient
	}
	type args struct {
		req *apiv1.GetPublicKeyRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    crypto.PublicKey
		wantErr bool
	}{
		{"ok", fields{
			&MockClient{
				getPublicKey: func(_ context.Context, _ *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
					return &kmspb.PublicKey{Pem: string(pemBytes)}, nil
				},
			}},
			args{&apiv1.GetPublicKeyRequest{Name: keyName}}, pk, false},
		{"ok with retries", fields{
			&MockClient{
				getPublicKey: func(_ context.Context, _ *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
					if retries != 2 {
						retries++
						return nil, status.Error(codes.FailedPrecondition, "key is not enabled, current state is: PENDING_GENERATION")
					}
					return &kmspb.PublicKey{Pem: string(pemBytes)}, nil
				},
			}},
			args{&apiv1.GetPublicKeyRequest{Name: keyName}}, pk, false},
		{"fail name", fields{&MockClient{}}, args{&apiv1.GetPublicKeyRequest{}}, nil, true},
		{"fail get public key", fields{
			&MockClient{
				getPublicKey: func(_ context.Context, _ *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
					return nil, testError
				},
			}},
			args{&apiv1.GetPublicKeyRequest{Name: keyName}}, nil, true},
		{"fail parse pem", fields{
			&MockClient{
				getPublicKey: func(_ context.Context, _ *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
					return &kmspb.PublicKey{Pem: string("bad pem")}, nil
				},
			}},
			args{&apiv1.GetPublicKeyRequest{Name: keyName}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &CloudKMS{
				client: tt.fields.client,
			}
			got, err := k.GetPublicKey(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("CloudKMS.GetPublicKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CloudKMS.GetPublicKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
