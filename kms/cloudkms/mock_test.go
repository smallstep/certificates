package cloudkms

import (
	"context"

	gax "github.com/googleapis/gax-go/v2"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

type MockClient struct {
	close                  func() error
	getPublicKey           func(context.Context, *kmspb.GetPublicKeyRequest, ...gax.CallOption) (*kmspb.PublicKey, error)
	asymmetricSign         func(context.Context, *kmspb.AsymmetricSignRequest, ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error)
	createCryptoKey        func(context.Context, *kmspb.CreateCryptoKeyRequest, ...gax.CallOption) (*kmspb.CryptoKey, error)
	getKeyRing             func(context.Context, *kmspb.GetKeyRingRequest, ...gax.CallOption) (*kmspb.KeyRing, error)
	createKeyRing          func(context.Context, *kmspb.CreateKeyRingRequest, ...gax.CallOption) (*kmspb.KeyRing, error)
	createCryptoKeyVersion func(context.Context, *kmspb.CreateCryptoKeyVersionRequest, ...gax.CallOption) (*kmspb.CryptoKeyVersion, error)
}

func (m *MockClient) Close() error {
	return m.close()
}

func (m *MockClient) GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...gax.CallOption) (*kmspb.PublicKey, error) {
	return m.getPublicKey(ctx, req, opts...)
}

func (m *MockClient) AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error) {
	return m.asymmetricSign(ctx, req, opts...)
}

func (m *MockClient) CreateCryptoKey(ctx context.Context, req *kmspb.CreateCryptoKeyRequest, opts ...gax.CallOption) (*kmspb.CryptoKey, error) {
	return m.createCryptoKey(ctx, req, opts...)
}

func (m *MockClient) GetKeyRing(ctx context.Context, req *kmspb.GetKeyRingRequest, opts ...gax.CallOption) (*kmspb.KeyRing, error) {
	return m.getKeyRing(ctx, req, opts...)
}

func (m *MockClient) CreateKeyRing(ctx context.Context, req *kmspb.CreateKeyRingRequest, opts ...gax.CallOption) (*kmspb.KeyRing, error) {
	return m.createKeyRing(ctx, req, opts...)
}

func (m *MockClient) CreateCryptoKeyVersion(ctx context.Context, req *kmspb.CreateCryptoKeyVersionRequest, opts ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	return m.createCryptoKeyVersion(ctx, req, opts...)
}
