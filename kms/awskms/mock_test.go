package awskms

import (
	"encoding/pem"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/kms"
)

type MockClient struct {
	getPublicKeyWithContext func(ctx aws.Context, input *kms.GetPublicKeyInput, opts ...request.Option) (*kms.GetPublicKeyOutput, error)
	createKeyWithContext    func(ctx aws.Context, input *kms.CreateKeyInput, opts ...request.Option) (*kms.CreateKeyOutput, error)
	createAliasWithContext  func(ctx aws.Context, input *kms.CreateAliasInput, opts ...request.Option) (*kms.CreateAliasOutput, error)
	signWithContext         func(ctx aws.Context, input *kms.SignInput, opts ...request.Option) (*kms.SignOutput, error)
}

func (m *MockClient) GetPublicKeyWithContext(ctx aws.Context, input *kms.GetPublicKeyInput, opts ...request.Option) (*kms.GetPublicKeyOutput, error) {
	return m.getPublicKeyWithContext(ctx, input, opts...)
}

func (m *MockClient) CreateKeyWithContext(ctx aws.Context, input *kms.CreateKeyInput, opts ...request.Option) (*kms.CreateKeyOutput, error) {
	return m.createKeyWithContext(ctx, input, opts...)
}

func (m *MockClient) CreateAliasWithContext(ctx aws.Context, input *kms.CreateAliasInput, opts ...request.Option) (*kms.CreateAliasOutput, error) {
	return m.createAliasWithContext(ctx, input, opts...)
}

func (m *MockClient) SignWithContext(ctx aws.Context, input *kms.SignInput, opts ...request.Option) (*kms.SignOutput, error) {
	return m.signWithContext(ctx, input, opts...)
}

const (
	publicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8XWlIWkOThxNjGbZLYUgRHmsvCrW
KF+HLktPfPTIK3lGd1k4849WQs59XIN+LXZQ6b2eRBEBKAHEyQus8UU7gw==
-----END PUBLIC KEY-----`
	keyID = "be468355-ca7a-40d9-a28b-8ae1c4c7f936"
)

var signature = []byte{
	0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
	0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
}

func getOKClient() *MockClient {
	return &MockClient{
		getPublicKeyWithContext: func(ctx aws.Context, input *kms.GetPublicKeyInput, opts ...request.Option) (*kms.GetPublicKeyOutput, error) {
			block, _ := pem.Decode([]byte(publicKey))
			return &kms.GetPublicKeyOutput{
				KeyId:     input.KeyId,
				PublicKey: block.Bytes,
			}, nil
		},
		createKeyWithContext: func(ctx aws.Context, input *kms.CreateKeyInput, opts ...request.Option) (*kms.CreateKeyOutput, error) {
			md := new(kms.KeyMetadata)
			md.SetKeyId(keyID)
			return &kms.CreateKeyOutput{
				KeyMetadata: md,
			}, nil
		},
		createAliasWithContext: func(ctx aws.Context, input *kms.CreateAliasInput, opts ...request.Option) (*kms.CreateAliasOutput, error) {
			return &kms.CreateAliasOutput{}, nil
		},
		signWithContext: func(ctx aws.Context, input *kms.SignInput, opts ...request.Option) (*kms.SignOutput, error) {
			return &kms.SignOutput{
				Signature: signature,
			}, nil
		},
	}
}
