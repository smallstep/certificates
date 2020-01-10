package cloudkms

import (
	"context"
	"crypto"
	"time"

	cloudkms "cloud.google.com/go/kms/apiv1"
	gax "github.com/googleapis/gax-go/v2"
	"github.com/pkg/errors"
	"github.com/smallstep/certificates/kms/apiv1"
	"github.com/smallstep/cli/crypto/pemutil"
	"google.golang.org/api/option"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

// protectionLevelMapping maps step protection levels with cloud kms ones.
var protectionLevelMapping = map[apiv1.ProtectionLevel]kmspb.ProtectionLevel{
	apiv1.UnspecifiedProtectionLevel: kmspb.ProtectionLevel_PROTECTION_LEVEL_UNSPECIFIED,
	apiv1.Software:                   kmspb.ProtectionLevel_SOFTWARE,
	apiv1.HSM:                        kmspb.ProtectionLevel_HSM,
}

// signatureAlgorithmMapping is a mapping between the step signature algorithm,
// and bits for RSA keys, with cloud kms one.
//
// Cloud KMS does not support SHA384WithRSA, SHA384WithRSAPSS, SHA384WithRSAPSS,
// ECDSAWithSHA512, and PureEd25519.
var signatureAlgorithmMapping = map[apiv1.SignatureAlgorithm]interface{}{
	apiv1.UnspecifiedSignAlgorithm: kmspb.CryptoKeyVersion_CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED,
	apiv1.SHA256WithRSA: map[int]kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm{
		0:    kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256,
		2048: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
		3072: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256,
		4096: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256,
	},
	apiv1.SHA512WithRSA: map[int]kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm{
		0:    kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256,
		4096: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256,
	},
	apiv1.SHA256WithRSAPSS: map[int]kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm{
		0:    kmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256,
		2048: kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256,
		3072: kmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256,
		4096: kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256,
	},
	apiv1.SHA512WithRSAPSS: map[int]kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm{
		0:    kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512,
		4096: kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512,
	},
	apiv1.ECDSAWithSHA256: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
	apiv1.ECDSAWithSHA384: kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384,
}

type keyManagementClient interface {
	GetPublicKey(context.Context, *kmspb.GetPublicKeyRequest, ...gax.CallOption) (*kmspb.PublicKey, error)
	AsymmetricSign(context.Context, *kmspb.AsymmetricSignRequest, ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error)
	CreateCryptoKey(context.Context, *kmspb.CreateCryptoKeyRequest, ...gax.CallOption) (*kmspb.CryptoKey, error)
}

// CloudKMS implements a KMS using Google's Cloud apiv1.
type CloudKMS struct {
	client keyManagementClient
}

func New(ctx context.Context, opts apiv1.Options) (*CloudKMS, error) {
	var cloudOpts []option.ClientOption
	if opts.CredentialsFile != "" {
		cloudOpts = append(cloudOpts, option.WithCredentialsFile(opts.CredentialsFile))
	}

	client, err := cloudkms.NewKeyManagementClient(ctx, cloudOpts...)
	if err != nil {
		return nil, err
	}

	return &CloudKMS{
		client: client,
	}, nil
}

// CreateSigner returns a new cloudkms signer configured with the given signing
// key name.
func (k *CloudKMS) CreateSigner(req *apiv1.CreateSignerRequest) (crypto.Signer, error) {
	if req.SigningKey == "" {
		return nil, errors.New("signing key cannot be empty")
	}

	return newSigner(k.client, req.SigningKey), nil
}

// CreateKey creates in Google's Cloud KMS a new asymmetric key for signing.
func (k *CloudKMS) CreateKey(req *apiv1.CreateKeyRequest) (*apiv1.CreateKeyResponse, error) {
	switch {
	case req.Name == "":
		return nil, errors.New("createKeyRequest 'name' cannot be empty")
	case req.Parent == "":
		return nil, errors.New("createKeyRequest 'parent' cannot be empty")
	}

	protectionLevel, ok := protectionLevelMapping[req.ProtectionLevel]
	if !ok {
		return nil, errors.Errorf("cloudKMS does not support protection level '%s'", req.ProtectionLevel)
	}

	var signatureAlgorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
	v, ok := signatureAlgorithmMapping[req.SignatureAlgorithm]
	if !ok {
		return nil, errors.Errorf("cloudKMS does not support signature algorithm '%s'", req.SignatureAlgorithm)
	}
	switch v := v.(type) {
	case kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm:
		signatureAlgorithm = v
	case map[int]kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm:
		if signatureAlgorithm, ok = v[req.Bits]; !ok {
			return nil, errors.Errorf("cloudKMS does not support signature algorithm '%s' with '%d' bits", req.SignatureAlgorithm, req.Bits)
		}
	default:
		return nil, errors.Errorf("unexpected error: this should not happen")
	}

	ctx, cancel := defaultContext()
	defer cancel()

	response, err := k.client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      req.Parent,
		CryptoKeyId: req.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				ProtectionLevel: protectionLevel,
				Algorithm:       signatureAlgorithm,
			},
		},
	})
	if err != nil {
		return nil, errors.Wrap(err, "cloudKMS CreateCryptoKey failed")
	}

	return &apiv1.CreateKeyResponse{
		Name: response.Name,
	}, nil
}

// GetPublicKey gets from Google's Cloud KMS a public key by name. Key names
// follow the pattern:
//   projects/([^/]+)/locations/([a-zA-Z0-9_-]{1,63})/keyRings/([a-zA-Z0-9_-]{1,63})/cryptoKeys/([a-zA-Z0-9_-]{1,63})/cryptoKeyVersions/([a-zA-Z0-9_-]{1,63})
func (k *CloudKMS) GetPublicKey(req *apiv1.GetPublicKeyRequest) (*apiv1.GetPublicKeyResponse, error) {
	ctx, cancel := defaultContext()
	defer cancel()

	response, err := k.client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: req.Name,
	})
	if err != nil {
		return nil, errors.Wrap(err, "cloudKMS GetPublicKey failed")
	}

	pk, err := pemutil.ParseKey([]byte(response.Pem))
	if err != nil {
		return nil, err
	}

	return &apiv1.GetPublicKeyResponse{
		Name:      req.Name,
		PublicKey: pk,
	}, nil
}

func defaultContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 15*time.Second)
}
