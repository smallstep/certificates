package cloudkms

import (
	"context"
	"crypto"
	"crypto/x509"
	"log"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	cloudkms "cloud.google.com/go/kms/apiv1"
	gax "github.com/googleapis/gax-go/v2"
	"github.com/pkg/errors"
	"github.com/smallstep/certificates/kms/apiv1"
	"github.com/smallstep/certificates/kms/uri"
	"go.step.sm/crypto/pemutil"
	"google.golang.org/api/option"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

// Scheme is the scheme used in uris.
const Scheme = "cloudkms"

const pendingGenerationRetries = 10

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
		0:    kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512,
		4096: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512,
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

var cryptoKeyVersionMapping = map[kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm]x509.SignatureAlgorithm{
	kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256:        x509.ECDSAWithSHA256,
	kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384:        x509.ECDSAWithSHA384,
	kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256: x509.SHA256WithRSA,
	kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256: x509.SHA256WithRSA,
	kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256: x509.SHA256WithRSA,
	kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512: x509.SHA512WithRSA,
	kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256:   x509.SHA256WithRSAPSS,
	kmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256:   x509.SHA256WithRSAPSS,
	kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256:   x509.SHA256WithRSAPSS,
	kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512:   x509.SHA512WithRSAPSS,
}

// KeyManagementClient defines the methods on KeyManagementClient that this
// package will use. This interface will be used for unit testing.
type KeyManagementClient interface {
	Close() error
	GetPublicKey(context.Context, *kmspb.GetPublicKeyRequest, ...gax.CallOption) (*kmspb.PublicKey, error)
	AsymmetricSign(context.Context, *kmspb.AsymmetricSignRequest, ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error)
	CreateCryptoKey(context.Context, *kmspb.CreateCryptoKeyRequest, ...gax.CallOption) (*kmspb.CryptoKey, error)
	GetKeyRing(context.Context, *kmspb.GetKeyRingRequest, ...gax.CallOption) (*kmspb.KeyRing, error)
	CreateKeyRing(context.Context, *kmspb.CreateKeyRingRequest, ...gax.CallOption) (*kmspb.KeyRing, error)
	CreateCryptoKeyVersion(ctx context.Context, req *kmspb.CreateCryptoKeyVersionRequest, opts ...gax.CallOption) (*kmspb.CryptoKeyVersion, error)
}

var newKeyManagementClient = func(ctx context.Context, opts ...option.ClientOption) (KeyManagementClient, error) {
	return cloudkms.NewKeyManagementClient(ctx, opts...)
}

// CloudKMS implements a KMS using Google's Cloud apiv1.
type CloudKMS struct {
	client KeyManagementClient
}

// New creates a new CloudKMS configured with a new client.
func New(ctx context.Context, opts apiv1.Options) (*CloudKMS, error) {
	var cloudOpts []option.ClientOption

	if opts.URI != "" {
		u, err := uri.ParseWithScheme(Scheme, opts.URI)
		if err != nil {
			return nil, err
		}
		if f := u.Get("credentials-file"); f != "" {
			cloudOpts = append(cloudOpts, option.WithCredentialsFile(f))
		}
	}

	// Deprecated way to set configuration parameters.
	if opts.CredentialsFile != "" {
		cloudOpts = append(cloudOpts, option.WithCredentialsFile(opts.CredentialsFile))
	}

	client, err := newKeyManagementClient(ctx, cloudOpts...)
	if err != nil {
		return nil, err
	}

	return &CloudKMS{
		client: client,
	}, nil
}

func init() {
	apiv1.Register(apiv1.CloudKMS, func(ctx context.Context, opts apiv1.Options) (apiv1.KeyManager, error) {
		return New(ctx, opts)
	})
}

// NewCloudKMS creates a CloudKMS with a given client.
func NewCloudKMS(client KeyManagementClient) *CloudKMS {
	return &CloudKMS{
		client: client,
	}
}

// Close closes the connection of the Cloud KMS client.
func (k *CloudKMS) Close() error {
	if err := k.client.Close(); err != nil {
		return errors.Wrap(err, "cloudKMS Close failed")
	}
	return nil
}

// CreateSigner returns a new cloudkms signer configured with the given signing
// key name.
func (k *CloudKMS) CreateSigner(req *apiv1.CreateSignerRequest) (crypto.Signer, error) {
	if req.SigningKey == "" {
		return nil, errors.New("signing key cannot be empty")
	}
	return NewSigner(k.client, req.SigningKey)
}

// CreateKey creates in Google's Cloud KMS a new asymmetric key for signing.
func (k *CloudKMS) CreateKey(req *apiv1.CreateKeyRequest) (*apiv1.CreateKeyResponse, error) {
	if req.Name == "" {
		return nil, errors.New("createKeyRequest 'name' cannot be empty")
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

	var crytoKeyName string

	// Split `projects/PROJECT_ID/locations/global/keyRings/RING_ID/cryptoKeys/KEY_ID`
	// to `projects/PROJECT_ID/locations/global/keyRings/RING_ID` and `KEY_ID`.
	keyRing, keyID := Parent(req.Name)
	if err := k.createKeyRingIfNeeded(keyRing); err != nil {
		return nil, err
	}

	ctx, cancel := defaultContext()
	defer cancel()

	// Create private key in CloudKMS.
	response, err := k.client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      keyRing,
		CryptoKeyId: keyID,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				ProtectionLevel: protectionLevel,
				Algorithm:       signatureAlgorithm,
			},
		},
	})
	if err != nil {
		if status.Code(err) != codes.AlreadyExists {
			return nil, errors.Wrap(err, "cloudKMS CreateCryptoKey failed")
		}
		// Create a new version if the key already exists.
		//
		// Note that it will have the same purpose, protection level and
		// algorithm than as previous one.
		req := &kmspb.CreateCryptoKeyVersionRequest{
			Parent: req.Name,
			CryptoKeyVersion: &kmspb.CryptoKeyVersion{
				State: kmspb.CryptoKeyVersion_ENABLED,
			},
		}
		response, err := k.client.CreateCryptoKeyVersion(ctx, req)
		if err != nil {
			return nil, errors.Wrap(err, "cloudKMS CreateCryptoKeyVersion failed")
		}
		crytoKeyName = response.Name
	} else {
		crytoKeyName = response.Name + "/cryptoKeyVersions/1"
	}

	// Sleep deterministically to avoid retries because of PENDING_GENERATING.
	// One second is often enough.
	if protectionLevel == kmspb.ProtectionLevel_HSM {
		time.Sleep(1 * time.Second)
	}

	// Retrieve public key to add it to the response.
	pk, err := k.GetPublicKey(&apiv1.GetPublicKeyRequest{
		Name: crytoKeyName,
	})
	if err != nil {
		return nil, errors.Wrap(err, "cloudKMS GetPublicKey failed")
	}

	return &apiv1.CreateKeyResponse{
		Name:      crytoKeyName,
		PublicKey: pk,
		CreateSignerRequest: apiv1.CreateSignerRequest{
			SigningKey: crytoKeyName,
		},
	}, nil
}

func (k *CloudKMS) createKeyRingIfNeeded(name string) error {
	ctx, cancel := defaultContext()
	defer cancel()

	_, err := k.client.GetKeyRing(ctx, &kmspb.GetKeyRingRequest{
		Name: name,
	})
	if err == nil {
		return nil
	}

	parent, child := Parent(name)
	_, err = k.client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    parent,
		KeyRingId: child,
	})
	if err != nil && status.Code(err) != codes.AlreadyExists {
		return errors.Wrap(err, "cloudKMS CreateKeyRing failed")
	}

	return nil
}

// GetPublicKey gets from Google's Cloud KMS a public key by name. Key names
// follow the pattern:
//
//	projects/([^/]+)/locations/([a-zA-Z0-9_-]{1,63})/keyRings/([a-zA-Z0-9_-]{1,63})/cryptoKeys/([a-zA-Z0-9_-]{1,63})/cryptoKeyVersions/([a-zA-Z0-9_-]{1,63})
func (k *CloudKMS) GetPublicKey(req *apiv1.GetPublicKeyRequest) (crypto.PublicKey, error) {
	if req.Name == "" {
		return nil, errors.New("createKeyRequest 'name' cannot be empty")
	}

	response, err := k.getPublicKeyWithRetries(req.Name, pendingGenerationRetries)
	if err != nil {
		return nil, errors.Wrap(err, "cloudKMS GetPublicKey failed")
	}

	pk, err := pemutil.ParseKey([]byte(response.Pem))
	if err != nil {
		return nil, err
	}

	return pk, nil
}

// getPublicKeyWithRetries retries the request if the error is
// FailedPrecondition, caused because the key is in the PENDING_GENERATION
// status.
func (k *CloudKMS) getPublicKeyWithRetries(name string, retries int) (response *kmspb.PublicKey, err error) {
	workFn := func() (*kmspb.PublicKey, error) {
		ctx, cancel := defaultContext()
		defer cancel()
		return k.client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
			Name: name,
		})
	}
	for i := 0; i < retries; i++ {
		if response, err = workFn(); err == nil {
			return
		}
		if status.Code(err) == codes.FailedPrecondition {
			log.Println("Waiting for key generation ...")
			time.Sleep(time.Duration(i+1) * time.Second)
			continue
		}
	}
	return
}

func defaultContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 15*time.Second)
}

// Parent splits a string in the format `key/value/key2/value2` in a parent and
// child, for the previous string it will return `key/value` and `value2`.
func Parent(name string) (string, string) {
	a, b := parent(name)
	a, _ = parent(a)
	return a, b
}

func parent(name string) (string, string) {
	i := strings.LastIndex(name, "/")
	switch i {
	case -1:
		return "", name
	case 0:
		return "", name[i+1:]
	default:
		return name[:i], name[i+1:]
	}
}
