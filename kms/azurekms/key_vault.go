package azurekms

import (
	"context"
	"crypto"
	"net/url"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/Azure/go-autorest/autorest/date"
	"github.com/pkg/errors"
	"github.com/smallstep/certificates/kms/apiv1"
	"github.com/smallstep/certificates/kms/uri"
)

func init() {
	apiv1.Register(apiv1.CloudKMS, func(ctx context.Context, opts apiv1.Options) (apiv1.KeyManager, error) {
		return New(ctx, opts)
	})
}

// Scheme is the scheme used for Azure Key Vault uris.
const Scheme = "azurekms"

var (
	valueTrue       = true
	value2048 int32 = 2048
	value3072 int32 = 3072
	value4096 int32 = 4096
)

var now = func() time.Time {
	return time.Now().UTC()
}

type keyType struct {
	Kty     keyvault.JSONWebKeyType
	Curve   keyvault.JSONWebKeyCurveName
	KeySize int
}

func (k keyType) KeyType(pl apiv1.ProtectionLevel) keyvault.JSONWebKeyType {
	switch k.Kty {
	case keyvault.EC:
		if pl == apiv1.HSM {
			return keyvault.ECHSM
		}
		return k.Kty
	case keyvault.RSA:
		if pl == apiv1.HSM {
			return keyvault.RSAHSM
		}
		return k.Kty
	default:
		return ""
	}
}

var signatureAlgorithmMapping = map[apiv1.SignatureAlgorithm]keyType{
	apiv1.UnspecifiedSignAlgorithm: {
		Kty:   keyvault.EC,
		Curve: keyvault.P256,
	},
	apiv1.SHA256WithRSA: {
		Kty: keyvault.RSA,
	},
	apiv1.SHA384WithRSA: {
		Kty: keyvault.RSA,
	},
	apiv1.SHA512WithRSA: {
		Kty: keyvault.RSA,
	},
	apiv1.SHA256WithRSAPSS: {
		Kty: keyvault.RSA,
	},
	apiv1.SHA384WithRSAPSS: {
		Kty: keyvault.RSA,
	},
	apiv1.SHA512WithRSAPSS: {
		Kty: keyvault.RSA,
	},
	apiv1.ECDSAWithSHA256: {
		Kty:   keyvault.EC,
		Curve: keyvault.P256,
	},
	apiv1.ECDSAWithSHA384: {
		Kty:   keyvault.EC,
		Curve: keyvault.P384,
	},
	apiv1.ECDSAWithSHA512: {
		Kty:   keyvault.EC,
		Curve: keyvault.P521,
	},
}

// vaultResource is that the client will use as audience.
const vaultResource = "https://vault.azure.net"

// KeyVaultClient is the interface implemented by keyvault.BaseClient. It it
// will be used for testing purposes.
type KeyVaultClient interface {
	GetKey(ctx context.Context, vaultBaseURL string, keyName string, keyVersion string) (keyvault.KeyBundle, error)
	CreateKey(ctx context.Context, vaultBaseURL string, keyName string, parameters keyvault.KeyCreateParameters) (keyvault.KeyBundle, error)
	Sign(ctx context.Context, vaultBaseURL string, keyName string, keyVersion string, parameters keyvault.KeySignParameters) (keyvault.KeyOperationResult, error)
}

// KeyVault implements a KMS using Azure Key Vault.
//
// TODO(mariano): The implementation is using /services/keyvault/v7.1/keyvault
// package, at some point Azure might create a keyvault client with all the
// functionality in /sdk/keyvault, we should migrate to that once available.
type KeyVault struct {
	baseClient KeyVaultClient
}

// New initializes a new KMS implemented using Azure Key Vault.
func New(ctx context.Context, opts apiv1.Options) (*KeyVault, error) {
	// Attempt to authorize with the following methods:
	// 1. Environment variables.
	//    - Client credentials
	//    - Client certificate
	//    - Username and password
	//    - MSI
	// 2. Using Azure CLI 2.0 on local development.
	authorizer, err := auth.NewAuthorizerFromEnvironmentWithResource(vaultResource)
	if err != nil {
		authorizer, err = auth.NewAuthorizerFromCLIWithResource(vaultResource)
		if err != nil {
			return nil, errors.Wrap(err, "error getting authorizer for key vault")
		}
	}

	baseClient := keyvault.New()
	baseClient.Authorizer = authorizer

	return &KeyVault{
		baseClient: &baseClient,
	}, nil
}

// GetPublicKey loads a public key from Azure Key Vault by its resource name.
func (k *KeyVault) GetPublicKey(req *apiv1.GetPublicKeyRequest) (crypto.PublicKey, error) {
	switch {
	case req.Name == "":
		return nil, errors.New("getPublicKeyRequest 'name' cannot be empty")
	}

	vault, name, version, err := parseKeyName(req.Name)
	if err != nil {
		return nil, err
	}

	ctx, cancel := defaultContext()
	defer cancel()

	resp, err := k.baseClient.GetKey(ctx, vaultBaseURL(vault), name, version)
	if err != nil {
		return nil, errors.Wrap(err, "keyVault GetKey failed")
	}

	return convertKey(resp.Key)
}

// CreateKey creates a asymmetric key in Azure Key Vault.
func (k *KeyVault) CreateKey(req *apiv1.CreateKeyRequest) (*apiv1.CreateKeyResponse, error) {
	vault, name, _, err := parseKeyName(req.Name)
	if err != nil {
		return nil, err
	}

	kt, ok := signatureAlgorithmMapping[req.SignatureAlgorithm]
	if !ok {
		return nil, errors.Errorf("keyVault does not support signature algorithm '%s'", req.SignatureAlgorithm)
	}
	var keySize *int32
	if kt.Kty == keyvault.RSA || kt.Kty == keyvault.RSAHSM {
		switch req.Bits {
		case 2048:
			keySize = &value2048
		case 0, 3072:
			keySize = &value3072
		case 4096:
			keySize = &value4096
		default:
			return nil, errors.Errorf("keyVault does not support key size %d", req.Bits)
		}
	}

	created := date.UnixTime(now())

	ctx, cancel := defaultContext()
	defer cancel()

	resp, err := k.baseClient.CreateKey(ctx, vaultBaseURL(vault), name, keyvault.KeyCreateParameters{
		Kty:     kt.KeyType(req.ProtectionLevel),
		KeySize: keySize,
		Curve:   kt.Curve,
		KeyOps: &[]keyvault.JSONWebKeyOperation{
			keyvault.Sign, keyvault.Verify,
		},
		KeyAttributes: &keyvault.KeyAttributes{
			Enabled:   &valueTrue,
			Created:   &created,
			NotBefore: &created,
		},
	})
	if err != nil {
		return nil, errors.Wrap(err, "keyVault CreateKey failed")
	}

	keyURI := uri.New("azurekms", url.Values{
		"vault": []string{vault},
		"id":    []string{name},
	}).String()

	publicKey, err := convertKey(resp.Key)
	if err != nil {
		return nil, err
	}

	return &apiv1.CreateKeyResponse{
		Name:      keyURI,
		PublicKey: publicKey,
		CreateSignerRequest: apiv1.CreateSignerRequest{
			SigningKey: keyURI,
		},
	}, nil
}

// CreateSigner returns a crypto.Signer from a previously created asymmetric key.
func (k *KeyVault) CreateSigner(req *apiv1.CreateSignerRequest) (crypto.Signer, error) {
	if req.SigningKey == "" {
		return nil, errors.New("createSignerRequest 'signingKey' cannot be empty")
	}
	return NewSigner(k.baseClient, req.SigningKey)
}

// Close closes the client connection to the Azure Key Vault. This is a noop.
func (k *KeyVault) Close() error {
	return nil
}
