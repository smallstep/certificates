package azurekms

import (
	"context"
	"crypto"
	"regexp"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/Azure/go-autorest/autorest/date"
	"github.com/pkg/errors"
	"github.com/smallstep/certificates/kms/apiv1"
	"github.com/smallstep/certificates/kms/uri"
)

func init() {
	apiv1.Register(apiv1.AzureKMS, func(ctx context.Context, opts apiv1.Options) (apiv1.KeyManager, error) {
		return New(ctx, opts)
	})
}

// Scheme is the scheme used for the Azure Key Vault uris.
const Scheme = "azurekms"

// keyIDRegexp is the regular expression that Key Vault uses on the kid. We can
// extract the vault, name and version of the key.
var keyIDRegexp = regexp.MustCompile(`^https://([0-9a-zA-Z-]+)\.vault\.azure\.net/keys/([0-9a-zA-Z-]+)/([0-9a-zA-Z-]+)$`)

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
	Kty   keyvault.JSONWebKeyType
	Curve keyvault.JSONWebKeyCurveName
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

// vaultResource is the value the client will use as audience.
const vaultResource = "https://vault.azure.net"

// KeyVaultClient is the interface implemented by keyvault.BaseClient. It will
// be used for testing purposes.
type KeyVaultClient interface {
	GetKey(ctx context.Context, vaultBaseURL string, keyName string, keyVersion string) (keyvault.KeyBundle, error)
	CreateKey(ctx context.Context, vaultBaseURL string, keyName string, parameters keyvault.KeyCreateParameters) (keyvault.KeyBundle, error)
	Sign(ctx context.Context, vaultBaseURL string, keyName string, keyVersion string, parameters keyvault.KeySignParameters) (keyvault.KeyOperationResult, error)
}

// KeyVault implements a KMS using Azure Key Vault.
//
// The URI format used in Azure Key Vault is the following:
//
//   - azurekms:name=key-name;vault=vault-name
//   - azurekms:name=key-name;vault=vault-name?version=key-version
//   - azurekms:name=key-name;vault=vault-name?hsm=true
//
// The scheme is "azurekms"; "name" is the key name; "vault" is the key vault
// name where the key is located; "version" is an optional parameter that
// defines the version of they key, if version is not given, the latest one will
// be used; "hsm" defines if an HSM want to be used for this key, this is
// specially useful when this is used from `step`.
//
// TODO(mariano): The implementation is using /services/keyvault/v7.1/keyvault
// package, at some point Azure might create a keyvault client with all the
// functionality in /sdk/keyvault, we should migrate to that once available.
type KeyVault struct {
	baseClient KeyVaultClient
	defaults   DefaultOptions
}

// DefaultOptions are custom options that can be passed as defaults using the
// URI in apiv1.Options.
type DefaultOptions struct {
	Vault           string
	ProtectionLevel apiv1.ProtectionLevel
}

var createClient = func(ctx context.Context, opts apiv1.Options) (KeyVaultClient, error) {
	baseClient := keyvault.New()

	// With an URI, try to log in only using client credentials in the URI.
	// Client credentials requires:
	// - client-id
	// - client-secret
	// - tenant-id
	// And optionally the aad-endpoint to support custom clouds:
	// - aad-endpoint (defaults to https://login.microsoftonline.com/)
	if opts.URI != "" {
		u, err := uri.ParseWithScheme(Scheme, opts.URI)
		if err != nil {
			return nil, err
		}

		// Required options
		clientID := u.Get("client-id")
		clientSecret := u.Get("client-secret")
		tenantID := u.Get("tenant-id")
		// optional
		aadEndpoint := u.Get("aad-endpoint")

		if clientID != "" && clientSecret != "" && tenantID != "" {
			s := auth.EnvironmentSettings{
				Values: map[string]string{
					auth.ClientID:     clientID,
					auth.ClientSecret: clientSecret,
					auth.TenantID:     tenantID,
					auth.Resource:     vaultResource,
				},
				Environment: azure.PublicCloud,
			}
			if aadEndpoint != "" {
				s.Environment.ActiveDirectoryEndpoint = aadEndpoint
			}
			baseClient.Authorizer, err = s.GetAuthorizer()
			if err != nil {
				return nil, err
			}
			return baseClient, nil
		}
	}

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
	baseClient.Authorizer = authorizer
	return &baseClient, nil
}

// New initializes a new KMS implemented using Azure Key Vault.
func New(ctx context.Context, opts apiv1.Options) (*KeyVault, error) {
	baseClient, err := createClient(ctx, opts)
	if err != nil {
		return nil, err
	}

	// step and step-ca do not need and URI, but having a default vault and
	// protection level is useful if this package is used as an api
	var defaults DefaultOptions
	if opts.URI != "" {
		u, err := uri.ParseWithScheme(Scheme, opts.URI)
		if err != nil {
			return nil, err
		}
		defaults.Vault = u.Get("vault")
		if u.GetBool("hsm") {
			defaults.ProtectionLevel = apiv1.HSM
		}
	}

	return &KeyVault{
		baseClient: baseClient,
		defaults:   defaults,
	}, nil
}

// GetPublicKey loads a public key from Azure Key Vault by its resource name.
func (k *KeyVault) GetPublicKey(req *apiv1.GetPublicKeyRequest) (crypto.PublicKey, error) {
	if req.Name == "" {
		return nil, errors.New("getPublicKeyRequest 'name' cannot be empty")
	}

	vault, name, version, _, err := parseKeyName(req.Name, k.defaults)
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
	if req.Name == "" {
		return nil, errors.New("createKeyRequest 'name' cannot be empty")
	}

	vault, name, _, hsm, err := parseKeyName(req.Name, k.defaults)
	if err != nil {
		return nil, err
	}

	// Override protection level to HSM only if it's not specified, and is given
	// in the uri.
	protectionLevel := req.ProtectionLevel
	if protectionLevel == apiv1.UnspecifiedProtectionLevel && hsm {
		protectionLevel = apiv1.HSM
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
		Kty:     kt.KeyType(protectionLevel),
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

	publicKey, err := convertKey(resp.Key)
	if err != nil {
		return nil, err
	}

	keyURI := getKeyName(vault, name, resp)
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
	return NewSigner(k.baseClient, req.SigningKey, k.defaults)
}

// Close closes the client connection to the Azure Key Vault. This is a noop.
func (k *KeyVault) Close() error {
	return nil
}

// ValidateName validates that the given string is a valid URI.
func (k *KeyVault) ValidateName(s string) error {
	_, _, _, _, err := parseKeyName(s, k.defaults)
	return err
}
