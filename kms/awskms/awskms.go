package awskms

import (
	"context"
	"crypto"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/pkg/errors"
	"github.com/smallstep/certificates/kms/apiv1"
	"github.com/smallstep/certificates/kms/uri"
	"go.step.sm/crypto/pemutil"
)

// Scheme is the scheme used in uris.
const Scheme = "awskms"

// KMS implements a KMS using AWS Key Management Service.
type KMS struct {
	session *session.Session
	service KeyManagementClient
}

// KeyManagementClient defines the methods on KeyManagementClient that this
// package will use. This interface will be used for unit testing.
type KeyManagementClient interface {
	GetPublicKeyWithContext(ctx aws.Context, input *kms.GetPublicKeyInput, opts ...request.Option) (*kms.GetPublicKeyOutput, error)
	CreateKeyWithContext(ctx aws.Context, input *kms.CreateKeyInput, opts ...request.Option) (*kms.CreateKeyOutput, error)
	CreateAliasWithContext(ctx aws.Context, input *kms.CreateAliasInput, opts ...request.Option) (*kms.CreateAliasOutput, error)
	SignWithContext(ctx aws.Context, input *kms.SignInput, opts ...request.Option) (*kms.SignOutput, error)
}

// customerMasterKeySpecMapping is a mapping between the step signature algorithm,
// and bits for RSA keys, with awskms CustomerMasterKeySpec.
var customerMasterKeySpecMapping = map[apiv1.SignatureAlgorithm]interface{}{
	apiv1.UnspecifiedSignAlgorithm: kms.CustomerMasterKeySpecEccNistP256,
	apiv1.SHA256WithRSA: map[int]string{
		0:    kms.CustomerMasterKeySpecRsa3072,
		2048: kms.CustomerMasterKeySpecRsa2048,
		3072: kms.CustomerMasterKeySpecRsa3072,
		4096: kms.CustomerMasterKeySpecRsa4096,
	},
	apiv1.SHA512WithRSA: map[int]string{
		0:    kms.CustomerMasterKeySpecRsa4096,
		4096: kms.CustomerMasterKeySpecRsa4096,
	},
	apiv1.SHA256WithRSAPSS: map[int]string{
		0:    kms.CustomerMasterKeySpecRsa3072,
		2048: kms.CustomerMasterKeySpecRsa2048,
		3072: kms.CustomerMasterKeySpecRsa3072,
		4096: kms.CustomerMasterKeySpecRsa4096,
	},
	apiv1.SHA512WithRSAPSS: map[int]string{
		0:    kms.CustomerMasterKeySpecRsa4096,
		4096: kms.CustomerMasterKeySpecRsa4096,
	},
	apiv1.ECDSAWithSHA256: kms.CustomerMasterKeySpecEccNistP256,
	apiv1.ECDSAWithSHA384: kms.CustomerMasterKeySpecEccNistP384,
	apiv1.ECDSAWithSHA512: kms.CustomerMasterKeySpecEccNistP521,
}

// New creates a new AWSKMS. By default, sessions will be created using the
// credentials in `~/.aws/credentials`, but this can be overridden using the
// CredentialsFile option, the Region and Profile can also be configured as
// options.
//
// AWS sessions can also be configured with environment variables, see docs at
// https://docs.aws.amazon.com/sdk-for-go/api/aws/session/ for all the options.
func New(ctx context.Context, opts apiv1.Options) (*KMS, error) {
	var o session.Options

	if opts.URI != "" {
		u, err := uri.ParseWithScheme(Scheme, opts.URI)
		if err != nil {
			return nil, err
		}
		o.Profile = u.Get("profile")
		if v := u.Get("region"); v != "" {
			o.Config.Region = new(string)
			*o.Config.Region = v
		}
		if f := u.Get("credentials-file"); f != "" {
			o.SharedConfigFiles = []string{opts.CredentialsFile}
		}
	}

	// Deprecated way to set configuration parameters.
	if opts.Region != "" {
		o.Config.Region = &opts.Region
	}
	if opts.Profile != "" {
		o.Profile = opts.Profile
	}
	if opts.CredentialsFile != "" {
		o.SharedConfigFiles = []string{opts.CredentialsFile}
	}

	sess, err := session.NewSessionWithOptions(o)
	if err != nil {
		return nil, errors.Wrap(err, "error creating AWS session")
	}

	return &KMS{
		session: sess,
		service: kms.New(sess),
	}, nil
}

func init() {
	apiv1.Register(apiv1.AmazonKMS, func(ctx context.Context, opts apiv1.Options) (apiv1.KeyManager, error) {
		return New(ctx, opts)
	})
}

// GetPublicKey returns a public key from KMS.
func (k *KMS) GetPublicKey(req *apiv1.GetPublicKeyRequest) (crypto.PublicKey, error) {
	if req.Name == "" {
		return nil, errors.New("getPublicKey 'name' cannot be empty")
	}
	keyID, err := parseKeyID(req.Name)
	if err != nil {
		return nil, err
	}

	ctx, cancel := defaultContext()
	defer cancel()

	resp, err := k.service.GetPublicKeyWithContext(ctx, &kms.GetPublicKeyInput{
		KeyId: &keyID,
	})
	if err != nil {
		return nil, errors.Wrap(err, "awskms GetPublicKeyWithContext failed")
	}

	return pemutil.ParseDER(resp.PublicKey)
}

// CreateKey generates a new key in KMS and returns the public key version
// of it.
func (k *KMS) CreateKey(req *apiv1.CreateKeyRequest) (*apiv1.CreateKeyResponse, error) {
	if req.Name == "" {
		return nil, errors.New("createKeyRequest 'name' cannot be empty")
	}

	keySpec, err := getCustomerMasterKeySpecMapping(req.SignatureAlgorithm, req.Bits)
	if err != nil {
		return nil, err
	}

	tag := new(kms.Tag)
	tag.SetTagKey("name")
	tag.SetTagValue(req.Name)

	input := &kms.CreateKeyInput{
		Description:           &req.Name,
		CustomerMasterKeySpec: &keySpec,
		Tags:                  []*kms.Tag{tag},
	}
	input.SetKeyUsage(kms.KeyUsageTypeSignVerify)

	ctx, cancel := defaultContext()
	defer cancel()

	resp, err := k.service.CreateKeyWithContext(ctx, input)
	if err != nil {
		return nil, errors.Wrap(err, "awskms CreateKeyWithContext failed")
	}
	if err := k.createKeyAlias(*resp.KeyMetadata.KeyId, req.Name); err != nil {
		return nil, err
	}

	// Create uri for key
	name := uri.New("awskms", url.Values{
		"key-id": []string{*resp.KeyMetadata.KeyId},
	}).String()

	publicKey, err := k.GetPublicKey(&apiv1.GetPublicKeyRequest{
		Name: name,
	})
	if err != nil {
		return nil, err
	}

	// Names uses Amazon Resource Name
	// https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html
	return &apiv1.CreateKeyResponse{
		Name:      name,
		PublicKey: publicKey,
		CreateSignerRequest: apiv1.CreateSignerRequest{
			SigningKey: name,
		},
	}, nil
}

func (k *KMS) createKeyAlias(keyID, alias string) error {
	alias = "alias/" + alias + "-" + keyID[:8]

	ctx, cancel := defaultContext()
	defer cancel()

	_, err := k.service.CreateAliasWithContext(ctx, &kms.CreateAliasInput{
		AliasName:   &alias,
		TargetKeyId: &keyID,
	})
	if err != nil {
		return errors.Wrap(err, "awskms CreateAliasWithContext failed")
	}
	return nil
}

// CreateSigner creates a new crypto.Signer with a previously configured key.
func (k *KMS) CreateSigner(req *apiv1.CreateSignerRequest) (crypto.Signer, error) {
	if req.SigningKey == "" {
		return nil, errors.New("createSigner 'signingKey' cannot be empty")
	}
	return NewSigner(k.service, req.SigningKey)
}

// Close closes the connection of the KMS client.
func (k *KMS) Close() error {
	return nil
}

func defaultContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 15*time.Second)
}

// parseKeyID extracts the key-id from an uri.
func parseKeyID(name string) (string, error) {
	name = strings.ToLower(name)
	if strings.HasPrefix(name, "awskms:") || strings.HasPrefix(name, "aws:") {
		u, err := uri.Parse(name)
		if err != nil {
			return "", err
		}
		if k := u.Get("key-id"); k != "" {
			return k, nil
		}
		return "", errors.Errorf("failed to get key-id from %s", name)
	}
	return name, nil
}

func getCustomerMasterKeySpecMapping(alg apiv1.SignatureAlgorithm, bits int) (string, error) {
	v, ok := customerMasterKeySpecMapping[alg]
	if !ok {
		return "", errors.Errorf("awskms does not support signature algorithm '%s'", alg)
	}

	switch v := v.(type) {
	case string:
		return v, nil
	case map[int]string:
		s, ok := v[bits]
		if !ok {
			return "", errors.Errorf("awskms does not support signature algorithm '%s' with '%d' bits", alg, bits)
		}
		return s, nil
	default:
		return "", errors.Errorf("unexpected error: this should not happen")
	}
}
