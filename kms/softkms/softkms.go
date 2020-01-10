package softkms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/kms/apiv1"
	"github.com/smallstep/cli/crypto/keys"
	"github.com/smallstep/cli/crypto/pemutil"
)

type algorithmAttributes struct {
	Type  string
	Curve string
}

var signatureAlgorithmMapping = map[apiv1.SignatureAlgorithm]algorithmAttributes{
	apiv1.UnspecifiedSignAlgorithm: algorithmAttributes{"EC", "P-256"},
	apiv1.SHA256WithRSA:            algorithmAttributes{"RSA", ""},
	apiv1.SHA384WithRSA:            algorithmAttributes{"RSA", ""},
	apiv1.SHA512WithRSA:            algorithmAttributes{"RSA", ""},
	apiv1.SHA256WithRSAPSS:         algorithmAttributes{"RSA", ""},
	apiv1.SHA384WithRSAPSS:         algorithmAttributes{"RSA", ""},
	apiv1.SHA512WithRSAPSS:         algorithmAttributes{"RSA", ""},
	apiv1.ECDSAWithSHA256:          algorithmAttributes{"EC", "P-256"},
	apiv1.ECDSAWithSHA384:          algorithmAttributes{"EC", "P-384"},
	apiv1.ECDSAWithSHA512:          algorithmAttributes{"EC", "P-521"},
	apiv1.PureEd25519:              algorithmAttributes{"OKP", "Ed25519"},
}

// SoftKSM is a key manager that uses keys stored in disk.
type SoftKMS struct{}

// New returns a new SoftKSM.
func New(ctx context.Context, opts apiv1.Options) (*SoftKMS, error) {
	return &SoftKMS{}, nil
}

// CreateSigner returns a new signer configured with the given signing key.
func (k *SoftKMS) CreateSigner(req *apiv1.CreateSignerRequest) (crypto.Signer, error) {
	var opts []pemutil.Options
	if req.Password != "" {
		opts = append(opts, pemutil.WithPassword([]byte(req.Password)))
	}

	switch {
	case len(req.SigningKeyPEM) != 0:
		v, err := pemutil.ParseKey(req.SigningKeyPEM, opts...)
		if err != nil {
			return nil, err
		}
		sig, ok := v.(crypto.Signer)
		if !ok {
			return nil, errors.New("signingKeyPEM is not a crypto.Signer")
		}
		return sig, nil
	case req.SigningKey != "":
		v, err := pemutil.Read(req.SigningKey, opts...)
		if err != nil {
			return nil, err
		}
		sig, ok := v.(crypto.Signer)
		if !ok {
			return nil, errors.New("signingKey is not a crypto.Signer")
		}
		return sig, nil
	default:
		return nil, errors.New("failed to load softKMS: please define signingKeyPEM or signingKey")
	}
}

func (k *SoftKMS) CreateKey(req *apiv1.CreateKeyRequest) (*apiv1.CreateKeyResponse, error) {
	v, ok := signatureAlgorithmMapping[req.SignatureAlgorithm]
	if !ok {
		return nil, errors.Errorf("softKMS does not support signature algorithm '%s'", req.SignatureAlgorithm)
	}

	pub, priv, err := keys.GenerateKeyPair(v.Type, v.Curve, req.Bits)
	if err != nil {
		return nil, err
	}

	return &apiv1.CreateKeyResponse{
		Name:       req.Name,
		PublicKey:  pub,
		PrivateKey: priv,
	}, nil
}

func (k *SoftKMS) GetPublicKey(req *apiv1.GetPublicKeyRequest) (*apiv1.GetPublicKeyResponse, error) {
	v, err := pemutil.Read(req.Name)
	if err != nil {
		return nil, err
	}

	switch v.(type) {
	case *x509.Certificate:
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
	default:
		return nil, errors.Errorf("unsupported public key type %T", v)
	}

	return &apiv1.GetPublicKeyResponse{
		Name:      req.Name,
		PublicKey: v,
	}, nil
}
