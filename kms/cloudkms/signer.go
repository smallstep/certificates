package cloudkms

import (
	"crypto"
	"crypto/x509"
	"io"

	"github.com/pkg/errors"
	"go.step.sm/crypto/pemutil"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

// Signer implements a crypto.Signer using Google's Cloud KMS.
type Signer struct {
	client     KeyManagementClient
	signingKey string
	algorithm  x509.SignatureAlgorithm
	publicKey  crypto.PublicKey
}

// NewSigner creates a new crypto.Signer the given CloudKMS signing key.
func NewSigner(c KeyManagementClient, signingKey string) (*Signer, error) {
	// Make sure that the key exists.
	signer := &Signer{
		client:     c,
		signingKey: signingKey,
	}
	if err := signer.preloadKey(signingKey); err != nil {
		return nil, err
	}

	return signer, nil
}

func (s *Signer) preloadKey(signingKey string) error {
	ctx, cancel := defaultContext()
	defer cancel()

	response, err := s.client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: signingKey,
	})
	if err != nil {
		return errors.Wrap(err, "cloudKMS GetPublicKey failed")
	}
	s.algorithm = cryptoKeyVersionMapping[response.Algorithm]
	s.publicKey, err = pemutil.ParseKey([]byte(response.Pem))
	return err
}

// Public returns the public key of this signer or an error.
func (s *Signer) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign signs digest with the private key stored in Google's Cloud KMS.
func (s *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	req := &kmspb.AsymmetricSignRequest{
		Name:   s.signingKey,
		Digest: &kmspb.Digest{},
	}

	switch h := opts.HashFunc(); h {
	case crypto.SHA256:
		req.Digest.Digest = &kmspb.Digest_Sha256{
			Sha256: digest,
		}
	case crypto.SHA384:
		req.Digest.Digest = &kmspb.Digest_Sha384{
			Sha384: digest,
		}
	case crypto.SHA512:
		req.Digest.Digest = &kmspb.Digest_Sha512{
			Sha512: digest,
		}
	default:
		return nil, errors.Errorf("unsupported hash function %v", h)
	}

	ctx, cancel := defaultContext()
	defer cancel()

	response, err := s.client.AsymmetricSign(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, "cloudKMS AsymmetricSign failed")
	}

	return response.Signature, nil
}

// SignatureAlgorithm returns the algorithm that must be specified in a
// certificate to sign. This is specially important to distinguish RSA and
// RSAPSS schemas.
func (s *Signer) SignatureAlgorithm() x509.SignatureAlgorithm {
	return s.algorithm
}
