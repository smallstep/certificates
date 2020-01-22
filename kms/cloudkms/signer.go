package cloudkms

import (
	"crypto"
	"io"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/pemutil"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

// Signer implements a crypto.Signer using Google's Cloud KMS.
type Signer struct {
	client     KeyManagementClient
	signingKey string
}

func NewSigner(c KeyManagementClient, signingKey string) *Signer {
	return &Signer{
		client:     c,
		signingKey: signingKey,
	}
}

// Public returns the public key of this signer or an error.
func (s *Signer) Public() crypto.PublicKey {
	ctx, cancel := defaultContext()
	defer cancel()

	response, err := s.client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: s.signingKey,
	})
	if err != nil {
		return errors.Wrap(err, "cloudKMS GetPublicKey failed")
	}

	pk, err := pemutil.ParseKey([]byte(response.Pem))
	if err != nil {
		return err
	}

	return pk
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
