package azurekms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"io"
	"math/big"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/pkg/errors"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// Signer implements a crypto.Signer using the AWS KMS.
type Signer struct {
	client       KeyVaultClient
	vaultBaseURL string
	name         string
	version      string
	publicKey    crypto.PublicKey
}

// NewSigner creates a new signer using a key in the AWS KMS.
func NewSigner(client KeyVaultClient, signingKey string, defaults DefaultOptions) (crypto.Signer, error) {
	vault, name, version, _, err := parseKeyName(signingKey, defaults)
	if err != nil {
		return nil, err
	}

	// Make sure that the key exists.
	signer := &Signer{
		client:       client,
		vaultBaseURL: vaultBaseURL(vault),
		name:         name,
		version:      version,
	}
	if err := signer.preloadKey(); err != nil {
		return nil, err
	}

	return signer, nil
}

func (s *Signer) preloadKey() error {
	ctx, cancel := defaultContext()
	defer cancel()

	resp, err := s.client.GetKey(ctx, s.vaultBaseURL, s.name, s.version)
	if err != nil {
		return errors.Wrap(err, "keyVault GetKey failed")
	}

	s.publicKey, err = convertKey(resp.Key)
	return err
}

// Public returns the public key of this signer or an error.
func (s *Signer) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign signs digest with the private key stored in the AWS KMS.
func (s *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	alg, err := getSigningAlgorithm(s.Public(), opts)
	if err != nil {
		return nil, err
	}

	b64 := base64.RawURLEncoding.EncodeToString(digest)

	// Sign with retry if the key is not ready
	resp, err := s.signWithRetry(alg, b64, 3)
	if err != nil {
		return nil, errors.Wrap(err, "keyVault Sign failed")
	}

	sig, err := base64.RawURLEncoding.DecodeString(*resp.Result)
	if err != nil {
		return nil, errors.Wrap(err, "error decoding keyVault Sign result")
	}

	var octetSize int
	switch alg {
	case keyvault.ES256:
		octetSize = 32 // 256-bit, concat(R,S) = 64 bytes
	case keyvault.ES384:
		octetSize = 48 // 384-bit, concat(R,S) = 96 bytes
	case keyvault.ES512:
		octetSize = 66 // 528-bit, concat(R,S) = 132 bytes
	default:
		return sig, nil
	}

	// Convert to asn1
	if len(sig) != octetSize*2 {
		return nil, errors.Errorf("keyVault Sign failed: unexpected signature length")
	}
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(new(big.Int).SetBytes(sig[:octetSize])) // R
		b.AddASN1BigInt(new(big.Int).SetBytes(sig[octetSize:])) // S
	})
	return b.Bytes()
}

func (s *Signer) signWithRetry(alg keyvault.JSONWebKeySignatureAlgorithm, b64 string, retryAttempts int) (keyvault.KeyOperationResult, error) {
retry:
	ctx, cancel := defaultContext()
	defer cancel()

	resp, err := s.client.Sign(ctx, s.vaultBaseURL, s.name, s.version, keyvault.KeySignParameters{
		Algorithm: alg,
		Value:     &b64,
	})
	if err != nil && retryAttempts > 0 {
		var requestError *azure.RequestError
		if errors.As(err, &requestError) {
			if se := requestError.ServiceError; se != nil && se.InnerError != nil {
				code, ok := se.InnerError["code"].(string)
				if ok && code == "KeyNotYetValid" {
					time.Sleep(time.Second / time.Duration(retryAttempts))
					retryAttempts--
					goto retry
				}
			}
		}
	}
	return resp, err
}

func getSigningAlgorithm(key crypto.PublicKey, opts crypto.SignerOpts) (keyvault.JSONWebKeySignatureAlgorithm, error) {
	switch key.(type) {
	case *rsa.PublicKey:
		hashFunc := opts.HashFunc()
		pss, isPSS := opts.(*rsa.PSSOptions)
		// Random salt lengths are not supported
		if isPSS &&
			pss.SaltLength != rsa.PSSSaltLengthAuto &&
			pss.SaltLength != rsa.PSSSaltLengthEqualsHash &&
			pss.SaltLength != hashFunc.Size() {
			return "", errors.Errorf("unsupported RSA-PSS salt length %d", pss.SaltLength)
		}

		switch h := hashFunc; h {
		case crypto.SHA256:
			if isPSS {
				return keyvault.PS256, nil
			}
			return keyvault.RS256, nil
		case crypto.SHA384:
			if isPSS {
				return keyvault.PS384, nil
			}
			return keyvault.RS384, nil
		case crypto.SHA512:
			if isPSS {
				return keyvault.PS512, nil
			}
			return keyvault.RS512, nil
		default:
			return "", errors.Errorf("unsupported hash function %v", h)
		}
	case *ecdsa.PublicKey:
		switch h := opts.HashFunc(); h {
		case crypto.SHA256:
			return keyvault.ES256, nil
		case crypto.SHA384:
			return keyvault.ES384, nil
		case crypto.SHA512:
			return keyvault.ES512, nil
		default:
			return "", errors.Errorf("unsupported hash function %v", h)
		}
	default:
		return "", errors.Errorf("unsupported key type %T", key)
	}
}
