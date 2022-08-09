package stepcas

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"net/url"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/cas/apiv1"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/randutil"
)

const defaultValidity = 5 * time.Minute

// timeNow returns the current time.
// This method is used for unit testing purposes.
var timeNow = time.Now

type x5cIssuer struct {
	caURL    *url.URL
	issuer   string
	certFile string
	keyFile  string
	password string
}

// newX5CIssuer create a new x5c token issuer. The given configuration should be
// already validate.
func newX5CIssuer(caURL *url.URL, cfg *apiv1.CertificateIssuer) (*x5cIssuer, error) {
	_, err := newX5CSigner(cfg.Certificate, cfg.Key, cfg.Password)
	if err != nil {
		return nil, err
	}

	return &x5cIssuer{
		caURL:    caURL,
		issuer:   cfg.Provisioner,
		certFile: cfg.Certificate,
		keyFile:  cfg.Key,
		password: cfg.Password,
	}, nil
}

func (i *x5cIssuer) SignToken(subject string, sans []string, info *raInfo) (string, error) {
	aud := i.caURL.ResolveReference(&url.URL{
		Path:     "/1.0/sign",
		Fragment: "x5c/" + i.issuer,
	}).String()

	return i.createToken(aud, subject, sans, info)
}

func (i *x5cIssuer) RevokeToken(subject string) (string, error) {
	aud := i.caURL.ResolveReference(&url.URL{
		Path:     "/1.0/revoke",
		Fragment: "x5c/" + i.issuer,
	}).String()

	return i.createToken(aud, subject, nil, nil)
}

func (i *x5cIssuer) Lifetime(d time.Duration) time.Duration {
	cert, err := pemutil.ReadCertificate(i.certFile, pemutil.WithFirstBlock())
	if err != nil {
		return d
	}
	now := timeNow()
	if now.Add(d + time.Minute).After(cert.NotAfter) {
		return cert.NotAfter.Sub(now) - time.Minute
	}
	return d
}

func (i *x5cIssuer) createToken(aud, sub string, sans []string, info *raInfo) (string, error) {
	signer, err := newX5CSigner(i.certFile, i.keyFile, i.password)
	if err != nil {
		return "", err
	}

	id, err := randutil.Hex(64) // 256 bits
	if err != nil {
		return "", err
	}

	claims := defaultClaims(i.issuer, sub, aud, id)
	builder := jose.Signed(signer).Claims(claims)
	if len(sans) > 0 {
		builder = builder.Claims(map[string]interface{}{
			"sans": sans,
		})
	}
	if info != nil {
		builder = builder.Claims(map[string]interface{}{
			"step": map[string]interface{}{
				"ra": info,
			},
		})
	}

	tok, err := builder.CompactSerialize()
	if err != nil {
		return "", errors.Wrap(err, "error signing token")
	}

	return tok, nil
}

func defaultClaims(iss, sub, aud, id string) jose.Claims {
	now := timeNow()
	return jose.Claims{
		ID:        id,
		Issuer:    iss,
		Subject:   sub,
		Audience:  jose.Audience{aud},
		Expiry:    jose.NewNumericDate(now.Add(defaultValidity)),
		NotBefore: jose.NewNumericDate(now),
		IssuedAt:  jose.NewNumericDate(now),
	}
}

func readKey(keyFile, password string) (crypto.Signer, error) {
	var opts []pemutil.Options
	if password != "" {
		opts = append(opts, pemutil.WithPassword([]byte(password)))
	}
	key, err := pemutil.Read(keyFile, opts...)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("key is not a crypto.Signer")
	}
	return signer, nil
}

func newX5CSigner(certFile, keyFile, password string) (jose.Signer, error) {
	signer, err := readKey(keyFile, password)
	if err != nil {
		return nil, err
	}
	kid, err := jose.Thumbprint(&jose.JSONWebKey{Key: signer.Public()})
	if err != nil {
		return nil, err
	}
	certs, err := pemutil.ReadCertificateBundle(certFile)
	if err != nil {
		return nil, errors.Wrap(err, "error reading x5c certificate chain")
	}
	certStrs, err := jose.ValidateX5C(certs, signer)
	if err != nil {
		return nil, errors.Wrap(err, "error validating x5c certificate chain and key")
	}

	so := new(jose.SignerOptions)
	so.WithType("JWT")
	so.WithHeader("kid", kid)
	so.WithHeader("x5c", certStrs)
	return newJoseSigner(signer, so)
}

func newJoseSigner(key crypto.Signer, so *jose.SignerOptions) (jose.Signer, error) {
	var alg jose.SignatureAlgorithm
	switch k := key.Public().(type) {
	case *ecdsa.PublicKey:
		switch k.Curve.Params().Name {
		case "P-256":
			alg = jose.ES256
		case "P-384":
			alg = jose.ES384
		case "P-521":
			alg = jose.ES512
		default:
			return nil, errors.Errorf("unsupported elliptic curve %s", k.Curve.Params().Name)
		}
	case ed25519.PublicKey:
		alg = jose.EdDSA
	case *rsa.PublicKey:
		alg = jose.DefaultRSASigAlgorithm
	default:
		return nil, errors.Errorf("unsupported key type %T", k)
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, so)
	if err != nil {
		return nil, errors.Wrap(err, "error creating jose.Signer")
	}
	return signer, nil
}
