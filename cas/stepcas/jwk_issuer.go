package stepcas

import (
	"crypto"
	"net/url"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/cas/apiv1"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/randutil"
)

type jwkIssuer struct {
	caURL   *url.URL
	keyFile string
	issuer  string
}

func newJWKIssuer(caURL *url.URL, cfg *apiv1.CertificateIssuer) (*jwkIssuer, error) {
	_, err := newJWKSigner(cfg.Key)
	if err != nil {
		return nil, err
	}

	return &jwkIssuer{
		caURL:   caURL,
		keyFile: cfg.Key,
		issuer:  cfg.Provisioner,
	}, nil
}

func (i *jwkIssuer) SignToken(subject string, sans []string) (string, error) {
	aud := i.caURL.ResolveReference(&url.URL{
		Path: "/1.0/sign",
	}).String()
	return i.createToken(aud, subject, sans)
}

func (i *jwkIssuer) RevokeToken(subject string) (string, error) {
	aud := i.caURL.ResolveReference(&url.URL{
		Path: "/1.0/revoke",
	}).String()
	return i.createToken(aud, subject, nil)
}

func (i *jwkIssuer) Lifetime(d time.Duration) time.Duration {
	return d
}

func (i *jwkIssuer) createToken(aud, sub string, sans []string) (string, error) {
	signer, err := newJWKSigner(i.keyFile)
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

	tok, err := builder.CompactSerialize()
	if err != nil {
		return "", errors.Wrap(err, "error signing token")
	}

	return tok, nil
}

func newJWKSigner(keyFile string) (jose.Signer, error) {
	key, err := pemutil.Read(keyFile)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("key is not a crypto.Signer")
	}
	kid, err := jose.Thumbprint(&jose.JSONWebKey{Key: signer.Public()})
	if err != nil {
		return nil, err
	}
	so := new(jose.SignerOptions)
	so.WithType("JWT")
	so.WithHeader("kid", kid)
	return newJoseSigner(signer, so)
}
