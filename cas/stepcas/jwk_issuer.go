package stepcas

import (
	"context"
	"crypto"
	"encoding/json"
	"net/url"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/cas/apiv1"
	"go.step.sm/cli-utils/ui"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/randutil"
)

type jwkIssuer struct {
	caURL  *url.URL
	issuer string
	signer jose.Signer
}

func newJWKIssuer(ctx context.Context, caURL *url.URL, client *ca.Client, cfg *apiv1.CertificateIssuer) (*jwkIssuer, error) {
	var err error
	var signer jose.Signer
	// Read the key from the CA if not provided.
	// Or read it from a PEM file.
	if cfg.Key == "" {
		p, err := findProvisioner(ctx, client, provisioner.TypeJWK, cfg.Provisioner)
		if err != nil {
			return nil, err
		}
		kid, key, ok := p.GetEncryptedKey()
		if !ok {
			return nil, errors.Errorf("provisioner with name %s does not have an encrypted key", cfg.Provisioner)
		}
		signer, err = newJWKSignerFromEncryptedKey(kid, key, cfg.Password)
		if err != nil {
			return nil, err
		}
	} else {
		signer, err = newJWKSigner(cfg.Key, cfg.Password)
		if err != nil {
			return nil, err
		}
	}

	return &jwkIssuer{
		caURL:  caURL,
		issuer: cfg.Provisioner,
		signer: signer,
	}, nil
}

func (i *jwkIssuer) SignToken(subject string, sans []string, info *raInfo) (string, error) {
	aud := i.caURL.ResolveReference(&url.URL{
		Path: "/1.0/sign",
	}).String()
	return i.createToken(aud, subject, sans, info)
}

func (i *jwkIssuer) RevokeToken(subject string) (string, error) {
	aud := i.caURL.ResolveReference(&url.URL{
		Path: "/1.0/revoke",
	}).String()
	return i.createToken(aud, subject, nil, nil)
}

func (i *jwkIssuer) Lifetime(d time.Duration) time.Duration {
	return d
}

func (i *jwkIssuer) createToken(aud, sub string, sans []string, info *raInfo) (string, error) {
	id, err := randutil.Hex(64) // 256 bits
	if err != nil {
		return "", err
	}

	claims := defaultClaims(i.issuer, sub, aud, id)
	builder := jose.Signed(i.signer).Claims(claims)
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

func newJWKSigner(keyFile, password string) (jose.Signer, error) {
	signer, err := readKey(keyFile, password)
	if err != nil {
		return nil, err
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

func newJWKSignerFromEncryptedKey(kid, key, password string) (jose.Signer, error) {
	var jwk jose.JSONWebKey

	// If the password is empty it will use the password prompter.
	b, err := jose.Decrypt([]byte(key),
		jose.WithPassword([]byte(password)),
		jose.WithPasswordPrompter("Please enter the password to decrypt the provisioner key", func(msg string) ([]byte, error) {
			return ui.PromptPassword(msg)
		}))
	if err != nil {
		return nil, err
	}

	// Decrypt returns the JSON representation of the JWK.
	if err := json.Unmarshal(b, &jwk); err != nil {
		return nil, errors.Wrap(err, "error parsing provisioner key")
	}

	signer, ok := jwk.Key.(crypto.Signer)
	if !ok {
		return nil, errors.New("error parsing provisioner key: key is not a crypto.Signer")
	}

	so := new(jose.SignerOptions)
	so.WithType("JWT")
	so.WithHeader("kid", kid)
	return newJoseSigner(signer, so)
}

func findProvisioner(ctx context.Context, client *ca.Client, typ provisioner.Type, name string) (provisioner.Interface, error) {
	cursor := ""
	for {
		ps, err := client.ProvisionersWithContext(ctx, ca.WithProvisionerCursor(cursor))
		if err != nil {
			return nil, err
		}
		for _, p := range ps.Provisioners {
			if p.GetType() == typ && p.GetName() == name {
				return p, nil
			}
		}
		if ps.NextCursor == "" {
			return nil, errors.Errorf("provisioner with name %s was not found", name)
		}
		cursor = ps.NextCursor
	}
}
