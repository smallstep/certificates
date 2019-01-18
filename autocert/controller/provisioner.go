package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/pki"
	"github.com/smallstep/cli/crypto/randutil"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/cli/token"
	"github.com/smallstep/cli/token/provision"
)

const (
	tokenLifetime = 5 * time.Minute
)

type Provisioner interface {
	Name() string
	Kid() string
	Token(subject string) (string, error)
}

type provisioner struct {
	name          string
	kid           string
	caUrl         string
	caRoot        string
	jwk           *jose.JSONWebKey
	tokenLifetime time.Duration
}

// Name returns the provisioner's name.
func (p *provisioner) Name() string {
	return p.name
}

// Kid returns the provisioners key ID.
func (p *provisioner) Kid() string {
	return p.kid
}

// Token generates a bootstrap token for a subject.
func (p *provisioner) Token(subject string) (string, error) {
	// A random jwt id will be used to identify duplicated tokens
	jwtID, err := randutil.Hex(64) // 256 bits
	if err != nil {
		return "", err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(tokenLifetime)
	signUrl := fmt.Sprintf("%v/1.0/sign", p.caUrl)

	tokOptions := []token.Options{
		token.WithJWTID(jwtID),
		token.WithKid(p.kid),
		token.WithIssuer(p.name),
		token.WithAudience(signUrl),
		token.WithValidity(notBefore, notAfter),
		token.WithRootCA(p.caRoot),
	}

	tok, err := provision.New(subject, tokOptions...)
	if err != nil {
		return "", err
	}

	return tok.SignedString(p.jwk.Algorithm, p.jwk.Key)
}

func decryptProvisionerJWK(encryptedKey, passFile string) (*jose.JSONWebKey, error) {
	decrypted, err := jose.Decrypt("", []byte(encryptedKey), jose.WithPasswordFile(passFile))
	if err != nil {
		return nil, err
	}

	jwk := new(jose.JSONWebKey)
	if err := json.Unmarshal(decrypted, jwk); err != nil {
		return nil, errors.Wrap(err, "error unmarshalling provisioning key")
	}
	return jwk, nil
}

// loadProvisionerJWKByKid retrieves a provisioner key from the CA by key ID and
// decrypts it using the specified password file.
func loadProvisionerJWKByKid(kid, caUrl, caRoot, passFile string) (*jose.JSONWebKey, error) {
	encrypted, err := pki.GetProvisionerKey(caUrl, caRoot, kid)
	if err != nil {
		return nil, err
	}
	
	return decryptProvisionerJWK(encrypted, passFile)
}

// loadProvisionerJWKByName retrieves the list of provisioners and encrypted key then
// returns the key of the first provisioner with a matching name that can be successfully
// decrypted with the specified password file.
func loadProvisionerJWKByName(name, caUrl, caRoot, passFile string) (key *jose.JSONWebKey, err error) {
	provisioners, err := pki.GetProvisioners(caUrl, caRoot)
	if err != nil {
		err = errors.Wrap(err, "error getting the provisioners")
		return
	}

	for _, provisioner := range provisioners {
		if provisioner.Name == name {
			key, err = decryptProvisionerJWK(provisioner.EncryptedKey, passFile)
			if err == nil {
				return
			}
		}
	}
	return nil, errors.New(fmt.Sprintf("provisioner '%s' not found (or your password is wrong)", name))
}

// NewProvisioner loads and decrypts key material from the CA for the named
// provisioner. The key identified by `kid` will be used if specified. If `kid`
// is the empty string we'll use the first key for the named provisioner that
// decrypts using `passFile`.
func NewProvisioner(name, kid, caUrl, caRoot, passFile string) (Provisioner, error) {
	var jwk *jose.JSONWebKey
	var err error
	if kid != "" {
		jwk, err = loadProvisionerJWKByKid(kid, caUrl, caRoot, passFile)
	} else {
		jwk, err = loadProvisionerJWKByName(name, caUrl, caRoot, passFile)
	}
	if err != nil {
		return nil, err
	}

	return &provisioner{
		name:          name,
		kid:           jwk.KeyID,
		caUrl:         caUrl,
		caRoot:        caRoot,
		jwk:           jwk,
		tokenLifetime: tokenLifetime,
	}, nil
}