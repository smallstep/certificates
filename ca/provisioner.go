package ca

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/cli/config"
	"github.com/smallstep/cli/crypto/randutil"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/cli/token"
	"github.com/smallstep/cli/token/provision"
)

const (
	tokenLifetime = 5 * time.Minute
)

// Provisioner is an authorized entity that can sign tokens necessary for
// signature requests.
type Provisioner struct {
	name          string
	kid           string
	caURL         string
	caRoot        string
	jwk           *jose.JSONWebKey
	tokenLifetime time.Duration
}

// NewProvisioner loads and decrypts key material from the CA for the named
// provisioner. The key identified by `kid` will be used if specified. If `kid`
// is the empty string we'll use the first key for the named provisioner that
// decrypts using `passFile`.
func NewProvisioner(name, kid, caURL, caRoot string, password []byte) (*Provisioner, error) {
	var jwk *jose.JSONWebKey
	var err error
	if kid != "" {
		jwk, err = loadProvisionerJWKByKid(kid, caURL, caRoot, password)
	} else {
		jwk, err = loadProvisionerJWKByName(name, caURL, caRoot, password)
	}
	if err != nil {
		return nil, err
	}

	return &Provisioner{
		name:          name,
		kid:           jwk.KeyID,
		caURL:         caURL,
		caRoot:        caRoot,
		jwk:           jwk,
		tokenLifetime: tokenLifetime,
	}, nil
}

// Name returns the provisioner's name.
func (p *Provisioner) Name() string {
	return p.name
}

// Kid returns the provisioners key ID.
func (p *Provisioner) Kid() string {
	return p.kid
}

// Token generates a bootstrap token for a subject.
func (p *Provisioner) Token(subject string) (string, error) {
	// A random jwt id will be used to identify duplicated tokens
	jwtID, err := randutil.Hex(64) // 256 bits
	if err != nil {
		return "", err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(tokenLifetime)
	signURL := fmt.Sprintf("%v/1.0/sign", p.caURL)

	tokOptions := []token.Options{
		token.WithJWTID(jwtID),
		token.WithKid(p.kid),
		token.WithIssuer(p.name),
		token.WithAudience(signURL),
		token.WithValidity(notBefore, notAfter),
		token.WithRootCA(p.caRoot),
		token.WithSANS([]string{subject}),
	}

	tok, err := provision.New(subject, tokOptions...)
	if err != nil {
		return "", err
	}

	return tok.SignedString(p.jwk.Algorithm, p.jwk.Key)
}

func decryptProvisionerJWK(encryptedKey string, password []byte) (*jose.JSONWebKey, error) {
	enc, err := jose.ParseEncrypted(encryptedKey)
	if err != nil {
		return nil, err
	}
	data, err := enc.Decrypt(password)
	if err != nil {
		return nil, err
	}
	jwk := new(jose.JSONWebKey)
	if err := json.Unmarshal(data, jwk); err != nil {
		return nil, errors.Wrap(err, "error unmarshaling provisioning key")
	}
	return jwk, nil
}

// loadProvisionerJWKByKid retrieves a provisioner key from the CA by key ID and
// decrypts it using the specified password file.
func loadProvisionerJWKByKid(kid, caURL, caRoot string, password []byte) (*jose.JSONWebKey, error) {
	encrypted, err := getProvisionerKey(caURL, caRoot, kid)
	if err != nil {
		return nil, err
	}

	return decryptProvisionerJWK(encrypted, password)
}

// loadProvisionerJWKByName retrieves the list of provisioners and encrypted key then
// returns the key of the first provisioner with a matching name that can be successfully
// decrypted with the specified password file.
func loadProvisionerJWKByName(name, caURL, caRoot string, password []byte) (key *jose.JSONWebKey, err error) {
	provisioners, err := getProvisioners(caURL, caRoot)
	if err != nil {
		err = errors.Wrap(err, "error getting the provisioners")
		return
	}

	for _, provisioner := range provisioners {
		if provisioner.GetName() == name {
			if _, encryptedKey, ok := provisioner.GetEncryptedKey(); ok {
				key, err = decryptProvisionerJWK(encryptedKey, password)
				if err == nil {
					return
				}
			}
		}
	}
	return nil, errors.Errorf("provisioner '%s' not found (or your password is wrong)", name)
}

// getRootCAPath returns the path where the root CA is stored based on the
// STEPPATH environment variable.
func getRootCAPath() string {
	return filepath.Join(config.StepPath(), "certs", "root_ca.crt")
}

// getProvisioners returns the map of provisioners on the given CA.
func getProvisioners(caURL, rootFile string) (provisioner.List, error) {
	if len(rootFile) == 0 {
		rootFile = getRootCAPath()
	}
	client, err := NewClient(caURL, WithRootFile(rootFile))
	if err != nil {
		return nil, err
	}
	cursor := ""
	var provisioners provisioner.List
	for {
		resp, err := client.Provisioners(WithProvisionerCursor(cursor), WithProvisionerLimit(100))
		if err != nil {
			return nil, err
		}
		provisioners = append(provisioners, resp.Provisioners...)
		if resp.NextCursor == "" {
			return provisioners, nil
		}
		cursor = resp.NextCursor
	}
}

// getProvisionerKey returns the encrypted provisioner key with the for the
// given kid.
func getProvisionerKey(caURL, rootFile, kid string) (string, error) {
	if len(rootFile) == 0 {
		rootFile = getRootCAPath()
	}
	client, err := NewClient(caURL, WithRootFile(rootFile))
	if err != nil {
		return "", err
	}
	resp, err := client.ProvisionerKey(kid)
	if err != nil {
		return "", err
	}
	return resp.Key, nil
}
