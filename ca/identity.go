package ca

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/cli/config"
	"github.com/smallstep/cli/crypto/pemutil"
)

// IdentityType represents the different types of identity files.
type IdentityType string

// DisableIdentity is a global variable to disable the identity.
var DisableIdentity = false

// Disabled represents a disabled identity type
const Disabled IdentityType = ""

// MutualTLS represents the identity using mTLS
const MutualTLS IdentityType = "mTLS"

// DefaultLeeway is the duration for matching not before claims.
const DefaultLeeway = 1 * time.Minute

// IdentityFile contains the location of the identity file.
var IdentityFile = filepath.Join(config.StepPath(), "config", "identity.json")

// Identity represents the identity file that can be used to authenticate with
// the CA.
type Identity struct {
	Type        string `json:"type"`
	Certificate string `json:"crt"`
	Key         string `json:"key"`
}

// NewIdentityRequest returns a new CSR to create the identity. If an identity
// was already present it reuses the private key.
func NewIdentityRequest(commonName string, sans ...string) (*api.CertificateRequest, crypto.PrivateKey, error) {
	var identityKey crypto.PrivateKey
	if i, err := LoadDefaultIdentity(); err == nil && i.Key != "" {
		if k, err := pemutil.Read(i.Key); err == nil {
			identityKey = k
		}
	}
	if identityKey == nil {
		return CreateCertificateRequest(commonName, sans...)
	}
	return createCertificateRequest(commonName, sans, identityKey)
}

// LoadDefaultIdentity loads the default identity.
func LoadDefaultIdentity() (*Identity, error) {
	b, err := ioutil.ReadFile(IdentityFile)
	if err != nil {
		return nil, errors.Wrap(err, "error reading identity json")
	}
	identity := new(Identity)
	if err := json.Unmarshal(b, &identity); err != nil {
		return nil, errors.Wrapf(err, "error unmarshaling %s", IdentityFile)
	}
	return identity, nil
}

// WriteDefaultIdentity writes the given certificates and key and the
// identity.json pointing to the new files.
func WriteDefaultIdentity(certChain []api.Certificate, key crypto.PrivateKey) error {
	base := filepath.Join(config.StepPath(), "config")
	if err := os.MkdirAll(base, 0700); err != nil {
		return errors.Wrap(err, "error creating config directory")
	}

	base = filepath.Join(config.StepPath(), "identity")
	if err := os.MkdirAll(base, 0700); err != nil {
		return errors.Wrap(err, "error creating identity directory")
	}

	certFilename := filepath.Join(base, "identity.crt")
	keyFilename := filepath.Join(base, "identity_key")

	// Write certificate
	buf := new(bytes.Buffer)
	for _, crt := range certChain {
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: crt.Raw,
		}
		if err := pem.Encode(buf, block); err != nil {
			return errors.Wrap(err, "error encoding identity certificate")
		}
	}
	if err := ioutil.WriteFile(certFilename, buf.Bytes(), 0600); err != nil {
		return errors.Wrap(err, "error writing identity certificate")
	}

	// Write key
	buf.Reset()
	block, err := pemutil.Serialize(key)
	if err != nil {
		return err
	}
	if err := pem.Encode(buf, block); err != nil {
		return errors.Wrap(err, "error encoding identity key")
	}
	if err := ioutil.WriteFile(keyFilename, buf.Bytes(), 0600); err != nil {
		return errors.Wrap(err, "error writing identity certificate")
	}

	// Write identity.json
	buf.Reset()
	enc := json.NewEncoder(buf)
	enc.SetIndent("", "   ")
	if err := enc.Encode(Identity{
		Type:        string(MutualTLS),
		Certificate: certFilename,
		Key:         keyFilename,
	}); err != nil {
		return errors.Wrap(err, "error writing identity json")
	}
	if err := ioutil.WriteFile(IdentityFile, buf.Bytes(), 0600); err != nil {
		return errors.Wrap(err, "error writing identity certificate")
	}

	return nil
}

// Kind returns the type for the given identity.
func (i *Identity) Kind() IdentityType {
	switch strings.ToLower(i.Type) {
	case "":
		return Disabled
	case "mtls":
		return MutualTLS
	default:
		return IdentityType(i.Type)
	}
}

// Validate validates the identity object.
func (i *Identity) Validate() error {
	switch i.Kind() {
	case Disabled:
		return nil
	case MutualTLS:
		if i.Certificate == "" {
			return errors.New("identity.crt cannot be empty")
		}
		if i.Key == "" {
			return errors.New("identity.key cannot be empty")
		}
		return nil
	default:
		return errors.Errorf("unsupported identity type %s", i.Type)
	}
}

// Options returns the ClientOptions used for the given identity.
func (i *Identity) Options() ([]ClientOption, error) {
	switch i.Kind() {
	case Disabled:
		return nil, nil
	case MutualTLS:
		crt, err := tls.LoadX509KeyPair(i.Certificate, i.Key)
		if err != nil {
			return nil, errors.Wrap(err, "error creating identity certificate")
		}
		// Check if certificate is expired.
		// Do not return any options if expired.
		x509Cert, err := x509.ParseCertificate(crt.Certificate[0])
		if err != nil {
			return nil, errors.Wrap(err, "error creating identity certificate")
		}
		now := time.Now().Truncate(time.Second)
		if now.Add(DefaultLeeway).Before(x509Cert.NotBefore) || now.After(x509Cert.NotAfter) {
			return nil, nil
		}
		return []ClientOption{WithCertificate(crt)}, nil
	default:
		return nil, errors.Errorf("unsupported identity type %s", i.Type)
	}
}

// Renew renews the identity certificate using the given client.
func (i *Identity) Renew(client *Client) error {
	switch i.Kind() {
	case Disabled:
		return nil
	case MutualTLS:
		cert, err := tls.LoadX509KeyPair(i.Certificate, i.Key)
		if err != nil {
			return errors.Wrap(err, "error creating identity certificate")
		}
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates:             []tls.Certificate{cert},
				RootCAs:                  client.GetRootCAs(),
				PreferServerCipherSuites: true,
			},
		}
		resp, err := client.Renew(tr)
		if err != nil {
			return err
		}
		buf := new(bytes.Buffer)
		for _, crt := range resp.CertChainPEM {
			block := &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: crt.Raw,
			}
			if err := pem.Encode(buf, block); err != nil {
				return errors.Wrap(err, "error encoding identity certificate")
			}
		}
		if err := ioutil.WriteFile(i.Certificate, buf.Bytes(), 0600); err != nil {
			return errors.Wrap(err, "error writing identity certificate")
		}
		return nil
	default:
		return errors.Errorf("unsupported identity type %s", i.Type)
	}
}
