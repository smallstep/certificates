package identity

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
	"go.step.sm/cli-utils/config"
	"go.step.sm/crypto/pemutil"
)

// Type represents the different types of identity files.
type Type string

// Disabled represents a disabled identity type
const Disabled Type = ""

// MutualTLS represents the identity using mTLS
const MutualTLS Type = "mTLS"

// DefaultLeeway is the duration for matching not before claims.
const DefaultLeeway = 1 * time.Minute

// IdentityFile contains the location of the identity file.
var IdentityFile = filepath.Join(config.StepPath(), "config", "identity.json")

// DefaultsFile contains the location of the defaults file.
var DefaultsFile = filepath.Join(config.StepPath(), "config", "defaults.json")

// Identity represents the identity file that can be used to authenticate with
// the CA.
type Identity struct {
	Type        string `json:"type"`
	Certificate string `json:"crt"`
	Key         string `json:"key"`
}

// LoadDefaultIdentity loads the default identity.
func LoadDefaultIdentity() (*Identity, error) {
	b, err := ioutil.ReadFile(IdentityFile)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading %s", IdentityFile)
	}
	identity := new(Identity)
	if err := json.Unmarshal(b, &identity); err != nil {
		return nil, errors.Wrapf(err, "error unmarshaling %s", IdentityFile)
	}
	return identity, nil
}

// configDir and identityDir are used in WriteDefaultIdentity for testing
// purposes.
var (
	configDir   = filepath.Join(config.StepPath(), "config")
	identityDir = filepath.Join(config.StepPath(), "identity")
)

// WriteDefaultIdentity writes the given certificates and key and the
// identity.json pointing to the new files.
func WriteDefaultIdentity(certChain []api.Certificate, key crypto.PrivateKey) error {
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return errors.Wrap(err, "error creating config directory")
	}

	if err := os.MkdirAll(identityDir, 0700); err != nil {
		return errors.Wrap(err, "error creating identity directory")
	}

	certFilename := filepath.Join(identityDir, "identity.crt")
	keyFilename := filepath.Join(identityDir, "identity_key")

	// Write certificate
	if err := WriteIdentityCertificate(certChain); err != nil {
		return err
	}

	// Write key
	buf := new(bytes.Buffer)
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

// WriteIdentityCertificate writes the identity certificate in disk.
func WriteIdentityCertificate(certChain []api.Certificate) error {
	buf := new(bytes.Buffer)
	certFilename := filepath.Join(identityDir, "identity.crt")
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

	return nil
}

// Kind returns the type for the given identity.
func (i *Identity) Kind() Type {
	switch strings.ToLower(i.Type) {
	case "":
		return Disabled
	case "mtls":
		return MutualTLS
	default:
		return Type(i.Type)
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
		if err := fileExists(i.Certificate); err != nil {
			return err
		}
		if err := fileExists(i.Key); err != nil {
			return err
		}
		return nil
	default:
		return errors.Errorf("unsupported identity type %s", i.Type)
	}
}

// TLSCertificate returns a tls.Certificate for the identity.
func (i *Identity) TLSCertificate() (tls.Certificate, error) {
	fail := func(err error) (tls.Certificate, error) { return tls.Certificate{}, err }
	switch i.Kind() {
	case Disabled:
		return tls.Certificate{}, nil
	case MutualTLS:
		crt, err := tls.LoadX509KeyPair(i.Certificate, i.Key)
		if err != nil {
			return fail(errors.Wrap(err, "error creating identity certificate"))
		}

		// Check if certificate is expired.
		x509Cert, err := x509.ParseCertificate(crt.Certificate[0])
		if err != nil {
			return fail(errors.Wrap(err, "error creating identity certificate"))
		}
		now := time.Now().Truncate(time.Second)
		if now.Add(DefaultLeeway).Before(x509Cert.NotBefore) {
			return fail(errors.New("certificate is not yet valid"))
		}
		if now.After(x509Cert.NotAfter) {
			return fail(errors.New("certificate is already expired"))
		}
		return crt, nil
	default:
		return fail(errors.Errorf("unsupported identity type %s", i.Type))
	}
}

// GetClientCertificateFunc returns a method that can be used as the
// GetClientCertificate property in a tls.Config.
func (i *Identity) GetClientCertificateFunc() func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		crt, err := tls.LoadX509KeyPair(i.Certificate, i.Key)
		if err != nil {
			return nil, errors.Wrap(err, "error loading identity certificate")
		}
		return &crt, nil
	}
}

// Renewer is that interface that a renew client must implement.
type Renewer interface {
	GetRootCAs() *x509.CertPool
	Renew(tr http.RoundTripper) (*api.SignResponse, error)
}

// Renew renews the current identity certificate using a client with a renew
// method.
func (i *Identity) Renew(client Renewer) error {
	switch i.Kind() {
	case Disabled:
		return nil
	case MutualTLS:
		cert, err := i.TLSCertificate()
		if err != nil {
			return err
		}

		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{
			Certificates:             []tls.Certificate{cert},
			RootCAs:                  client.GetRootCAs(),
			PreferServerCipherSuites: true,
		}

		sign, err := client.Renew(tr)
		if err != nil {
			return err
		}

		if sign.CertChainPEM == nil || len(sign.CertChainPEM) == 0 {
			sign.CertChainPEM = []api.Certificate{sign.ServerPEM, sign.CaPEM}
		}

		// Write certificate
		buf := new(bytes.Buffer)
		for _, crt := range sign.CertChainPEM {
			block := &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: crt.Raw,
			}
			if err := pem.Encode(buf, block); err != nil {
				return errors.Wrap(err, "error encoding identity certificate")
			}
		}
		certFilename := filepath.Join(identityDir, "identity.crt")
		if err := ioutil.WriteFile(certFilename, buf.Bytes(), 0600); err != nil {
			return errors.Wrap(err, "error writing identity certificate")
		}

		return nil
	default:
		return errors.Errorf("unsupported identity type %s", i.Type)
	}
}

func fileExists(filename string) error {
	info, err := os.Stat(filename)
	if err != nil {
		return errors.Wrapf(err, "error reading %s", filename)
	}
	if info.IsDir() {
		return errors.Errorf("error reading %s: file is a directory", filename)
	}
	return nil
}
