package ca

import (
	"crypto/tls"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/config"
)

// IdentityType represents the different types of identity files.
type IdentityType string

// MutualTLS represents the identity using mTLS
const MutualTLS IdentityType = "mTLS"

// IdentityFile contains the location of the identity file.
var IdentityFile = filepath.Join(config.StepPath(), "config", "identity.json")

// Identity represents the identity file that can be used to authenticate with
// the CA.
type Identity struct {
	Type        string `json:"type"`
	Certificate string `json:"crt"`
	Key         string `json:"key"`
}

// Kind returns the type for the given identity.
func (i *Identity) Kind() IdentityType {
	switch strings.ToLower(i.Type) {
	case "mtls":
		return MutualTLS
	default:
		return IdentityType(i.Type)
	}
}

// Validate validates the identity object.
func (i *Identity) Validate() error {
	switch i.Kind() {
	case MutualTLS:
		if i.Certificate == "" {
			return errors.New("identity.crt cannot be empty")
		}
		if i.Key == "" {
			return errors.New("identity.key cannot be empty")
		}
		return nil
	case "":
		return errors.New("identity.type cannot be empty")
	default:
		return errors.Errorf("unsupported identity type %s", i.Type)
	}
}

// Options returns the ClientOptions used for the given identity.
func (i *Identity) Options() ([]ClientOption, error) {
	switch i.Kind() {
	case MutualTLS:
		crt, err := tls.LoadX509KeyPair(i.Certificate, i.Key)
		if err != nil {
			return nil, errors.Wrap(err, "error creating identity certificate")
		}
		return []ClientOption{WithCertificate(crt)}, nil
	default:
		return nil, errors.Errorf("unsupported identity type %s", i.Type)
	}
}
