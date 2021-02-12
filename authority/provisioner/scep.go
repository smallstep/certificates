package provisioner

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"github.com/pkg/errors"
)

// SCEP is the SCEP provisioner type, an entity that can authorize the
// SCEP provisioning flow
type SCEP struct {
	*base
	Type string `json:"type"`
	Name string `json:"name"`
	// ForceCN bool     `json:"forceCN,omitempty"`
	// Claims  *Claims  `json:"claims,omitempty"`
	// Options *Options `json:"options,omitempty"`
	// claimer *Claimer

	IntermediateCert string
	SigningKey       string
	CACertificates   []*x509.Certificate
}

// GetID returns the provisioner unique identifier.
func (s SCEP) GetID() string {
	return "scep/" + s.Name
}

// GetName returns the name of the provisioner.
func (s *SCEP) GetName() string {
	return s.Name
}

// GetType returns the type of provisioner.
func (s *SCEP) GetType() Type {
	return TypeSCEP
}

// GetEncryptedKey returns the base provisioner encrypted key if it's defined.
func (s *SCEP) GetEncryptedKey() (string, string, bool) {
	return "", "", false
}

// GetTokenID returns the identifier of the token.
func (s *SCEP) GetTokenID(ott string) (string, error) {
	return "", errors.New("scep provisioner does not implement GetTokenID")
}

// GetCACertificates returns the CA certificate chain
// TODO: this should come from the authority instead?
func (s *SCEP) GetCACertificates() []*x509.Certificate {

	pemtxt, _ := ioutil.ReadFile(s.IntermediateCert) // TODO: move reading key to init? That's probably safer.
	block, _ := pem.Decode([]byte(pemtxt))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Println(err)
	}

	// TODO: return chain? I'm not sure if the client understands it correctly
	return []*x509.Certificate{cert}
}

func (s *SCEP) GetSigningKey() *rsa.PrivateKey {

	keyBytes, err := ioutil.ReadFile(s.SigningKey)
	if err != nil {
		return nil
	}

	block, _ := pem.Decode([]byte(keyBytes))
	if block == nil {
		return nil
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	return key
}

// Init initializes and validates the fields of a JWK type.
func (s *SCEP) Init(config Config) (err error) {

	switch {
	case s.Type == "":
		return errors.New("provisioner type cannot be empty")
	case s.Name == "":
		return errors.New("provisioner name cannot be empty")
	}

	// // Update claims with global ones
	// if p.claimer, err = NewClaimer(p.Claims, config.Claims); err != nil {
	// 	return err
	// }

	s.IntermediateCert = config.IntermediateCert
	s.SigningKey = config.SigningKey
	s.CACertificates = config.CACertificates

	return err
}

// Interface guards
var (
	_ Interface = (*SCEP)(nil)
	//_ scep.Provisioner = (*SCEP)(nil)
)
