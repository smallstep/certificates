package models

import (
	"context"
	"crypto/x509"
	"errors"

	"github.com/smallstep/certificates/authority/provisioner"
	"golang.org/x/crypto/ssh"
)

var errDummyImplementation = errors.New("dummy implementation")

// SCEP is the SCEP provisioner model used solely in CA API
// responses. All methods for the [provisioner.Interface] interface
// are implemented, but return a dummy error.
// TODO(hs): remove reliance on the interface for the API responses
type SCEP struct {
	ID                            string               `json:"-"`
	Type                          string               `json:"type"`
	Name                          string               `json:"name"`
	ForceCN                       bool                 `json:"forceCN"`
	ChallengePassword             string               `json:"challenge"`
	Capabilities                  []string             `json:"capabilities,omitempty"`
	IncludeRoot                   bool                 `json:"includeRoot"`
	ExcludeIntermediate           bool                 `json:"excludeIntermediate"`
	MinimumPublicKeyLength        int                  `json:"minimumPublicKeyLength"`
	DecrypterCertificate          []byte               `json:"decrypterCertificate"`
	DecrypterKeyPEM               []byte               `json:"decrypterKeyPEM"`
	DecrypterKeyURI               string               `json:"decrypterKey"`
	DecrypterKeyPassword          string               `json:"decrypterKeyPassword"`
	EncryptionAlgorithmIdentifier int                  `json:"encryptionAlgorithmIdentifier"`
	Options                       *provisioner.Options `json:"options,omitempty"`
	Claims                        *provisioner.Claims  `json:"claims,omitempty"`
}

// GetID returns the provisioner unique identifier.
func (s *SCEP) GetID() string {
	if s.ID != "" {
		return s.ID
	}
	return s.GetIDForToken()
}

// GetIDForToken returns an identifier that will be used to load the provisioner
// from a token.
func (s *SCEP) GetIDForToken() string {
	return "scep/" + s.Name
}

// GetName returns the name of the provisioner.
func (s *SCEP) GetName() string {
	return s.Name
}

// GetType returns the type of provisioner.
func (s *SCEP) GetType() provisioner.Type {
	return provisioner.TypeSCEP
}

// GetEncryptedKey returns the base provisioner encrypted key if it's defined.
func (s *SCEP) GetEncryptedKey() (string, string, bool) {
	return "", "", false
}

// GetTokenID returns the identifier of the token.
func (s *SCEP) GetTokenID(string) (string, error) {
	return "", errDummyImplementation
}

// Init initializes and validates the fields of a SCEP type.
func (s *SCEP) Init(_ provisioner.Config) (err error) {
	return errDummyImplementation
}

// AuthorizeSign returns an unimplemented error. Provisioners should overwrite
// this method if they will support authorizing tokens for signing x509 Certificates.
func (s *SCEP) AuthorizeSign(context.Context, string) ([]provisioner.SignOption, error) {
	return nil, errDummyImplementation
}

// AuthorizeRevoke returns an unimplemented error. Provisioners should overwrite
// this method if they will support authorizing tokens for revoking x509 Certificates.
func (s *SCEP) AuthorizeRevoke(context.Context, string) error {
	return errDummyImplementation
}

// AuthorizeRenew returns an unimplemented error. Provisioners should overwrite
// this method if they will support authorizing tokens for renewing x509 Certificates.
func (s *SCEP) AuthorizeRenew(context.Context, *x509.Certificate) error {
	return errDummyImplementation
}

// AuthorizeSSHSign returns an unimplemented error. Provisioners should overwrite
// this method if they will support authorizing tokens for signing SSH Certificates.
func (s *SCEP) AuthorizeSSHSign(context.Context, string) ([]provisioner.SignOption, error) {
	return nil, errDummyImplementation
}

// AuthorizeSSHRevoke returns an unimplemented error. Provisioners should overwrite
// this method if they will support authorizing tokens for revoking SSH Certificates.
func (s *SCEP) AuthorizeSSHRevoke(context.Context, string) error {
	return errDummyImplementation
}

// AuthorizeSSHRenew returns an unimplemented error. Provisioners should overwrite
// this method if they will support authorizing tokens for renewing SSH Certificates.
func (s *SCEP) AuthorizeSSHRenew(context.Context, string) (*ssh.Certificate, error) {
	return nil, errDummyImplementation
}

// AuthorizeSSHRekey returns an unimplemented error. Provisioners should overwrite
// this method if they will support authorizing tokens for rekeying SSH Certificates.
func (s *SCEP) AuthorizeSSHRekey(context.Context, string) (*ssh.Certificate, []provisioner.SignOption, error) {
	return nil, nil, errDummyImplementation
}

var _ provisioner.Interface = (*SCEP)(nil)
