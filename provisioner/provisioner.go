package provisioner

import (
	"errors"

	jose "gopkg.in/square/go-jose.v2"
)

// Provisioner - authorized entity that can sign tokens necessary for signature requests.
type Provisioner struct {
	Issuer       string           `json:"issuer,omitempty"`
	Type         string           `json:"type,omitempty"`
	Key          *jose.JSONWebKey `json:"key,omitempty"`
	EncryptedKey string           `json:"encryptedKey,omitempty"`
}

// Validate validates a provisioner.
func (p *Provisioner) Validate() error {
	switch {
	case p.Issuer == "":
		return errors.New("provisioner issuer cannot be empty")

	case p.Type == "":
		return errors.New("provisioner type cannot be empty")

	case p.Key == nil:
		return errors.New("provisioner key cannot be empty")
	}

	return nil
}
