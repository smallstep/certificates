package acme

import (
	"encoding/json"

	"github.com/pkg/errors"
	"go.step.sm/crypto/jose"
)

// Account is a subset of the internal account type containing only those
// attributes required for responses in the ACME protocol.
type Account struct {
	Contact []string         `json:"contact,omitempty"`
	Status  string           `json:"status"`
	Orders  string           `json:"orders"`
	ID      string           `json:"-"`
	Key     *jose.JSONWebKey `json:"-"`
}

// ToLog enables response logging.
func (a *Account) ToLog() (interface{}, error) {
	b, err := json.Marshal(a)
	if err != nil {
		return nil, ServerInternalErr(errors.Wrap(err, "error marshaling account for logging"))
	}
	return string(b), nil
}

// GetID returns the account ID.
func (a *Account) GetID() string {
	return a.ID
}

// GetKey returns the JWK associated with the account.
func (a *Account) GetKey() *jose.JSONWebKey {
	return a.Key
}

// IsValid returns true if the Account is valid.
func (a *Account) IsValid() bool {
	return Status(a.Status) == StatusValid
}
