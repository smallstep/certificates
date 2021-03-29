package acme

import (
	"crypto"
	"encoding/base64"
	"encoding/json"

	"go.step.sm/crypto/jose"
)

// Account is a subset of the internal account type containing only those
// attributes required for responses in the ACME protocol.
type Account struct {
	ID        string           `json:"-"`
	Key       *jose.JSONWebKey `json:"-"`
	Contact   []string         `json:"contact,omitempty"`
	Status    Status           `json:"status"`
	OrdersURL string           `json:"orders"`
}

// ToLog enables response logging.
func (a *Account) ToLog() (interface{}, error) {
	b, err := json.Marshal(a)
	if err != nil {
		return nil, WrapErrorISE(err, "error marshaling account for logging")
	}
	return string(b), nil
}

// IsValid returns true if the Account is valid.
func (a *Account) IsValid() bool {
	return Status(a.Status) == StatusValid
}

// KeyToID converts a JWK to a thumbprint.
func KeyToID(jwk *jose.JSONWebKey) (string, error) {
	kid, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", WrapErrorISE(err, "error generating jwk thumbprint")
	}
	return base64.RawURLEncoding.EncodeToString(kid), nil
}
