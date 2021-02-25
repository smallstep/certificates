package types

import (
	"encoding/json"

	"github.com/pkg/errors"
)

// Authz is a subset of the Authz type containing only those attributes
// required for responses in the ACME protocol.
type Authz struct {
	Identifier Identifier   `json:"identifier"`
	Status     string       `json:"status"`
	Expires    string       `json:"expires"`
	Challenges []*Challenge `json:"challenges"`
	Wildcard   bool         `json:"wildcard"`
	ID         string       `json:"-"`
}

// ToLog enables response logging.
func (a *Authz) ToLog() (interface{}, error) {
	b, err := json.Marshal(a)
	if err != nil {
		return nil, ServerInternalErr(errors.Wrap(err, "error marshaling authz for logging"))
	}
	return string(b), nil
}

// GetID returns the Authz ID.
func (a *Authz) GetID() string {
	return a.ID
}
