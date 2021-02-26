package types

import (
	"encoding/json"

	"github.com/pkg/errors"
)

// Order contains order metadata for the ACME protocol order type.
type Order struct {
	Status         string       `json:"status"`
	Expires        string       `json:"expires,omitempty"`
	Identifiers    []Identifier `json:"identifiers"`
	NotBefore      string       `json:"notBefore,omitempty"`
	NotAfter       string       `json:"notAfter,omitempty"`
	Error          interface{}  `json:"error,omitempty"`
	Authorizations []string     `json:"authorizations"`
	Finalize       string       `json:"finalize"`
	Certificate    string       `json:"certificate,omitempty"`
	ID             string       `json:"-"`
}

// ToLog enables response logging.
func (o *Order) ToLog() (interface{}, error) {
	b, err := json.Marshal(o)
	if err != nil {
		return nil, ServerInternalErr(errors.Wrap(err, "error marshaling order for logging"))
	}
	return string(b), nil
}
