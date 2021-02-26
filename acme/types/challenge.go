package types

import (
	"encoding/json"

	"github.com/pkg/errors"
)

// Challenge represents an ACME response Challenge type.
type Challenge struct {
	Type      string  `json:"type"`
	Status    string  `json:"status"`
	Token     string  `json:"token"`
	Validated string  `json:"validated,omitempty"`
	URL       string  `json:"url"`
	Error     *AError `json:"error,omitempty"`
	ID        string  `json:"-"`
	AuthzID   string  `json:"-"`
	AccountID string  `json:"-"`
	Value     string  `json:"-"`
}

// ToLog enables response logging.
func (c *Challenge) ToLog() (interface{}, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return nil, ServerInternalErr(errors.Wrap(err, "error marshaling challenge for logging"))
	}
	return string(b), nil
}
