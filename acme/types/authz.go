package types

import (
	"encoding/json"

	"github.com/pkg/errors"
)

// Authorization representst an ACME Authorization.
type Authorization struct {
	Identifier Identifier   `json:"identifier"`
	Status     string       `json:"status"`
	Expires    string       `json:"expires"`
	Challenges []*Challenge `json:"challenges"`
	Wildcard   bool         `json:"wildcard"`
	ID         string       `json:"-"`
	AccountID  string       `json:"-"`
}

// ToLog enables response logging.
func (a *Authz) ToLog() (interface{}, error) {
	b, err := json.Marshal(a)
	if err != nil {
		return nil, ServerInternalErr(errors.Wrap(err, "error marshaling authz for logging"))
	}
	return string(b), nil
}
