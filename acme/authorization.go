package types

import (
	"context"
	"encoding/json"
	"time"

	"github.com/pkg/errors"
)

// Authorization representst an ACME Authorization.
type Authorization struct {
	Identifier *Identifier  `json:"identifier"`
	Status     string       `json:"status"`
	Expires    string       `json:"expires"`
	Challenges []*Challenge `json:"challenges"`
	Wildcard   bool         `json:"wildcard"`
	ID         string       `json:"-"`
	AccountID  string       `json:"-"`
}

// ToLog enables response logging.
func (az *Authorization) ToLog() (interface{}, error) {
	b, err := json.Marshal(az)
	if err != nil {
		return nil, ServerInternalErr(errors.Wrap(err, "error marshaling authz for logging"))
	}
	return string(b), nil
}

// UpdateStatus updates the ACME Authorization Status if necessary.
// Changes to the Authorization are saved using the database interface.
func (az *Authorization) UpdateStatus(ctx context.Context, db DB) error {
	now := time.Now().UTC()
	expiry, err := time.Parse(time.RFC3339, az.Expires)
	if err != nil {
		return ServerInternalErr(errors.Wrap("error converting expiry string to time"))
	}

	switch az.Status {
	case StatusInvalid:
		return nil
	case StatusValid:
		return nil
	case StatusPending:
		// check expiry
		if now.After(expiry) {
			az.Status = StatusInvalid
			az.Error = MalformedErr(errors.New("authz has expired"))
			break
		}

		var isValid = false
		for _, chID := range ba.Challenges {
			ch, err := db.GetChallenge(ctx, chID, az.ID)
			if err != nil {
				return ServerInternalErr(err)
			}
			if ch.Status == StatusValid {
				isValid = true
				break
			}
		}

		if !isValid {
			return nil
		}
		az.Status = StatusValid
		az.Error = nil
	default:
		return nil, ServerInternalErr(errors.Errorf("unrecognized authz status: %s", ba.Status))
	}

	return ServerInternalErr(db.UpdateAuthorization(ctx, az))
}
