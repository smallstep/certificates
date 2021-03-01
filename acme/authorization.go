package acme

import (
	"context"
	"encoding/json"
	"time"
)

// Authorization representst an ACME Authorization.
type Authorization struct {
	Identifier *Identifier  `json:"identifier"`
	Status     Status       `json:"status"`
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
		return nil, ErrorInternalServerWrap(err, "error marshaling authz for logging")
	}
	return string(b), nil
}

// UpdateStatus updates the ACME Authorization Status if necessary.
// Changes to the Authorization are saved using the database interface.
func (az *Authorization) UpdateStatus(ctx context.Context, db DB) error {
	now := time.Now().UTC()
	expiry, err := time.Parse(time.RFC3339, az.Expires)
	if err != nil {
		return ErrorInternalServerWrap(err, "error converting expiry string to time")
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
			break
		}

		var isValid = false
		for _, ch := range az.Challenges {
			if ch.Status == StatusValid {
				isValid = true
				break
			}
		}

		if !isValid {
			return nil
		}
		az.Status = StatusValid
	default:
		return NewError(ErrorServerInternalType, "unrecognized authorization status: %s", az.Status)
	}

	if err = db.UpdateAuthorization(ctx, az); err != nil {
		return ErrorInternalServerWrap(err, "error updating authorization")
	}
	return nil
}
