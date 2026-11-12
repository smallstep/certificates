package acme

import (
	"context"
	"encoding/json"
	"time"
)

// Authorization representst an ACME Authorization.
type Authorization struct {
	ID          string       `json:"-"`
	AccountID   string       `json:"-"`
	Token       string       `json:"-"`
	Fingerprint string       `json:"-"`
	Identifier  Identifier   `json:"identifier"`
	Status      Status       `json:"status"`
	Challenges  []*Challenge `json:"challenges"`
	Wildcard    bool         `json:"wildcard"`
	ExpiresAt   time.Time    `json:"expires"`
	Error       *Error       `json:"error,omitempty"`
}

// ToLog enables response logging.
func (az *Authorization) ToLog() (any, error) {
	b, err := json.Marshal(az)
	if err != nil {
		return nil, WrapErrorISE(err, "error marshaling authz for logging")
	}
	return string(b), nil
}

// UpdateStatus updates the ACME Authorization Status if necessary.
// Changes to the Authorization are saved using the database interface.
func (az *Authorization) UpdateStatus(ctx context.Context, db DB) error {
	now := clock.Now()

	switch az.Status {
	case StatusInvalid:
		return nil
	case StatusValid:
		return nil
	case StatusPending:
		// check expiry
		if now.After(az.ExpiresAt) {
			az.Status = StatusInvalid
			break
		}

		var (
			isValid bool
			invalid *Challenge
		)
		for _, ch := range az.Challenges {
			if ch.Status == StatusValid {
				isValid = true
				break
			}
			if ch.Status == StatusInvalid && invalid == nil {
				invalid = ch
			}
		}

		switch {
		case isValid:
			az.Status = StatusValid
			az.Error = nil
		case invalid != nil:
			// RFC 8555, section 7.1.6: if the client attempts to fulfill a
			// challenge and fails, the authorization transitions to invalid.
			// Leaving it pending makes clients poll until it expires.
			az.Status = StatusInvalid
			az.Error = invalid.Error
		default:
			return nil
		}
	default:
		return NewErrorISE("unrecognized authorization status: %s", az.Status)
	}

	if err := db.UpdateAuthorization(ctx, az); err != nil {
		return WrapErrorISE(err, "error updating authorization")
	}
	return nil
}
