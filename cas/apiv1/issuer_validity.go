package apiv1

import (
	"fmt"
	"net/http"
	"time"
)

// IssuerValidityError is a request-policy rejection, not a malformed CA path.
type IssuerValidityError struct {
	RequestedNotAfter time.Time
	LimitNotAfter     time.Time
	Reason            string
}

// Error returns the safe public policy diagnostic.
func (e *IssuerValidityError) Error() string {
	limit := e.LimitNotAfter.UTC().Truncate(time.Second).Format(time.RFC3339)
	if e.Reason == "no_remaining_validity" {
		return fmt.Sprintf("issuing CA chain expiration %s leaves no usable certificate validity; contact the CA operator", limit)
	}
	return fmt.Sprintf("requested certificate expiration %s exceeds issuing CA chain expiration %s", e.RequestedNotAfter.UTC().Truncate(time.Second).Format(time.RFC3339), limit)
}

// StatusCode returns the native API policy rejection status.
func (e *IssuerValidityError) StatusCode() int {
	return http.StatusForbidden
}
