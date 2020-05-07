package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/pkg/errors"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/logging"
)

// NewAccountRequest represents the payload for a new account request.
type NewAccountRequest struct {
	Contact              []string `json:"contact"`
	OnlyReturnExisting   bool     `json:"onlyReturnExisting"`
	TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
}

func validateContacts(cs []string) error {
	for _, c := range cs {
		if len(c) == 0 {
			return acme.MalformedErr(errors.New("contact cannot be empty string"))
		}
	}
	return nil
}

// Validate validates a new-account request body.
func (n *NewAccountRequest) Validate() error {
	if n.OnlyReturnExisting && len(n.Contact) > 0 {
		return acme.MalformedErr(errors.New("incompatible input; onlyReturnExisting must be alone"))
	}
	return validateContacts(n.Contact)
}

// UpdateAccountRequest represents an update-account request.
type UpdateAccountRequest struct {
	Contact []string `json:"contact"`
	Status  string   `json:"status"`
}

// IsDeactivateRequest returns true if the update request is a deactivation
// request, false otherwise.
func (u *UpdateAccountRequest) IsDeactivateRequest() bool {
	return u.Status == acme.StatusDeactivated
}

// Validate validates a update-account request body.
func (u *UpdateAccountRequest) Validate() error {
	switch {
	case len(u.Status) > 0 && len(u.Contact) > 0:
		return acme.MalformedErr(errors.New("incompatible input; contact and " +
			"status updates are mutually exclusive"))
	case len(u.Contact) > 0:
		if err := validateContacts(u.Contact); err != nil {
			return err
		}
		return nil
	case len(u.Status) > 0:
		if u.Status != acme.StatusDeactivated {
			return acme.MalformedErr(errors.Errorf("cannot update account "+
				"status to %s, only deactivated", u.Status))
		}
		return nil
	default:
		// According to the ACME spec (https://tools.ietf.org/html/rfc8555#section-7.3.2)
		// accountUpdate should ignore any fields not recognized by the server.
		return nil
	}
}

// NewAccount is the handler resource for creating new ACME accounts.
func (h *Handler) NewAccount(w http.ResponseWriter, r *http.Request) {
	payload, err := payloadFromContext(r.Context())
	if err != nil {
		api.WriteError(w, err)
		return
	}
	var nar NewAccountRequest
	if err := json.Unmarshal(payload.value, &nar); err != nil {
		api.WriteError(w, acme.MalformedErr(errors.Wrap(err,
			"failed to unmarshal new-account request payload")))
		return
	}
	if err := nar.Validate(); err != nil {
		api.WriteError(w, err)
		return
	}

	httpStatus := http.StatusCreated
	acc, err := acme.AccountFromContext(r.Context())
	if err != nil {
		acmeErr, ok := err.(*acme.Error)
		if !ok || acmeErr.Status != http.StatusBadRequest {
			// Something went wrong ...
			api.WriteError(w, err)
			return
		}

		// Account does not exist //
		if nar.OnlyReturnExisting {
			api.WriteError(w, acme.AccountDoesNotExistErr(nil))
			return
		}
		jwk, err := acme.JwkFromContext(r.Context())
		if err != nil {
			api.WriteError(w, err)
			return
		}

		if acc, err = h.Auth.NewAccount(r.Context(), acme.AccountOptions{
			Key:     jwk,
			Contact: nar.Contact,
		}); err != nil {
			api.WriteError(w, err)
			return
		}
	} else {
		// Account exists //
		httpStatus = http.StatusOK
	}

	w.Header().Set("Location", h.Auth.GetLink(r.Context(), acme.AccountLink,
		true, acc.GetID()))
	api.JSONStatus(w, acc, httpStatus)
}

// GetUpdateAccount is the api for updating an ACME account.
func (h *Handler) GetUpdateAccount(w http.ResponseWriter, r *http.Request) {
	acc, err := acme.AccountFromContext(r.Context())
	if err != nil {
		api.WriteError(w, err)
		return
	}
	payload, err := payloadFromContext(r.Context())
	if err != nil {
		api.WriteError(w, err)
		return
	}

	// If PostAsGet just respond with the account, otherwise process like a
	// normal Post request.
	if !payload.isPostAsGet {
		var uar UpdateAccountRequest
		if err := json.Unmarshal(payload.value, &uar); err != nil {
			api.WriteError(w, acme.MalformedErr(errors.Wrap(err, "failed to unmarshal new-account request payload")))
			return
		}
		if err := uar.Validate(); err != nil {
			api.WriteError(w, err)
			return
		}
		var err error
		// If neither the status nor the contacts are being updated then ignore
		// the updates and return 200. This conforms with the behavior detailed
		// in the ACME spec (https://tools.ietf.org/html/rfc8555#section-7.3.2).
		if uar.IsDeactivateRequest() {
			acc, err = h.Auth.DeactivateAccount(r.Context(), acc.GetID())
		} else if len(uar.Contact) > 0 {
			acc, err = h.Auth.UpdateAccount(r.Context(), acc.GetID(), uar.Contact)
		}
		if err != nil {
			api.WriteError(w, err)
			return
		}
	}
	w.Header().Set("Location", h.Auth.GetLink(r.Context(), acme.AccountLink,
		true, acc.GetID()))
	api.JSON(w, acc)
}

func logOrdersByAccount(w http.ResponseWriter, oids []string) {
	if rl, ok := w.(logging.ResponseLogger); ok {
		m := map[string]interface{}{
			"orders": oids,
		}
		rl.WithFields(m)
	}
}

// GetOrdersByAccount ACME api for retrieving the list of order urls belonging to an account.
func (h *Handler) GetOrdersByAccount(w http.ResponseWriter, r *http.Request) {
	acc, err := acme.AccountFromContext(r.Context())
	if err != nil {
		api.WriteError(w, err)
		return
	}
	accID := chi.URLParam(r, "accID")
	if acc.ID != accID {
		api.WriteError(w, acme.UnauthorizedErr(errors.New("account ID does not match url param")))
		return
	}
	orders, err := h.Auth.GetOrdersByAccount(r.Context(), acc.GetID())
	if err != nil {
		api.WriteError(w, err)
		return
	}
	api.JSON(w, orders)
	logOrdersByAccount(w, orders)
}
