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
		return acme.MalformedErr(errors.Errorf("empty update request"))
	}
}

// NewAccount is the handler resource for creating new ACME accounts.
func (h *Handler) NewAccount(w http.ResponseWriter, r *http.Request) {
	prov, err := provisionerFromContext(r)
	if err != nil {
		api.WriteError(w, err)
		return
	}
	payload, err := payloadFromContext(r)
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
	acc, err := accountFromContext(r)
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
		jwk, err := jwkFromContext(r)
		if err != nil {
			api.WriteError(w, err)
			return
		}

		if acc, err = h.Auth.NewAccount(prov, acme.AccountOptions{
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

	w.Header().Set("Location", h.Auth.GetLink(acme.AccountLink,
		acme.URLSafeProvisionerName(prov), true, acc.GetID()))
	api.JSONStatus(w, acc, httpStatus)
}

// GetUpdateAccount is the api for updating an ACME account.
func (h *Handler) GetUpdateAccount(w http.ResponseWriter, r *http.Request) {
	prov, err := provisionerFromContext(r)
	if err != nil {
		api.WriteError(w, err)
		return
	}
	acc, err := accountFromContext(r)
	if err != nil {
		api.WriteError(w, err)
		return
	}
	payload, err := payloadFromContext(r)
	if err != nil {
		api.WriteError(w, err)
		return
	}

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
		if uar.IsDeactivateRequest() {
			acc, err = h.Auth.DeactivateAccount(prov, acc.GetID())
		} else {
			acc, err = h.Auth.UpdateAccount(prov, acc.GetID(), uar.Contact)
		}
		if err != nil {
			api.WriteError(w, err)
			return
		}
	}
	w.Header().Set("Location", h.Auth.GetLink(acme.AccountLink, acme.URLSafeProvisionerName(prov), true, acc.GetID()))
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
	prov, err := provisionerFromContext(r)
	if err != nil {
		api.WriteError(w, err)
		return
	}
	acc, err := accountFromContext(r)
	if err != nil {
		api.WriteError(w, err)
		return
	}

	accID := chi.URLParam(r, "accID")
	if acc.ID != accID {
		api.WriteError(w, acme.UnauthorizedErr(errors.New("account ID does not match url param")))
		return
	}
	orders, err := h.Auth.GetOrdersByAccount(prov, acc.GetID())
	if err != nil {
		api.WriteError(w, err)
		return
	}
	api.JSON(w, orders)
	logOrdersByAccount(w, orders)
}
