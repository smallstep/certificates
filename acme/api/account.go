package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/logging"
)

// NewAccountRequest represents the payload for a new account request.
type NewAccountRequest struct {
	Contact                []string                `json:"contact"`
	OnlyReturnExisting     bool                    `json:"onlyReturnExisting"`
	TermsOfServiceAgreed   bool                    `json:"termsOfServiceAgreed"`
	ExternalAccountBinding *ExternalAccountBinding `json:"externalAccountBinding,omitempty"`
}

func validateContacts(cs []string) error {
	for _, c := range cs {
		if c == "" {
			return acme.NewError(acme.ErrorMalformedType, "contact cannot be empty string")
		}
	}
	return nil
}

// Validate validates a new-account request body.
func (n *NewAccountRequest) Validate() error {
	if n.OnlyReturnExisting && len(n.Contact) > 0 {
		return acme.NewError(acme.ErrorMalformedType, "incompatible input; onlyReturnExisting must be alone")
	}
	return validateContacts(n.Contact)
}

// UpdateAccountRequest represents an update-account request.
type UpdateAccountRequest struct {
	Contact []string    `json:"contact"`
	Status  acme.Status `json:"status"`
}

// Validate validates a update-account request body.
func (u *UpdateAccountRequest) Validate() error {
	switch {
	case len(u.Status) > 0 && len(u.Contact) > 0:
		return acme.NewError(acme.ErrorMalformedType, "incompatible input; contact and "+
			"status updates are mutually exclusive")
	case len(u.Contact) > 0:
		if err := validateContacts(u.Contact); err != nil {
			return err
		}
		return nil
	case len(u.Status) > 0:
		if u.Status != acme.StatusDeactivated {
			return acme.NewError(acme.ErrorMalformedType, "cannot update account "+
				"status to %s, only deactivated", u.Status)
		}
		return nil
	default:
		// According to the ACME spec (https://tools.ietf.org/html/rfc8555#section-7.3.2)
		// accountUpdate should ignore any fields not recognized by the server.
		return nil
	}
}

// NewAccount is the handler resource for creating new ACME accounts.
func NewAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	db := acme.MustDatabaseFromContext(ctx)
	linker := acme.MustLinkerFromContext(ctx)

	payload, err := payloadFromContext(ctx)
	if err != nil {
		render.Error(w, err)
		return
	}
	var nar NewAccountRequest
	if err := json.Unmarshal(payload.value, &nar); err != nil {
		render.Error(w, acme.WrapError(acme.ErrorMalformedType, err,
			"failed to unmarshal new-account request payload"))
		return
	}
	if err := nar.Validate(); err != nil {
		render.Error(w, err)
		return
	}

	prov, err := acmeProvisionerFromContext(ctx)
	if err != nil {
		render.Error(w, err)
		return
	}

	httpStatus := http.StatusCreated
	acc, err := accountFromContext(ctx)
	if err != nil {
		var acmeErr *acme.Error
		if !errors.As(err, &acmeErr) || acmeErr.Status != http.StatusBadRequest {
			// Something went wrong ...
			render.Error(w, err)
			return
		}

		// Account does not exist //
		if nar.OnlyReturnExisting {
			render.Error(w, acme.NewError(acme.ErrorAccountDoesNotExistType,
				"account does not exist"))
			return
		}

		jwk, err := jwkFromContext(ctx)
		if err != nil {
			render.Error(w, err)
			return
		}

		eak, err := validateExternalAccountBinding(ctx, &nar)
		if err != nil {
			render.Error(w, err)
			return
		}

		acc = &acme.Account{
			Key:     jwk,
			Contact: nar.Contact,
			Status:  acme.StatusValid,
		}
		if err := db.CreateAccount(ctx, acc); err != nil {
			render.Error(w, acme.WrapErrorISE(err, "error creating account"))
			return
		}

		if eak != nil { // means that we have a (valid) External Account Binding key that should be bound, updated and sent in the response
			if err := eak.BindTo(acc); err != nil {
				render.Error(w, err)
				return
			}
			if err := db.UpdateExternalAccountKey(ctx, prov.ID, eak); err != nil {
				render.Error(w, acme.WrapErrorISE(err, "error updating external account binding key"))
				return
			}
			acc.ExternalAccountBinding = nar.ExternalAccountBinding
		}
	} else {
		// Account exists
		httpStatus = http.StatusOK
	}

	linker.LinkAccount(ctx, acc)

	w.Header().Set("Location", linker.GetLink(r.Context(), acme.AccountLinkType, acc.ID))
	render.JSONStatus(w, acc, httpStatus)
}

// GetOrUpdateAccount is the api for updating an ACME account.
func GetOrUpdateAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	db := acme.MustDatabaseFromContext(ctx)
	linker := acme.MustLinkerFromContext(ctx)

	acc, err := accountFromContext(ctx)
	if err != nil {
		render.Error(w, err)
		return
	}
	payload, err := payloadFromContext(ctx)
	if err != nil {
		render.Error(w, err)
		return
	}

	// If PostAsGet just respond with the account, otherwise process like a
	// normal Post request.
	if !payload.isPostAsGet {
		var uar UpdateAccountRequest
		if err := json.Unmarshal(payload.value, &uar); err != nil {
			render.Error(w, acme.WrapError(acme.ErrorMalformedType, err,
				"failed to unmarshal new-account request payload"))
			return
		}
		if err := uar.Validate(); err != nil {
			render.Error(w, err)
			return
		}
		if len(uar.Status) > 0 || len(uar.Contact) > 0 {
			if len(uar.Status) > 0 {
				acc.Status = uar.Status
			} else if len(uar.Contact) > 0 {
				acc.Contact = uar.Contact
			}

			if err := db.UpdateAccount(ctx, acc); err != nil {
				render.Error(w, acme.WrapErrorISE(err, "error updating account"))
				return
			}
		}
	}

	linker.LinkAccount(ctx, acc)

	w.Header().Set("Location", linker.GetLink(ctx, acme.AccountLinkType, acc.ID))
	render.JSON(w, acc)
}

func logOrdersByAccount(w http.ResponseWriter, oids []string) {
	if rl, ok := w.(logging.ResponseLogger); ok {
		m := map[string]interface{}{
			"orders": oids,
		}
		rl.WithFields(m)
	}
}

// GetOrdersByAccountID ACME api for retrieving the list of order urls belonging to an account.
func GetOrdersByAccountID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	db := acme.MustDatabaseFromContext(ctx)
	linker := acme.MustLinkerFromContext(ctx)

	acc, err := accountFromContext(ctx)
	if err != nil {
		render.Error(w, err)
		return
	}
	accID := chi.URLParam(r, "accID")
	if acc.ID != accID {
		render.Error(w, acme.NewError(acme.ErrorUnauthorizedType, "account ID '%s' does not match url param '%s'", acc.ID, accID))
		return
	}

	orders, err := db.GetOrdersByAccountID(ctx, acc.ID)
	if err != nil {
		render.Error(w, err)
		return
	}

	linker.LinkOrdersByAccountID(ctx, orders)

	render.JSON(w, orders)
	logOrdersByAccount(w, orders)
}
