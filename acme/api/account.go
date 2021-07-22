package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/logging"

	squarejose "gopkg.in/square/go-jose.v2"
)

// NewAccountRequest represents the payload for a new account request.
type NewAccountRequest struct {
	Contact                []string    `json:"contact"`
	OnlyReturnExisting     bool        `json:"onlyReturnExisting"`
	TermsOfServiceAgreed   bool        `json:"termsOfServiceAgreed"`
	ExternalAccountBinding interface{} `json:"externalAccountBinding,omitempty"`
}

func validateContacts(cs []string) error {
	for _, c := range cs {
		if len(c) == 0 {
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
func (h *Handler) NewAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	payload, err := payloadFromContext(ctx)
	if err != nil {
		api.WriteError(w, err)
		return
	}
	var nar NewAccountRequest
	if err := json.Unmarshal(payload.value, &nar); err != nil {
		api.WriteError(w, acme.WrapError(acme.ErrorMalformedType, err,
			"failed to unmarshal new-account request payload"))
		return
	}
	if err := nar.Validate(); err != nil {
		api.WriteError(w, err)
		return
	}

	eak, err := h.validateExternalAccountBinding(ctx, &nar)
	if err != nil {
		api.WriteError(w, err)
		return
	}

	httpStatus := http.StatusCreated
	acc, err := accountFromContext(r.Context())
	if err != nil {
		acmeErr, ok := err.(*acme.Error)
		if !ok || acmeErr.Status != http.StatusBadRequest {
			// Something went wrong ...
			api.WriteError(w, err)
			return
		}

		// Account does not exist //
		if nar.OnlyReturnExisting {
			api.WriteError(w, acme.NewError(acme.ErrorAccountDoesNotExistType,
				"account does not exist"))
			return
		}
		jwk, err := jwkFromContext(ctx)
		if err != nil {
			api.WriteError(w, err)
			return
		}

		acc = &acme.Account{
			Key:     jwk,
			Contact: nar.Contact,
			Status:  acme.StatusValid,
		}
		if err := h.db.CreateAccount(ctx, acc); err != nil {
			api.WriteError(w, acme.WrapErrorISE(err, "error creating account"))
			return
		}
		if eak != nil { // means that we have a (valid) External Account Binding key that should be bound, updated and sent in the response
			eak.BindTo(acc)
			if err := h.db.UpdateExternalAccountKey(ctx, eak); err != nil {
				api.WriteError(w, acme.WrapErrorISE(err, "error updating external account binding key"))
				return
			}
			acc.ExternalAccountBinding = nar.ExternalAccountBinding
		}
	} else {
		// Account exists
		httpStatus = http.StatusOK
	}

	h.linker.LinkAccount(ctx, acc)

	w.Header().Set("Location", h.linker.GetLink(r.Context(), AccountLinkType, acc.ID))
	api.JSONStatus(w, acc, httpStatus)
}

// GetOrUpdateAccount is the api for updating an ACME account.
func (h *Handler) GetOrUpdateAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	acc, err := accountFromContext(ctx)
	if err != nil {
		api.WriteError(w, err)
		return
	}
	payload, err := payloadFromContext(ctx)
	if err != nil {
		api.WriteError(w, err)
		return
	}

	// If PostAsGet just respond with the account, otherwise process like a
	// normal Post request.
	if !payload.isPostAsGet {
		var uar UpdateAccountRequest
		if err := json.Unmarshal(payload.value, &uar); err != nil {
			api.WriteError(w, acme.WrapError(acme.ErrorMalformedType, err,
				"failed to unmarshal new-account request payload"))
			return
		}
		if err := uar.Validate(); err != nil {
			api.WriteError(w, err)
			return
		}
		if len(uar.Status) > 0 || len(uar.Contact) > 0 {
			if len(uar.Status) > 0 {
				acc.Status = uar.Status
			} else if len(uar.Contact) > 0 {
				acc.Contact = uar.Contact
			}

			if err := h.db.UpdateAccount(ctx, acc); err != nil {
				api.WriteError(w, acme.WrapErrorISE(err, "error updating account"))
				return
			}
		}
	}

	h.linker.LinkAccount(ctx, acc)

	w.Header().Set("Location", h.linker.GetLink(ctx, AccountLinkType, acc.ID))
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

// GetOrdersByAccountID ACME api for retrieving the list of order urls belonging to an account.
func (h *Handler) GetOrdersByAccountID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	acc, err := accountFromContext(ctx)
	if err != nil {
		api.WriteError(w, err)
		return
	}
	accID := chi.URLParam(r, "accID")
	if acc.ID != accID {
		api.WriteError(w, acme.NewError(acme.ErrorUnauthorizedType, "account ID '%s' does not match url param '%s'", acc.ID, accID))
		return
	}
	orders, err := h.db.GetOrdersByAccountID(ctx, acc.ID)
	if err != nil {
		api.WriteError(w, err)
		return
	}

	h.linker.LinkOrdersByAccountID(ctx, orders)

	api.JSON(w, orders)
	logOrdersByAccount(w, orders)
}

// validateExternalAccountBinding validates the externalAccountBinding property in a call to new-account
func (h *Handler) validateExternalAccountBinding(ctx context.Context, nar *NewAccountRequest) (*acme.ExternalAccountKey, error) {
	acmeProv, err := acmeProvisionerFromContext(ctx)
	if err != nil {
		return nil, acme.WrapErrorISE(err, "could not load ACME provisioner from context")
	}

	if !acmeProv.RequireEAB {
		return nil, nil
	}

	if nar.ExternalAccountBinding == nil {
		return nil, acme.NewError(acme.ErrorExternalAccountRequiredType, "no external account binding provided")
	}

	eabJSONBytes, err := json.Marshal(nar.ExternalAccountBinding)
	if err != nil {
		return nil, acme.WrapErrorISE(err, "error marshaling externalAccountBinding into JSON")
	}

	eabJWS, err := squarejose.ParseSigned(string(eabJSONBytes))
	if err != nil {
		return nil, acme.WrapErrorISE(err, "error parsing externalAccountBinding jws")
	}

	// TODO: verify supported algorithms against the incoming alg (and corresponding settings)?
	// TODO: implement strategy pattern to allow for different ways of verification (i.e. webhook call) based on configuration

	keyID := eabJWS.Signatures[0].Protected.KeyID
	externalAccountKey, err := h.db.GetExternalAccountKey(ctx, keyID)
	if err != nil {
		return nil, acme.WrapErrorISE(err, "error retrieving external account key")
	}

	if externalAccountKey.AlreadyBound() {
		return nil, acme.NewError(acme.ErrorUnauthorizedType, "external account binding key with id '%s' was already bound to account '%s' on %s", keyID, externalAccountKey.AccountID, externalAccountKey.BoundAt)
	}

	payload, err := eabJWS.Verify(externalAccountKey.KeyBytes)
	if err != nil {
		return nil, acme.WrapErrorISE(err, "error verifying externalAccountBinding signature")
	}

	jwk, err := jwkFromContext(ctx)
	if err != nil {
		return nil, err
	}

	var payloadJWK *squarejose.JSONWebKey
	err = json.Unmarshal(payload, &payloadJWK)
	if err != nil {
		return nil, acme.WrapError(acme.ErrorMalformedType, err, "error unmarshaling payload into jwk")
	}

	if !keysAreEqual(jwk, payloadJWK) {
		return nil, acme.NewError(acme.ErrorMalformedType, "keys in jws and eab payload do not match") // TODO: decide ACME error type to use
	}

	return externalAccountKey, nil
}

func keysAreEqual(x, y *squarejose.JSONWebKey) bool {
	if x == nil || y == nil {
		return false
	}
	digestX, errX := acme.KeyToID(x)
	digestY, errY := acme.KeyToID(y)
	if errX != nil || errY != nil {
		return false
	}
	return digestX == digestY
}
