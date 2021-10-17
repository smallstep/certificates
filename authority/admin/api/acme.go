package api

import (
	"context"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/authority/provisioner"
	"go.step.sm/linkedca"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// CreateExternalAccountKeyRequest is the type for POST /admin/acme/eab requests
type CreateExternalAccountKeyRequest struct {
	Reference string `json:"reference"`
}

// Validate validates a new ACME EAB Key request body.
func (r *CreateExternalAccountKeyRequest) Validate() error {
	return nil
}

// GetExternalAccountKeysResponse is the type for GET /admin/acme/eab responses
type GetExternalAccountKeysResponse struct {
	EAKs       []*linkedca.EABKey `json:"eaks"`
	NextCursor string             `json:"nextCursor"`
}

// requireEABEnabled is a middleware that ensures ACME EAB is enabled
// before serving requests that act on ACME EAB credentials.
func (h *Handler) requireEABEnabled(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		prov := chi.URLParam(r, "prov")
		eabEnabled, err := h.provisionerHasEABEnabled(r.Context(), prov)
		if err != nil {
			api.WriteError(w, err)
			return
		}
		if !eabEnabled {
			api.WriteError(w, admin.NewError(admin.ErrorBadRequestType, "ACME EAB not enabled for provisioner %s", prov))
			return
		}
		next(w, r)
	}
}

// provisionerHasEABEnabled determines if the "requireEAB" setting for an ACME
// provisioner is set to true and thus has EAB enabled.
func (h *Handler) provisionerHasEABEnabled(ctx context.Context, provisionerName string) (bool, error) {
	var (
		p   provisioner.Interface
		err error
	)
	if p, err = h.auth.LoadProvisionerByName(provisionerName); err != nil {
		return false, admin.WrapErrorISE(err, "error loading provisioner %s", provisionerName)
	}

	prov, err := h.db.GetProvisioner(ctx, p.GetID())
	if err != nil {
		return false, admin.WrapErrorISE(err, "error getting provisioner with ID: %s", p.GetID())
	}

	details := prov.GetDetails()
	if details == nil {
		return false, admin.NewErrorISE("error getting details for provisioner with ID: %s", p.GetID())
	}

	acmeProvisioner := details.GetACME()
	if acmeProvisioner == nil {
		return false, admin.NewErrorISE("error getting ACME details for provisioner with ID: %s", p.GetID())
	}

	return acmeProvisioner.GetRequireEab(), nil
}

// CreateExternalAccountKey creates a new External Account Binding key
func (h *Handler) CreateExternalAccountKey(w http.ResponseWriter, r *http.Request) {
	var body CreateExternalAccountKeyRequest
	if err := api.ReadJSON(r.Body, &body); err != nil {
		api.WriteError(w, admin.WrapError(admin.ErrorBadRequestType, err, "error reading request body"))
		return
	}

	if err := body.Validate(); err != nil {
		api.WriteError(w, err)
		return
	}

	prov := chi.URLParam(r, "prov")
	reference := body.Reference

	// check if a key with the reference does not exist (only when a reference was in the request)
	if reference != "" {
		k, err := h.acmeDB.GetExternalAccountKeyByReference(r.Context(), prov, reference)
		// retrieving an EAB key from DB results in an error if it doesn't exist, which is what we're looking for,
		// but other errors can also happen. Return early if that happens; continuing if it was acme.ErrNotFound.
		shouldWriteError := err != nil && acme.ErrNotFound != err
		if shouldWriteError {
			api.WriteError(w, err)
			return
		}
		// if a key was found, return HTTP 409 conflict
		if k != nil {
			err := admin.NewError(admin.ErrorBadRequestType, "an ACME EAB key for provisioner %s with reference %s already exists", prov, reference)
			err.Status = 409
			api.WriteError(w, err)
			return
		}
		// continue execution if no key was found for the reference
	}

	eak, err := h.acmeDB.CreateExternalAccountKey(r.Context(), prov, reference)
	if err != nil {
		api.WriteError(w, admin.WrapErrorISE(err, "error creating ACME EAB key for provisioner %s and reference %s", prov, reference))
		return
	}

	response := &linkedca.EABKey{
		Id:          eak.ID,
		HmacKey:     eak.KeyBytes,
		Provisioner: eak.Provisioner,
		Reference:   eak.Reference,
	}

	api.ProtoJSONStatus(w, response, http.StatusCreated)
}

// DeleteExternalAccountKey deletes an ACME External Account Key.
func (h *Handler) DeleteExternalAccountKey(w http.ResponseWriter, r *http.Request) {
	prov := chi.URLParam(r, "prov")
	keyID := chi.URLParam(r, "id")

	if err := h.acmeDB.DeleteExternalAccountKey(r.Context(), prov, keyID); err != nil {
		api.WriteError(w, admin.WrapErrorISE(err, "error deleting ACME EAB Key %s", keyID))
		return
	}

	api.JSON(w, &DeleteResponse{Status: "ok"})
}

// GetExternalAccountKeys returns a segment of ACME EAB Keys.
func (h *Handler) GetExternalAccountKeys(w http.ResponseWriter, r *http.Request) {
	prov := chi.URLParam(r, "prov")
	reference := chi.URLParam(r, "ref")

	// TODO: support paging? It'll probably leak to the DB layer, as we have to loop through all keys

	var (
		key  *acme.ExternalAccountKey
		keys []*acme.ExternalAccountKey
		err  error
	)
	if reference != "" {
		key, err = h.acmeDB.GetExternalAccountKeyByReference(r.Context(), prov, reference)
		if err != nil {
			api.WriteError(w, admin.WrapErrorISE(err, "error getting external account key with reference %s", reference))
			return
		}
		keys = []*acme.ExternalAccountKey{key}
	} else {
		keys, err = h.acmeDB.GetExternalAccountKeys(r.Context(), prov)
		if err != nil {
			api.WriteError(w, admin.WrapErrorISE(err, "error getting external account keys"))
			return
		}
	}

	eaks := make([]*linkedca.EABKey, len(keys))
	for i, k := range keys {
		eaks[i] = &linkedca.EABKey{
			Id:          k.ID,
			HmacKey:     []byte{},
			Provisioner: k.Provisioner,
			Reference:   k.Reference,
			Account:     k.AccountID,
			CreatedAt:   timestamppb.New(k.CreatedAt),
			BoundAt:     timestamppb.New(k.BoundAt),
		}
	}

	nextCursor := ""
	api.JSON(w, &GetExternalAccountKeysResponse{
		EAKs:       eaks,
		NextCursor: nextCursor,
	})
}
