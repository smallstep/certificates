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
	Provisioner string `json:"provisioner"`
	Reference   string `json:"reference"`
}

// Validate validates a new ACME EAB Key request body.
func (r *CreateExternalAccountKeyRequest) Validate() error {
	if r.Provisioner == "" {
		return admin.NewError(admin.ErrorBadRequestType, "provisioner name cannot be empty")
	}
	return nil
}

// GetExternalAccountKeysResponse is the type for GET /admin/acme/eab responses
type GetExternalAccountKeysResponse struct {
	EAKs       []*linkedca.EABKey `json:"eaks"`
	NextCursor string             `json:"nextCursor"`
}

// provisionerHasEABEnabled determines if the "requireEAB" setting for an ACME
// provisioner is set to true and thus has EAB enabled.
// TODO: rewrite this into a middleware for the ACME handlers? This probably requires
// ensuring that all the ACME EAB APIs that need the middleware work the same in terms
// of specifying the provisioner; probably a bit of refactoring required.
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

	acme := details.GetACME()
	if acme == nil {
		return false, admin.NewErrorISE("error getting ACME details for provisioner with ID: %s", p.GetID())
	}

	return acme.GetRequireEab(), nil
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

	provisioner := body.Provisioner
	reference := body.Reference

	eabEnabled, err := h.provisionerHasEABEnabled(r.Context(), provisioner)
	if err != nil {
		api.WriteError(w, err)
		return
	}

	if !eabEnabled {
		api.WriteError(w, admin.NewError(admin.ErrorBadRequestType, "ACME EAB not enabled for provisioner %s", provisioner))
		return
	}

	if reference != "" {
		k, err := h.acmeDB.GetExternalAccountKeyByReference(r.Context(), provisioner, reference)
		if err == nil || k != nil {
			err := admin.NewError(admin.ErrorBadRequestType, "an ACME EAB key for provisioner %s with reference %s already exists", provisioner, reference)
			err.Status = 409
			api.WriteError(w, err)
			return
		}
	}

	eak, err := h.acmeDB.CreateExternalAccountKey(r.Context(), provisioner, reference)
	if err != nil {
		api.WriteError(w, admin.WrapErrorISE(err, "error creating ACME EAB key for provisioner %s and reference %s", provisioner, reference))
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
	id := chi.URLParam(r, "id")

	// TODO: add provisioner as parameter, so that check can be performed if EAB is enabled or not

	if err := h.acmeDB.DeleteExternalAccountKey(r.Context(), id); err != nil {
		api.WriteError(w, admin.WrapErrorISE(err, "error deleting ACME EAB Key %s", id))
		return
	}

	api.JSON(w, &DeleteResponse{Status: "ok"})
}

// GetExternalAccountKeys returns a segment of ACME EAB Keys.
func (h *Handler) GetExternalAccountKeys(w http.ResponseWriter, r *http.Request) {
	prov := chi.URLParam(r, "prov")
	reference := chi.URLParam(r, "ref")

	eabEnabled, err := h.provisionerHasEABEnabled(r.Context(), prov)
	if err != nil {
		api.WriteError(w, err)
		return
	}

	if !eabEnabled {
		api.WriteError(w, admin.NewError(admin.ErrorBadRequestType, "ACME EAB not enabled for provisioner %s", prov))
		return
	}

	// TODO: support paging properly? It'll probably leak to the DB layer, as we have to loop through all keys
	// cursor, limit, err := api.ParseCursor(r)
	// if err != nil {
	// 	api.WriteError(w, admin.WrapError(admin.ErrorBadRequestType, err,
	// 		"error parsing cursor and limit from query params"))
	// 	return
	// }

	var (
		key  *acme.ExternalAccountKey
		keys []*acme.ExternalAccountKey
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
