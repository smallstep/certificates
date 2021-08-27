package api

import (
	"net/http"

	"github.com/go-chi/chi"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/admin"
	"go.step.sm/linkedca"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// CreateExternalAccountKeyRequest is the type for POST /admin/acme/eab requests
type CreateExternalAccountKeyRequest struct {
	ProvisionerName string `json:"provisioner"`
	Name            string `json:"name"`
}

// Validate validates a new-admin request body.
func (r *CreateExternalAccountKeyRequest) Validate() error {
	if r.ProvisionerName == "" {
		return admin.NewError(admin.ErrorBadRequestType, "provisioner name cannot be empty")
	}
	if r.Name == "" {
		return admin.NewError(admin.ErrorBadRequestType, "name / reference cannot be empty")
	}
	return nil
}

// GetExternalAccountKeysResponse is the type for GET /admin/acme/eab responses
type GetExternalAccountKeysResponse struct {
	EAKs       []*linkedca.EABKey `json:"eaks"`
	NextCursor string             `json:"nextCursor"`
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

	eak, err := h.acmeDB.CreateExternalAccountKey(r.Context(), body.ProvisionerName, body.Name)
	if err != nil {
		api.WriteError(w, admin.WrapErrorISE(err, "error creating external account key %s", body.Name))
		return
	}

	response := &linkedca.EABKey{
		EabKid:          eak.ID,
		EabHmacKey:      eak.KeyBytes,
		ProvisionerName: eak.ProvisionerName,
		Name:            eak.Name,
	}

	api.ProtoJSONStatus(w, response, http.StatusCreated)
}

// DeleteExternalAccountKey deletes an ACME External Account Key.
func (h *Handler) DeleteExternalAccountKey(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if err := h.acmeDB.DeleteExternalAccountKey(r.Context(), id); err != nil {
		api.WriteError(w, admin.WrapErrorISE(err, "error deleting ACME EAB Key %s", id))
		return
	}

	api.JSON(w, &DeleteResponse{Status: "ok"})
}

// GetExternalAccountKeys returns a segment of ACME EAB Keys.
func (h *Handler) GetExternalAccountKeys(w http.ResponseWriter, r *http.Request) {
	prov := chi.URLParam(r, "prov")

	// TODO: support paging properly? It'll probably leak to the DB layer, as we have to loop through all keys
	// cursor, limit, err := api.ParseCursor(r)
	// if err != nil {
	// 	api.WriteError(w, admin.WrapError(admin.ErrorBadRequestType, err,
	// 		"error parsing cursor and limit from query params"))
	// 	return
	// }

	keys, err := h.acmeDB.GetExternalAccountKeys(r.Context(), prov)
	if err != nil {
		api.WriteError(w, admin.WrapErrorISE(err, "error getting external account keys"))
		return
	}

	eaks := make([]*linkedca.EABKey, len(keys))
	for i, k := range keys {
		eaks[i] = &linkedca.EABKey{
			EabKid:          k.ID,
			EabHmacKey:      []byte{},
			ProvisionerName: k.ProvisionerName,
			Name:            k.Name,
			Account:         k.AccountID,
			CreatedAt:       timestamppb.New(k.CreatedAt),
			BoundAt:         timestamppb.New(k.BoundAt),
		}
	}

	nextCursor := ""
	api.JSON(w, &GetExternalAccountKeysResponse{
		EAKs:       eaks,
		NextCursor: nextCursor,
	})
}
