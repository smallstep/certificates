package api

import (
	"net/http"

	"github.com/go-chi/chi"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/admin"
	"go.step.sm/linkedca"
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
	if err := api.ReadJSON(r.Body, &body); err != nil { // TODO: rewrite into protobuf json (likely)
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
	// cursor, limit, err := api.ParseCursor(r)
	// if err != nil {
	// 	api.WriteError(w, admin.WrapError(admin.ErrorBadRequestType, err,
	// 		"error parsing cursor and limit from query params"))
	// 	return
	// }

	// eaks, nextCursor, err := h.acmeDB.GetExternalAccountKeys(cursor, limit)
	// if err != nil {
	// 	api.WriteError(w, admin.WrapErrorISE(err, "error retrieving paginated admins"))
	// 	return
	// }
	// api.JSON(w, &GetExternalAccountKeysResponse{
	// 	EAKs:       eaks,
	// 	NextCursor: nextCursor,
	// })
}
