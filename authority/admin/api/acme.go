package api

import (
	"net/http"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/admin"
)

// CreateExternalAccountKeyRequest is the type for POST /admin/acme/eab requests
type CreateExternalAccountKeyRequest struct {
	Name string `json:"name"`
}

// CreateExternalAccountKeyResponse is the type for POST /admin/acme/eab responses
type CreateExternalAccountKeyResponse struct {
	KeyID string `json:"keyID"`
	Name  string `json:"name"`
	Key   []byte `json:"key"`
}

// GetExternalAccountKeysResponse is the type for GET /admin/acme/eab responses
type GetExternalAccountKeysResponse struct {
	EAKs       []*CreateExternalAccountKeyResponse `json:"eaks"`
	NextCursor string                              `json:"nextCursor"`
}

// CreateExternalAccountKey creates a new External Account Binding key
func (h *Handler) CreateExternalAccountKey(w http.ResponseWriter, r *http.Request) {
	var body CreateExternalAccountKeyRequest
	if err := api.ReadJSON(r.Body, &body); err != nil { // TODO: rewrite into protobuf json (likely)
		api.WriteError(w, err)
		return
	}

	// TODO: Validate input

	eak, err := h.acmeDB.CreateExternalAccountKey(r.Context(), body.Name)
	if err != nil {
		api.WriteError(w, admin.WrapErrorISE(err, "error creating external account key %s", body.Name))
		return
	}

	eakResponse := CreateExternalAccountKeyResponse{
		KeyID: eak.ID,
		Name:  eak.Name,
		Key:   eak.KeyBytes,
	}

	api.JSONStatus(w, eakResponse, http.StatusCreated) // TODO: rewrite into protobuf json (likely)
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
