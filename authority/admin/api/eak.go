package api

import (
	"net/http"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/admin"
)

// CreateExternalAccountKeyRequest is the type for POST /admin/eak requests
type CreateExternalAccountKeyRequest struct {
	Name string `json:"name"`
}

// CreateExternalAccountKeyResponse is the type for POST /admin/eak responses
type CreateExternalAccountKeyResponse struct {
	KeyID string `json:"keyID"`
	Name  string `json:"name"`
	Key   []byte `json:"key"`
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
