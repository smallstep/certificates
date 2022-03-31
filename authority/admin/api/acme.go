package api

import (
	"fmt"
	"net/http"

	"go.step.sm/linkedca"

	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority/admin"
)

// CreateExternalAccountKeyRequest is the type for POST /admin/acme/eab requests
type CreateExternalAccountKeyRequest struct {
	Reference string `json:"reference"`
}

// Validate validates a new ACME EAB Key request body.
func (r *CreateExternalAccountKeyRequest) Validate() error {
	if len(r.Reference) > 256 { // an arbitrary, but sensible (IMO), limit
		return fmt.Errorf("reference length %d exceeds the maximum (256)", len(r.Reference))
	}
	return nil
}

// GetExternalAccountKeysResponse is the type for GET /admin/acme/eab responses
type GetExternalAccountKeysResponse struct {
	EAKs       []*linkedca.EABKey `json:"eaks"`
	NextCursor string             `json:"nextCursor"`
}

// requireEABEnabled is a middleware that ensures ACME EAB is enabled
// before serving requests that act on ACME EAB credentials.
func (h *Handler) requireEABEnabled(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		prov := linkedca.ProvisionerFromContext(ctx)

		details := prov.GetDetails()
		if details == nil {
			render.Error(w, admin.NewErrorISE("error getting details for provisioner '%s'", prov.GetName()))
			return
		}

		acmeProvisioner := details.GetACME()
		if acmeProvisioner == nil {
			render.Error(w, admin.NewErrorISE("error getting ACME details for provisioner '%s'", prov.GetName()))
			return
		}

		if !acmeProvisioner.RequireEab {
			render.Error(w, admin.NewError(admin.ErrorBadRequestType, "ACME EAB not enabled for provisioner '%s'", prov.GetName()))
			return
		}

		next(w, r)
	}
}

type acmeAdminResponderInterface interface {
	GetExternalAccountKeys(w http.ResponseWriter, r *http.Request)
	CreateExternalAccountKey(w http.ResponseWriter, r *http.Request)
	DeleteExternalAccountKey(w http.ResponseWriter, r *http.Request)
}

// ACMEAdminResponder is responsible for writing ACME admin responses
type ACMEAdminResponder struct{}

// NewACMEAdminResponder returns a new ACMEAdminResponder
func NewACMEAdminResponder() *ACMEAdminResponder {
	return &ACMEAdminResponder{}
}

// GetExternalAccountKeys writes the response for the EAB keys GET endpoint
func (h *ACMEAdminResponder) GetExternalAccountKeys(w http.ResponseWriter, r *http.Request) {
	render.Error(w, admin.NewError(admin.ErrorNotImplementedType, "this functionality is currently only available in Certificate Manager: https://u.step.sm/cm"))
}

// CreateExternalAccountKey writes the response for the EAB key POST endpoint
func (h *ACMEAdminResponder) CreateExternalAccountKey(w http.ResponseWriter, r *http.Request) {
	render.Error(w, admin.NewError(admin.ErrorNotImplementedType, "this functionality is currently only available in Certificate Manager: https://u.step.sm/cm"))
}

// DeleteExternalAccountKey writes the response for the EAB key DELETE endpoint
func (h *ACMEAdminResponder) DeleteExternalAccountKey(w http.ResponseWriter, r *http.Request) {
	render.Error(w, admin.NewError(admin.ErrorNotImplementedType, "this functionality is currently only available in Certificate Manager: https://u.step.sm/cm"))
}
