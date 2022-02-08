package api

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/authority/provisioner"
	"go.step.sm/linkedca"
)

const (
	// provisionerContextKey provisioner key
	provisionerContextKey = ContextKey("provisioner")
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
func (h *Handler) requireEABEnabled(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		provName := chi.URLParam(r, "provisionerName")
		eabEnabled, prov, err := h.provisionerHasEABEnabled(ctx, provName)
		if err != nil {
			api.WriteError(w, err)
			return
		}
		if !eabEnabled {
			api.WriteError(w, admin.NewError(admin.ErrorBadRequestType, "ACME EAB not enabled for provisioner %s", prov.GetName()))
			return
		}
		ctx = context.WithValue(ctx, provisionerContextKey, prov)
		next(w, r.WithContext(ctx))
	}
}

// provisionerHasEABEnabled determines if the "requireEAB" setting for an ACME
// provisioner is set to true and thus has EAB enabled.
func (h *Handler) provisionerHasEABEnabled(ctx context.Context, provisionerName string) (bool, *linkedca.Provisioner, error) {
	var (
		p   provisioner.Interface
		err error
	)
	if p, err = h.auth.LoadProvisionerByName(provisionerName); err != nil {
		return false, nil, admin.WrapErrorISE(err, "error loading provisioner %s", provisionerName)
	}

	prov, err := h.adminDB.GetProvisioner(ctx, p.GetID())
	if err != nil {
		return false, nil, admin.WrapErrorISE(err, "error getting provisioner with ID: %s", p.GetID())
	}

	details := prov.GetDetails()
	if details == nil {
		return false, nil, admin.NewErrorISE("error getting details for provisioner with ID: %s", p.GetID())
	}

	acmeProvisioner := details.GetACME()
	if acmeProvisioner == nil {
		return false, nil, admin.NewErrorISE("error getting ACME details for provisioner with ID: %s", p.GetID())
	}

	return acmeProvisioner.GetRequireEab(), prov, nil
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
	api.WriteError(w, admin.NewError(admin.ErrorNotImplementedType, "this functionality is currently only available in Certificate Manager: https://smallstep.com/signup?product=cm"))
}

// CreateExternalAccountKey writes the response for the EAB key POST endpoint
func (h *ACMEAdminResponder) CreateExternalAccountKey(w http.ResponseWriter, r *http.Request) {
	api.WriteError(w, admin.NewError(admin.ErrorNotImplementedType, "this functionality is currently only available in Certificate Manager: https://smallstep.com/signup?product=cm"))
}

// DeleteExternalAccountKey writes the response for the EAB key DELETE endpoint
func (h *ACMEAdminResponder) DeleteExternalAccountKey(w http.ResponseWriter, r *http.Request) {
	api.WriteError(w, admin.NewError(admin.ErrorNotImplementedType, "this functionality is currently only available in Certificate Manager: https://smallstep.com/signup?product=cm"))
}
