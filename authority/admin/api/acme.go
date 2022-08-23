package api

import (
	"fmt"
	"net/http"

	"go.step.sm/linkedca"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/smallstep/certificates/acme"
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
func requireEABEnabled(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		prov := linkedca.MustProvisionerFromContext(ctx)

		acmeProvisioner := prov.GetDetails().GetACME()
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

// ACMEAdminResponder is responsible for writing ACME admin responses
type ACMEAdminResponder interface {
	GetExternalAccountKeys(w http.ResponseWriter, r *http.Request)
	CreateExternalAccountKey(w http.ResponseWriter, r *http.Request)
	DeleteExternalAccountKey(w http.ResponseWriter, r *http.Request)
}

// acmeAdminResponder implements ACMEAdminResponder.
type acmeAdminResponder struct{}

// NewACMEAdminResponder returns a new ACMEAdminResponder
func NewACMEAdminResponder() ACMEAdminResponder {
	return &acmeAdminResponder{}
}

// GetExternalAccountKeys writes the response for the EAB keys GET endpoint
func (h *acmeAdminResponder) GetExternalAccountKeys(w http.ResponseWriter, r *http.Request) {
	render.Error(w, admin.NewError(admin.ErrorNotImplementedType, "this functionality is currently only available in Certificate Manager: https://u.step.sm/cm"))
}

// CreateExternalAccountKey writes the response for the EAB key POST endpoint
func (h *acmeAdminResponder) CreateExternalAccountKey(w http.ResponseWriter, r *http.Request) {
	render.Error(w, admin.NewError(admin.ErrorNotImplementedType, "this functionality is currently only available in Certificate Manager: https://u.step.sm/cm"))
}

// DeleteExternalAccountKey writes the response for the EAB key DELETE endpoint
func (h *acmeAdminResponder) DeleteExternalAccountKey(w http.ResponseWriter, r *http.Request) {
	render.Error(w, admin.NewError(admin.ErrorNotImplementedType, "this functionality is currently only available in Certificate Manager: https://u.step.sm/cm"))
}

func eakToLinked(k *acme.ExternalAccountKey) *linkedca.EABKey {
	if k == nil {
		return nil
	}

	eak := &linkedca.EABKey{
		Id:          k.ID,
		HmacKey:     k.HmacKey,
		Provisioner: k.ProvisionerID,
		Reference:   k.Reference,
		Account:     k.AccountID,
		CreatedAt:   timestamppb.New(k.CreatedAt),
		BoundAt:     timestamppb.New(k.BoundAt),
	}

	if k.Policy != nil {
		eak.Policy = &linkedca.Policy{
			X509: &linkedca.X509Policy{
				Allow: &linkedca.X509Names{},
				Deny:  &linkedca.X509Names{},
			},
		}
		eak.Policy.X509.Allow.Dns = k.Policy.X509.Allowed.DNSNames
		eak.Policy.X509.Allow.Ips = k.Policy.X509.Allowed.IPRanges
		eak.Policy.X509.Deny.Dns = k.Policy.X509.Denied.DNSNames
		eak.Policy.X509.Deny.Ips = k.Policy.X509.Denied.IPRanges
		eak.Policy.X509.AllowWildcardNames = k.Policy.X509.AllowWildcardNames
	}

	return eak
}

func linkedEAKToCertificates(k *linkedca.EABKey) *acme.ExternalAccountKey {
	if k == nil {
		return nil
	}

	eak := &acme.ExternalAccountKey{
		ID:            k.Id,
		ProvisionerID: k.Provisioner,
		Reference:     k.Reference,
		AccountID:     k.Account,
		HmacKey:       k.HmacKey,
		CreatedAt:     k.CreatedAt.AsTime(),
		BoundAt:       k.BoundAt.AsTime(),
	}

	if policy := k.GetPolicy(); policy != nil {
		eak.Policy = &acme.Policy{}
		if x509 := policy.GetX509(); x509 != nil {
			eak.Policy.X509 = acme.X509Policy{}
			if allow := x509.GetAllow(); allow != nil {
				eak.Policy.X509.Allowed = acme.PolicyNames{}
				eak.Policy.X509.Allowed.DNSNames = allow.Dns
				eak.Policy.X509.Allowed.IPRanges = allow.Ips
			}
			if deny := x509.GetDeny(); deny != nil {
				eak.Policy.X509.Denied = acme.PolicyNames{}
				eak.Policy.X509.Denied.DNSNames = deny.Dns
				eak.Policy.X509.Denied.IPRanges = deny.Ips
			}
			eak.Policy.X509.AllowWildcardNames = x509.AllowWildcardNames
		}
	}

	return eak
}
