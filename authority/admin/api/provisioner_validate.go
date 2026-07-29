package api

import (
	"encoding/json"
	"net/url"

	"github.com/smallstep/linkedca"
	"go.step.sm/crypto/jose"

	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/authority/provisioner"
)

// detailsType returns the provisioner type implied by the populated details
// oneof arm. ok is false for arms unknown to this package, in which case no
// type/details matching is enforced.
func detailsType(data any) (linkedca.Provisioner_Type, bool) {
	switch data.(type) {
	case *linkedca.ProvisionerDetails_JWK:
		return linkedca.Provisioner_JWK, true
	case *linkedca.ProvisionerDetails_OIDC:
		return linkedca.Provisioner_OIDC, true
	case *linkedca.ProvisionerDetails_GCP:
		return linkedca.Provisioner_GCP, true
	case *linkedca.ProvisionerDetails_AWS:
		return linkedca.Provisioner_AWS, true
	case *linkedca.ProvisionerDetails_Azure:
		return linkedca.Provisioner_AZURE, true
	case *linkedca.ProvisionerDetails_ACME:
		return linkedca.Provisioner_ACME, true
	case *linkedca.ProvisionerDetails_X5C:
		return linkedca.Provisioner_X5C, true
	case *linkedca.ProvisionerDetails_K8SSA:
		return linkedca.Provisioner_K8SSA, true
	case *linkedca.ProvisionerDetails_SSHPOP:
		return linkedca.Provisioner_SSHPOP, true
	case *linkedca.ProvisionerDetails_SCEP:
		return linkedca.Provisioner_SCEP, true
	case *linkedca.ProvisionerDetails_Nebula:
		return linkedca.Provisioner_NEBULA, true
	default:
		return linkedca.Provisioner_NOOP, false
	}
}

// anyNonEmpty reports whether at least one entry in bs has content.
func anyNonEmpty(bs [][]byte) bool {
	for _, b := range bs {
		if len(b) > 0 {
			return true
		}
	}
	return false
}

// validateProvisioner validates a provisioner sent to the create or update
// endpoints before it is stored. It enforces that the details oneof matches
// the declared type and that per-type required fields are present and
// parseable, returning structured bad-request errors instead of the internal
// errors the downstream translation layer would produce. Deeper semantic
// validation remains in provisioner.Interface.Init.
func validateProvisioner(p *linkedca.Provisioner) error {
	if p.GetName() == "" {
		return admin.NewError(admin.ErrorBadRequestType, "provisioner name is required")
	}
	if p.GetType() == linkedca.Provisioner_NOOP {
		return admin.NewError(admin.ErrorBadRequestType, "provisioner type is required")
	}
	data := p.GetDetails().GetData()
	if data == nil {
		return admin.NewError(admin.ErrorBadRequestType, "provisioner details are required")
	}
	if typ, ok := detailsType(data); ok && typ != p.GetType() {
		return admin.NewError(admin.ErrorBadRequestType,
			"provisioner details (%s) do not match provisioner type (%s)", typ, p.GetType())
	}

	switch d := data.(type) {
	case *linkedca.ProvisionerDetails_JWK:
		if len(d.JWK.GetPublicKey()) == 0 {
			return admin.NewError(admin.ErrorBadRequestType, "jwk.publicKey is required")
		}
		var key jose.JSONWebKey
		if err := json.Unmarshal(d.JWK.GetPublicKey(), &key); err != nil {
			return admin.NewError(admin.ErrorBadRequestType, "jwk.publicKey is not a valid JWK")
		}
	case *linkedca.ProvisionerDetails_OIDC:
		switch {
		case d.OIDC.GetClientId() == "":
			return admin.NewError(admin.ErrorBadRequestType, "oidc.clientId is required")
		case d.OIDC.GetConfigurationEndpoint() == "":
			return admin.NewError(admin.ErrorBadRequestType, "oidc.configurationEndpoint is required")
		}
		if _, err := url.Parse(d.OIDC.GetConfigurationEndpoint()); err != nil {
			return admin.NewError(admin.ErrorBadRequestType, "oidc.configurationEndpoint is not a valid URL")
		}
	case *linkedca.ProvisionerDetails_AWS:
		if age := d.AWS.GetInstanceAge(); age != "" {
			if _, err := provisioner.NewDuration(age); err != nil {
				return admin.NewError(admin.ErrorBadRequestType, "aws.instanceAge is invalid")
			}
		}
	case *linkedca.ProvisionerDetails_GCP:
		if age := d.GCP.GetInstanceAge(); age != "" {
			if _, err := provisioner.NewDuration(age); err != nil {
				return admin.NewError(admin.ErrorBadRequestType, "gcp.instanceAge is invalid")
			}
		}
	case *linkedca.ProvisionerDetails_Azure:
		if d.Azure.GetTenantId() == "" {
			return admin.NewError(admin.ErrorBadRequestType, "azure.tenantId is required")
		}
	case *linkedca.ProvisionerDetails_X5C:
		if !anyNonEmpty(d.X5C.GetRoots()) {
			return admin.NewError(admin.ErrorBadRequestType, "x5c.roots is required")
		}
	case *linkedca.ProvisionerDetails_K8SSA:
		if !anyNonEmpty(d.K8SSA.GetPublicKeys()) {
			return admin.NewError(admin.ErrorBadRequestType, "k8sSA.publicKeys is required")
		}
	case *linkedca.ProvisionerDetails_Nebula:
		if !anyNonEmpty(d.Nebula.GetRoots()) {
			return admin.NewError(admin.ErrorBadRequestType, "nebula.roots is required")
		}
	}
	return nil
}
