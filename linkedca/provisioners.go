package linkedca

import (
	"encoding/json"
	"fmt"
)

// UnmarshalProvisionerDetails unmarshals details type to the specific provisioner details.
func UnmarshalProvisionerDetails(typ Provisioner_Type, data []byte) (*ProvisionerDetails, error) {
	var v isProvisionerDetails_Data
	switch typ {
	case Provisioner_JWK:
		v = new(ProvisionerDetails_JWK)
	case Provisioner_OIDC:
		v = new(ProvisionerDetails_OIDC)
	case Provisioner_GCP:
		v = new(ProvisionerDetails_GCP)
	case Provisioner_AWS:
		v = new(ProvisionerDetails_AWS)
	case Provisioner_AZURE:
		v = new(ProvisionerDetails_Azure)
	case Provisioner_ACME:
		v = new(ProvisionerDetails_ACME)
	case Provisioner_X5C:
		v = new(ProvisionerDetails_X5C)
	case Provisioner_K8SSA:
		v = new(ProvisionerDetails_K8SSA)
	case Provisioner_SSHPOP:
		v = new(ProvisionerDetails_SSHPOP)
	default:
		return nil, fmt.Errorf("unsupported provisioner type %s", typ)
	}

	if err := json.Unmarshal(data, v); err != nil {
		return nil, err
	}
	return &ProvisionerDetails{Data: v}, nil
}
