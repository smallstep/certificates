package admin

import "github.com/smallstep/certificates/authority/status"

// Type specifies the type of the admin. e.g. SUPER_ADMIN, REGULAR
type Type string

var (
	// TypeSuper superadmin
	TypeSuper = Type("SUPER_ADMIN")
	// TypeRegular regular
	TypeRegular = Type("REGULAR")
)

// Admin type.
type Admin struct {
	ID              string      `json:"id"`
	AuthorityID     string      `json:"-"`
	Subject         string      `json:"subject"`
	ProvisionerName string      `json:"provisionerName"`
	ProvisionerType string      `json:"provisionerType"`
	ProvisionerID   string      `json:"provisionerID"`
	Type            Type        `json:"type"`
	Status          status.Type `json:"status"`
}
