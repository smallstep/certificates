package mgmt

import (
	"github.com/smallstep/certificates/authority/admin"
)

// AdminType specifies the type of the admin. e.g. SUPER_ADMIN, REGULAR
type AdminType admin.Type

var (
	// AdminTypeSuper superadmin
	AdminTypeSuper = admin.TypeSuper
	// AdminTypeRegular regular
	AdminTypeRegular = admin.TypeRegular
)

// Admin type.
type Admin admin.Admin

// ToCertificates converts an Admin to the Admin type expected by the authority.
func (adm *Admin) ToCertificates() (*admin.Admin, error) {
	return (*admin.Admin)(adm), nil
}
