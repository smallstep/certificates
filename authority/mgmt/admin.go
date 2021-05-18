package mgmt

import (
	"context"

	"github.com/smallstep/certificates/authority/admin"
)

// AdminType specifies the type of the admin. e.g. SUPER_ADMIN, REGULAR
type AdminType string

var (
	// AdminTypeSuper superadmin
	AdminTypeSuper = AdminType("SUPER_ADMIN")
	// AdminTypeRegular regular
	AdminTypeRegular = AdminType("REGULAR")
)

// Admin type.
type Admin struct {
	ID              string     `json:"id"`
	AuthorityID     string     `json:"-"`
	ProvisionerID   string     `json:"provisionerID"`
	Subject         string     `json:"subject"`
	ProvisionerName string     `json:"provisionerName"`
	ProvisionerType string     `json:"provisionerType"`
	Type            AdminType  `json:"type"`
	Status          StatusType `json:"status"`
}

// CreateAdmin builds and stores an admin type in the DB.
func CreateAdmin(ctx context.Context, db DB, provName, sub string, typ AdminType) (*Admin, error) {
	adm := &Admin{
		Subject:         sub,
		ProvisionerName: provName,
		Type:            typ,
		Status:          StatusActive,
	}
	if err := db.CreateAdmin(ctx, adm); err != nil {
		return nil, WrapErrorISE(err, "error creating admin")
	}
	return adm, nil
}

// ToCertificates converts an Admin to the Admin type expected by the authority.
func (adm *Admin) ToCertificates() (*admin.Admin, error) {
	return &admin.Admin{
		ID:              adm.ID,
		Subject:         adm.Subject,
		ProvisionerID:   adm.ProvisionerID,
		ProvisionerName: adm.ProvisionerName,
		ProvisionerType: adm.ProvisionerType,
		Type:            admin.Type(adm.Type),
	}, nil
}
