package mgmt

import "context"

// Admin type.
type Admin struct {
	ID            string     `json:"id"`
	AuthorityID   string     `json:"-"`
	ProvisionerID string     `json:"provisionerID"`
	Name          string     `json:"name"`
	IsSuperAdmin  bool       `json:"isSuperAdmin"`
	Status        StatusType `json:"status"`
}

// CreateAdmin builds and stores an admin type in the DB.
func CreateAdmin(ctx context.Context, db DB, name string, provID string, isSuperAdmin bool) (*Admin, error) {
	adm := &Admin{
		Name:          name,
		ProvisionerID: provID,
		IsSuperAdmin:  isSuperAdmin,
		Status:        StatusActive,
	}
	if err := db.CreateAdmin(ctx, adm); err != nil {
		return nil, WrapErrorISE(err, "error creating admin")
	}
	return adm, nil
}
