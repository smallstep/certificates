package nosql

import (
	"context"
	"encoding/json"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/authority/mgmt"
	"github.com/smallstep/nosql"
)

// dbAdmin is the database representation of the Admin type.
type dbAdmin struct {
	ID           string    `json:"id"`
	AuthorityID  string    `json:"authorityID"`
	Name         string    `json:"name"`
	Provisioner  string    `json:"provisioner"`
	IsSuperAdmin bool      `json:"isSuperAdmin"`
	CreatedAt    time.Time `json:"createdAt"`
	DeletedAt    time.Time `json:"deletedAt"`
}

func (dbp *dbAdmin) clone() *dbAdmin {
	u := *dbp
	return &u
}

func (db *DB) getDBAdminBytes(ctx context.Context, id string) ([]byte, error) {
	data, err := db.db.Get(authorityAdminsTable, []byte(id))
	if nosql.IsErrNotFound(err) {
		return nil, mgmt.NewError(mgmt.ErrorNotFoundType, "admin %s not found", id)
	} else if err != nil {
		return nil, errors.Wrapf(err, "error loading admin %s", id)
	}
	return data, nil
}

func (db *DB) getDBAdmin(ctx context.Context, id string) (*dbAdmin, error) {
	data, err := db.getDBAdminBytes(ctx, id)
	if err != nil {
		return nil, err
	}
	dba, err := unmarshalDBAdmin(data, id)
	if err != nil {
		return nil, err
	}
	if dba.AuthorityID != db.authorityID {
		return nil, mgmt.NewError(mgmt.ErrorAuthorityMismatchType,
			"admin %s is not owned by authority %s", dba.ID, db.authorityID)
	}
	return dba, nil
}

// GetAdmin retrieves and unmarshals a admin from the database.
func (db *DB) GetAdmin(ctx context.Context, id string) (*mgmt.Admin, error) {
	data, err := db.getDBAdminBytes(ctx, id)
	if err != nil {
		return nil, err
	}
	adm, err := unmarshalAdmin(data, id)
	if err != nil {
		return nil, err
	}
	if adm.Status == mgmt.StatusDeleted {
		return nil, mgmt.NewError(mgmt.ErrorDeletedType, "admin %s is deleted")
	}
	if adm.AuthorityID != db.authorityID {
		return nil, mgmt.NewError(mgmt.ErrorAuthorityMismatchType,
			"admin %s is not owned by authority %s", adm.ID, db.authorityID)
	}
	return adm, nil
}

func unmarshalDBAdmin(data []byte, id string) (*dbAdmin, error) {
	var dba = new(dbAdmin)
	if err := json.Unmarshal(data, dba); err != nil {
		return nil, errors.Wrapf(err, "error unmarshaling admin %s into dbAdmin", id)
	}
	return dba, nil
}

func unmarshalAdmin(data []byte, id string) (*mgmt.Admin, error) {
	var dba = new(dbAdmin)
	if err := json.Unmarshal(data, dba); err != nil {
		return nil, errors.Wrapf(err, "error unmarshaling admin %s into dbAdmin", id)
	}
	adm := &mgmt.Admin{
		ID:           dba.ID,
		Name:         dba.Name,
		Provisioner:  dba.Provisioner,
		IsSuperAdmin: dba.IsSuperAdmin,
	}
	if !dba.DeletedAt.IsZero() {
		adm.Status = mgmt.StatusDeleted
	}
	return adm, nil
}

// GetAdmins retrieves and unmarshals all active (not deleted) admins
// from the database.
// TODO should we be paginating?
func (db *DB) GetAdmins(ctx context.Context, az *acme.Authorization) ([]*mgmt.Admin, error) {
	dbEntries, err := db.db.List(authorityAdminsTable)
	if err != nil {
		return nil, errors.Wrap(err, "error loading admins")
	}
	var admins []*mgmt.Admin
	for _, entry := range dbEntries {
		adm, err := unmarshalAdmin(entry.Value, string(entry.Key))
		if err != nil {
			return nil, err
		}
		if adm.Status == mgmt.StatusDeleted {
			continue
		}
		if adm.AuthorityID != db.authorityID {
			continue
		}
		admins = append(admins, adm)
	}
	return admins, nil
}

// CreateAdmin stores a new admin to the database.
func (db *DB) CreateAdmin(ctx context.Context, adm *mgmt.Admin) error {
	var err error
	adm.ID, err = randID()
	if err != nil {
		return errors.Wrap(err, "error generating random id for admin")
	}

	dba := &dbAdmin{
		ID:           adm.ID,
		AuthorityID:  db.authorityID,
		Name:         adm.Name,
		Provisioner:  adm.Provisioner,
		IsSuperAdmin: adm.IsSuperAdmin,
		CreatedAt:    clock.Now(),
	}

	return db.save(ctx, dba.ID, dba, nil, "admin", authorityAdminsTable)
}

// UpdateAdmin saves an updated admin to the database.
func (db *DB) UpdateAdmin(ctx context.Context, adm *mgmt.Admin) error {
	old, err := db.getDBAdmin(ctx, adm.ID)
	if err != nil {
		return err
	}

	nu := old.clone()

	// If the admin was active but is now deleted ...
	if old.DeletedAt.IsZero() && adm.Status == mgmt.StatusDeleted {
		nu.DeletedAt = clock.Now()
	}
	nu.Provisioner = adm.Provisioner
	nu.IsSuperAdmin = adm.IsSuperAdmin

	return db.save(ctx, old.ID, nu, old, "admin", authorityAdminsTable)
}
