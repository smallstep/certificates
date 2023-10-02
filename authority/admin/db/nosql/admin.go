package nosql

import (
	"context"
	"encoding/json"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/nosql"
	"go.step.sm/linkedca"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// dbAdmin is the database representation of the Admin type.
type dbAdmin struct {
	ID            string              `json:"id"`
	AuthorityID   string              `json:"authorityID"`
	ProvisionerID string              `json:"provisionerID"`
	Subject       string              `json:"subject"`
	Type          linkedca.Admin_Type `json:"type"`
	CreatedAt     time.Time           `json:"createdAt"`
	DeletedAt     time.Time           `json:"deletedAt"`
}

func (dba *dbAdmin) convert() *linkedca.Admin {
	return &linkedca.Admin{
		Id:            dba.ID,
		AuthorityId:   dba.AuthorityID,
		ProvisionerId: dba.ProvisionerID,
		Subject:       dba.Subject,
		Type:          dba.Type,
		CreatedAt:     timestamppb.New(dba.CreatedAt),
		DeletedAt:     timestamppb.New(dba.DeletedAt),
	}
}

func (dba *dbAdmin) clone() *dbAdmin {
	u := *dba
	return &u
}

func (db *DB) getDBAdminBytes(_ context.Context, id string) ([]byte, error) {
	data, err := db.db.Get(adminsTable, []byte(id))
	if nosql.IsErrNotFound(err) {
		return nil, admin.NewError(admin.ErrorNotFoundType, "admin %s not found", id)
	} else if err != nil {
		return nil, errors.Wrapf(err, "error loading admin %s", id)
	}
	return data, nil
}

func (db *DB) unmarshalDBAdmin(data []byte, id string) (*dbAdmin, error) {
	var dba = new(dbAdmin)
	if err := json.Unmarshal(data, dba); err != nil {
		return nil, errors.Wrapf(err, "error unmarshaling admin %s into dbAdmin", id)
	}
	if !dba.DeletedAt.IsZero() {
		return nil, admin.NewError(admin.ErrorDeletedType, "admin %s is deleted", id)
	}
	if dba.AuthorityID != db.authorityID {
		return nil, admin.NewError(admin.ErrorAuthorityMismatchType,
			"admin %s is not owned by authority %s", dba.ID, db.authorityID)
	}
	return dba, nil
}

func (db *DB) getDBAdmin(ctx context.Context, id string) (*dbAdmin, error) {
	data, err := db.getDBAdminBytes(ctx, id)
	if err != nil {
		return nil, err
	}
	dba, err := db.unmarshalDBAdmin(data, id)
	if err != nil {
		return nil, err
	}
	return dba, nil
}

func (db *DB) unmarshalAdmin(data []byte, id string) (*linkedca.Admin, error) {
	dba, err := db.unmarshalDBAdmin(data, id)
	if err != nil {
		return nil, err
	}
	return dba.convert(), nil
}

// GetAdmin retrieves and unmarshals a admin from the database.
func (db *DB) GetAdmin(ctx context.Context, id string) (*linkedca.Admin, error) {
	data, err := db.getDBAdminBytes(ctx, id)
	if err != nil {
		return nil, err
	}
	adm, err := db.unmarshalAdmin(data, id)
	if err != nil {
		return nil, err
	}

	return adm, nil
}

// GetAdmins retrieves and unmarshals all active (not deleted) admins
// from the database.
// TODO should we be paginating?
func (db *DB) GetAdmins(context.Context) ([]*linkedca.Admin, error) {
	dbEntries, err := db.db.List(adminsTable)
	if err != nil {
		return nil, errors.Wrap(err, "error loading admins")
	}
	var admins = []*linkedca.Admin{}
	for _, entry := range dbEntries {
		adm, err := db.unmarshalAdmin(entry.Value, string(entry.Key))
		if err != nil {
			var ae *admin.Error
			if errors.As(err, &ae) {
				if ae.IsType(admin.ErrorDeletedType) || ae.IsType(admin.ErrorAuthorityMismatchType) {
					continue
				}
				return nil, err
			}
			return nil, err
		}
		if adm.AuthorityId != db.authorityID {
			continue
		}
		admins = append(admins, adm)
	}
	return admins, nil
}

// CreateAdmin stores a new admin to the database.
func (db *DB) CreateAdmin(ctx context.Context, adm *linkedca.Admin) error {
	var err error
	adm.Id, err = randID()
	if err != nil {
		return admin.WrapErrorISE(err, "error generating random id for admin")
	}
	adm.AuthorityId = db.authorityID

	dba := &dbAdmin{
		ID:            adm.Id,
		AuthorityID:   db.authorityID,
		ProvisionerID: adm.ProvisionerId,
		Subject:       adm.Subject,
		Type:          adm.Type,
		CreatedAt:     clock.Now(),
	}

	return db.save(ctx, dba.ID, dba, nil, "admin", adminsTable)
}

// UpdateAdmin saves an updated admin to the database.
func (db *DB) UpdateAdmin(ctx context.Context, adm *linkedca.Admin) error {
	old, err := db.getDBAdmin(ctx, adm.Id)
	if err != nil {
		return err
	}

	nu := old.clone()
	nu.Type = adm.Type

	return db.save(ctx, old.ID, nu, old, "admin", adminsTable)
}

// DeleteAdmin saves an updated admin to the database.
func (db *DB) DeleteAdmin(ctx context.Context, id string) error {
	old, err := db.getDBAdmin(ctx, id)
	if err != nil {
		return err
	}

	nu := old.clone()
	nu.DeletedAt = clock.Now()

	return db.save(ctx, old.ID, nu, old, "admin", adminsTable)
}
