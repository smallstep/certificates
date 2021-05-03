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

// dbProvisioner is the database representation of a Provisioner type.
type dbProvisioner struct {
	ID           string                    `json:"id"`
	AuthorityID  string                    `json:"authorityID"`
	Type         linkedca.Provisioner_Type `json:"type"`
	Name         string                    `json:"name"`
	Claims       *linkedca.Claims          `json:"claims"`
	Details      []byte                    `json:"details"`
	X509Template *linkedca.Template        `json:"x509Template"`
	SSHTemplate  *linkedca.Template        `json:"sshTemplate"`
	CreatedAt    time.Time                 `json:"createdAt"`
	DeletedAt    time.Time                 `json:"deletedAt"`
}

func (dbp *dbProvisioner) clone() *dbProvisioner {
	u := *dbp
	return &u
}

func (dbp *dbProvisioner) convert2linkedca() (*linkedca.Provisioner, error) {
	details, err := admin.UnmarshalProvisionerDetails(dbp.Type, dbp.Details)
	if err != nil {
		return nil, err
	}

	return &linkedca.Provisioner{
		Id:           dbp.ID,
		AuthorityId:  dbp.AuthorityID,
		Type:         dbp.Type,
		Name:         dbp.Name,
		Claims:       dbp.Claims,
		Details:      details,
		X509Template: dbp.X509Template,
		SshTemplate:  dbp.SSHTemplate,
		CreatedAt:    timestamppb.New(dbp.CreatedAt),
		DeletedAt:    timestamppb.New(dbp.DeletedAt),
	}, nil
}

func (db *DB) getDBProvisionerBytes(ctx context.Context, id string) ([]byte, error) {
	data, err := db.db.Get(provisionersTable, []byte(id))
	if nosql.IsErrNotFound(err) {
		return nil, admin.NewError(admin.ErrorNotFoundType, "provisioner %s not found", id)
	} else if err != nil {
		return nil, errors.Wrapf(err, "error loading provisioner %s", id)
	}
	return data, nil
}

func (db *DB) unmarshalDBProvisioner(data []byte, id string) (*dbProvisioner, error) {
	var dbp = new(dbProvisioner)
	if err := json.Unmarshal(data, dbp); err != nil {
		return nil, errors.Wrapf(err, "error unmarshaling provisioner %s into dbProvisioner", id)
	}
	if !dbp.DeletedAt.IsZero() {
		return nil, admin.NewError(admin.ErrorDeletedType, "provisioner %s is deleted", id)
	}
	if dbp.AuthorityID != db.authorityID {
		return nil, admin.NewError(admin.ErrorAuthorityMismatchType,
			"provisioner %s is not owned by authority %s", id, db.authorityID)
	}
	return dbp, nil
}

func (db *DB) getDBProvisioner(ctx context.Context, id string) (*dbProvisioner, error) {
	data, err := db.getDBProvisionerBytes(ctx, id)
	if err != nil {
		return nil, err
	}
	dbp, err := db.unmarshalDBProvisioner(data, id)
	if err != nil {
		return nil, err
	}
	return dbp, nil
}

func (db *DB) unmarshalProvisioner(data []byte, id string) (*linkedca.Provisioner, error) {
	dbp, err := db.unmarshalDBProvisioner(data, id)
	if err != nil {
		return nil, err
	}

	return dbp.convert2linkedca()
}

// GetProvisioner retrieves and unmarshals a provisioner from the database.
func (db *DB) GetProvisioner(ctx context.Context, id string) (*linkedca.Provisioner, error) {
	data, err := db.getDBProvisionerBytes(ctx, id)
	if err != nil {
		return nil, err
	}

	prov, err := db.unmarshalProvisioner(data, id)
	if err != nil {
		return nil, err
	}
	return prov, nil
}

// GetProvisioners retrieves and unmarshals all active (not deleted) provisioners
// from the database.
func (db *DB) GetProvisioners(ctx context.Context) ([]*linkedca.Provisioner, error) {
	dbEntries, err := db.db.List(provisionersTable)
	if err != nil {
		return nil, errors.Wrap(err, "error loading provisioners")
	}
	var provs []*linkedca.Provisioner
	for _, entry := range dbEntries {
		prov, err := db.unmarshalProvisioner(entry.Value, string(entry.Key))
		if err != nil {
			switch k := err.(type) {
			case *admin.Error:
				if k.IsType(admin.ErrorDeletedType) || k.IsType(admin.ErrorAuthorityMismatchType) {
					continue
				} else {
					return nil, err
				}
			default:
				return nil, err
			}
		}
		if prov.AuthorityId != db.authorityID {
			continue
		}
		provs = append(provs, prov)
	}
	return provs, nil
}

// CreateProvisioner stores a new provisioner to the database.
func (db *DB) CreateProvisioner(ctx context.Context, prov *linkedca.Provisioner) error {
	var err error
	prov.Id, err = randID()
	if err != nil {
		return admin.WrapErrorISE(err, "error generating random id for provisioner")
	}

	details, err := json.Marshal(prov.Details.GetData())
	if err != nil {
		return admin.WrapErrorISE(err, "error marshaling details when creating provisioner %s", prov.Name)
	}

	dbp := &dbProvisioner{
		ID:           prov.Id,
		AuthorityID:  db.authorityID,
		Type:         prov.Type,
		Name:         prov.Name,
		Claims:       prov.Claims,
		Details:      details,
		X509Template: prov.X509Template,
		SSHTemplate:  prov.SshTemplate,
		CreatedAt:    clock.Now(),
	}

	if err := db.save(ctx, prov.Id, dbp, nil, "provisioner", provisionersTable); err != nil {
		return admin.WrapErrorISE(err, "error creating provisioner %s", prov.Name)
	}

	return nil
}

// UpdateProvisioner saves an updated provisioner to the database.
func (db *DB) UpdateProvisioner(ctx context.Context, prov *linkedca.Provisioner) error {
	old, err := db.getDBProvisioner(ctx, prov.Id)
	if err != nil {
		return err
	}

	nu := old.clone()

	if old.Type != prov.Type {
		return admin.NewError(admin.ErrorBadRequestType, "cannot update provisioner type")
	}
	nu.Name = prov.Name
	nu.Claims = prov.Claims
	nu.Details, err = json.Marshal(prov.Details.GetData())
	if err != nil {
		return admin.WrapErrorISE(err, "error marshaling details when updating provisioner %s", prov.Name)
	}
	nu.X509Template = prov.X509Template
	nu.SSHTemplate = prov.SshTemplate

	return db.save(ctx, prov.Id, nu, old, "provisioner", provisionersTable)
}

// DeleteProvisioner saves an updated admin to the database.
func (db *DB) DeleteProvisioner(ctx context.Context, id string) error {
	old, err := db.getDBProvisioner(ctx, id)
	if err != nil {
		return err
	}

	nu := old.clone()
	nu.DeletedAt = clock.Now()

	return db.save(ctx, old.ID, nu, old, "provisioner", provisionersTable)
}
