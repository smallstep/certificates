package nosql

import (
	"context"
	"encoding/json"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/mgmt"
	"github.com/smallstep/nosql"
)

// dbProvisioner is the database representation of a Provisioner type.
type dbProvisioner struct {
	ID           string       `json:"id"`
	AuthorityID  string       `json:"authorityID"`
	Type         string       `json:"type"`
	Name         string       `json:"name"`
	Claims       *mgmt.Claims `json:"claims"`
	Details      interface{}  `json:"details"`
	X509Template string       `json:"x509Template"`
	SSHTemplate  string       `json:"sshTemplate"`
	CreatedAt    time.Time    `json:"createdAt"`
	DeletedAt    time.Time    `json:"deletedAt"`
}

func (dbp *dbProvisioner) clone() *dbProvisioner {
	u := *dbp
	return &u
}

func (db *DB) getDBProvisionerBytes(ctx context.Context, id string) ([]byte, error) {
	data, err := db.db.Get(authorityProvisionersTable, []byte(id))
	if nosql.IsErrNotFound(err) {
		return nil, mgmt.NewError(mgmt.ErrorNotFoundType, "provisioner %s not found", id)
	} else if err != nil {
		return nil, errors.Wrapf(err, "error loading provisioner %s", id)
	}
	return data, nil
}

func (db *DB) getDBProvisioner(ctx context.Context, id string) (*dbProvisioner, error) {
	data, err := db.getDBProvisionerBytes(ctx, id)
	if err != nil {
		return nil, err
	}
	dbp, err := unmarshalDBProvisioner(data, id)
	if err != nil {
		return nil, err
	}
	if dbp.AuthorityID != db.authorityID {
		return nil, mgmt.NewError(mgmt.ErrorAuthorityMismatchType,
			"provisioner %s is not owned by authority %s", dbp.ID, db.authorityID)
	}
	return dbp, nil
}

// GetProvisioner retrieves and unmarshals a provisioner from the database.
func (db *DB) GetProvisioner(ctx context.Context, id string) (*mgmt.Provisioner, error) {
	data, err := db.getDBProvisionerBytes(ctx, id)
	if err != nil {
		return nil, err
	}

	prov, err := unmarshalProvisioner(data, id)
	if err != nil {
		return nil, err
	}
	if prov.Status == mgmt.StatusDeleted {
		return nil, mgmt.NewError(mgmt.ErrorDeletedType, "provisioner %s is deleted", prov.ID)
	}
	if prov.AuthorityID != db.authorityID {
		return nil, mgmt.NewError(mgmt.ErrorAuthorityMismatchType,
			"provisioner %s is not owned by authority %s", prov.ID, db.authorityID)
	}
	return prov, nil
}

func unmarshalDBProvisioner(data []byte, id string) (*dbProvisioner, error) {
	var dbp = new(dbProvisioner)
	if err := json.Unmarshal(data, dbp); err != nil {
		return nil, errors.Wrapf(err, "error unmarshaling provisioner %s into dbProvisioner", id)
	}
	return dbp, nil
}

func unmarshalProvisioner(data []byte, id string) (*mgmt.Provisioner, error) {
	dbp, err := unmarshalDBProvisioner(data, id)
	if err != nil {
		return nil, err
	}

	prov := &mgmt.Provisioner{
		ID:           dbp.ID,
		Type:         dbp.Type,
		Name:         dbp.Name,
		Claims:       dbp.Claims,
		X509Template: dbp.X509Template,
		SSHTemplate:  dbp.SSHTemplate,
	}
	if !dbp.DeletedAt.IsZero() {
		prov.Status = mgmt.StatusDeleted
	}
	return prov, nil
}

// GetProvisioners retrieves and unmarshals all active (not deleted) provisioners
// from the database.
// TODO should we be paginating?
func (db *DB) GetProvisioners(ctx context.Context) ([]*mgmt.Provisioner, error) {
	dbEntries, err := db.db.List(authorityProvisionersTable)
	if err != nil {
		return nil, errors.Wrap(err, "error loading provisioners")
	}
	var provs []*mgmt.Provisioner
	for _, entry := range dbEntries {
		prov, err := unmarshalProvisioner(entry.Value, string(entry.Key))
		if err != nil {
			return nil, err
		}
		if prov.Status == mgmt.StatusDeleted {
			continue
		}
		if prov.AuthorityID != db.authorityID {
			continue
		}
		provs = append(provs, prov)
	}
	return provs, nil
}

// CreateProvisioner stores a new provisioner to the database.
func (db *DB) CreateProvisioner(ctx context.Context, prov *mgmt.Provisioner) error {
	var err error
	prov.ID, err = randID()
	if err != nil {
		return errors.Wrap(err, "error generating random id for provisioner")
	}

	dbp := &dbProvisioner{
		ID:           prov.ID,
		AuthorityID:  db.authorityID,
		Type:         prov.Type,
		Name:         prov.Name,
		Claims:       prov.Claims,
		Details:      prov.Details,
		X509Template: prov.X509Template,
		SSHTemplate:  prov.SSHTemplate,
		CreatedAt:    clock.Now(),
	}

	return db.save(ctx, dbp.ID, dbp, nil, "provisioner", authorityProvisionersTable)
}

// UpdateProvisioner saves an updated provisioner to the database.
func (db *DB) UpdateProvisioner(ctx context.Context, prov *mgmt.Provisioner) error {
	old, err := db.getDBProvisioner(ctx, prov.ID)
	if err != nil {
		return err
	}

	nu := old.clone()

	// If the provisioner was active but is now deleted ...
	if old.DeletedAt.IsZero() && prov.Status == mgmt.StatusDeleted {
		nu.DeletedAt = clock.Now()
	}
	nu.Claims = prov.Claims
	nu.Details = prov.Details
	nu.X509Template = prov.X509Template
	nu.SSHTemplate = prov.SSHTemplate

	return db.save(ctx, old.ID, nu, old, "provisioner", authorityProvisionersTable)
}
