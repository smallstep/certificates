package nosql

import (
	"context"
	"encoding/json"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/mgmt"
	"github.com/smallstep/certificates/authority/status"
	"github.com/smallstep/nosql"
)

// dbProvisioner is the database representation of a Provisioner type.
type dbProvisioner struct {
	ID          string `json:"id"`
	AuthorityID string `json:"authorityID"`
	Type        string `json:"type"`
	// Name is the key
	Name             string       `json:"name"`
	Claims           *mgmt.Claims `json:"claims"`
	Details          []byte       `json:"details"`
	X509Template     string       `json:"x509Template"`
	X509TemplateData []byte       `json:"x509TemplateData"`
	SSHTemplate      string       `json:"sshTemplate"`
	SSHTemplateData  []byte       `json:"sshTemplateData"`
	CreatedAt        time.Time    `json:"createdAt"`
	DeletedAt        time.Time    `json:"deletedAt"`
}

type provisionerNameID struct {
	Name string `json:"name"`
	ID   string `json:"id"`
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
	if !dbp.DeletedAt.IsZero() {
		return nil, mgmt.NewError(mgmt.ErrorDeletedType, "provisioner %s is deleted", id)
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
	if prov.Status == status.Deleted {
		return nil, mgmt.NewError(mgmt.ErrorDeletedType, "provisioner %s is deleted", prov.ID)
	}
	if prov.AuthorityID != db.authorityID {
		return nil, mgmt.NewError(mgmt.ErrorAuthorityMismatchType,
			"provisioner %s is not owned by authority %s", prov.ID, db.authorityID)
	}
	return prov, nil
}

func unmarshalDBProvisioner(data []byte, name string) (*dbProvisioner, error) {
	var dbp = new(dbProvisioner)
	if err := json.Unmarshal(data, dbp); err != nil {
		return nil, errors.Wrapf(err, "error unmarshaling provisioner %s into dbProvisioner", name)
	}
	return dbp, nil
}

func unmarshalProvisioner(data []byte, name string) (*mgmt.Provisioner, error) {
	dbp, err := unmarshalDBProvisioner(data, name)
	if err != nil {
		return nil, err
	}

	details, err := mgmt.UnmarshalProvisionerDetails(dbp.Details)
	if err != nil {
		return nil, err
	}

	prov := &mgmt.Provisioner{
		ID:               dbp.ID,
		AuthorityID:      dbp.AuthorityID,
		Type:             dbp.Type,
		Name:             dbp.Name,
		Claims:           dbp.Claims,
		Details:          details,
		Status:           status.Active,
		X509Template:     dbp.X509Template,
		X509TemplateData: dbp.X509TemplateData,
		SSHTemplate:      dbp.SSHTemplate,
		SSHTemplateData:  dbp.SSHTemplateData,
	}
	if !dbp.DeletedAt.IsZero() {
		prov.Status = status.Deleted
	}
	return prov, nil
}

// GetProvisioners retrieves and unmarshals all active (not deleted) provisioners
// from the database.
func (db *DB) GetProvisioners(ctx context.Context) ([]*mgmt.Provisioner, error) {
	dbEntries, err := db.db.List(authorityProvisionersTable)
	if err != nil {
		return nil, mgmt.WrapErrorISE(err, "error loading provisioners")
	}
	var provs []*mgmt.Provisioner
	for _, entry := range dbEntries {
		prov, err := unmarshalProvisioner(entry.Value, string(entry.Key))
		if err != nil {
			return nil, err
		}
		if prov.Status == status.Deleted {
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

	details, err := json.Marshal(prov.Details)
	if err != nil {
		return mgmt.WrapErrorISE(err, "error marshaling details when creating provisioner %s", prov.Name)
	}

	dbp := &dbProvisioner{
		ID:               prov.ID,
		AuthorityID:      db.authorityID,
		Type:             prov.Type,
		Name:             prov.Name,
		Claims:           prov.Claims,
		Details:          details,
		X509Template:     prov.X509Template,
		X509TemplateData: prov.X509TemplateData,
		SSHTemplate:      prov.SSHTemplate,
		SSHTemplateData:  prov.SSHTemplateData,
		CreatedAt:        clock.Now(),
	}

	if err := db.save(ctx, prov.ID, dbp, nil, "provisioner", authorityProvisionersTable); err != nil {
		return mgmt.WrapErrorISE(err, "error creating provisioner %s", prov.Name)
	}

	return nil
}

// UpdateProvisioner saves an updated provisioner to the database.
func (db *DB) UpdateProvisioner(ctx context.Context, prov *mgmt.Provisioner) error {
	old, err := db.getDBProvisioner(ctx, prov.ID)
	if err != nil {
		return err
	}

	nu := old.clone()

	nu.Type = prov.Type
	nu.Name = prov.Name
	nu.Claims = prov.Claims
	nu.Details, err = json.Marshal(prov.Details)
	if err != nil {
		return mgmt.WrapErrorISE(err, "error marshaling details when updating provisioner %s", prov.Name)
	}
	nu.X509Template = prov.X509Template
	nu.X509TemplateData = prov.X509TemplateData
	nu.SSHTemplateData = prov.SSHTemplateData

	if err := db.save(ctx, prov.ID, nu, old, "provisioner", authorityProvisionersTable); err != nil {
		return mgmt.WrapErrorISE(err, "error updating provisioner %s", prov.Name)
	}

	return nil
}
