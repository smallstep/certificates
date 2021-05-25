package nosql

import (
	"context"
	"encoding/json"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/mgmt"
	"github.com/smallstep/certificates/linkedca"
	"github.com/smallstep/nosql"
)

// dbProvisioner is the database representation of a Provisioner type.
type dbProvisioner struct {
	ID          string                    `json:"id"`
	AuthorityID string                    `json:"authorityID"`
	Type        linkedca.Provisioner_Type `json:"type"`
	// Name is the key
	Name             string           `json:"name"`
	Claims           *linkedca.Claims `json:"claims"`
	Details          []byte           `json:"details"`
	X509Template     []byte           `json:"x509Template"`
	X509TemplateData []byte           `json:"x509TemplateData"`
	SSHTemplate      []byte           `json:"sshTemplate"`
	SSHTemplateData  []byte           `json:"sshTemplateData"`
	CreatedAt        time.Time        `json:"createdAt"`
	DeletedAt        time.Time        `json:"deletedAt"`
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
func (db *DB) GetProvisioner(ctx context.Context, id string) (*linkedca.Provisioner, error) {
	data, err := db.getDBProvisionerBytes(ctx, id)
	if err != nil {
		return nil, err
	}

	prov, err := unmarshalProvisioner(data, id)
	if err != nil {
		return nil, err
	}
	if prov.AuthorityId != db.authorityID {
		return nil, mgmt.NewError(mgmt.ErrorAuthorityMismatchType,
			"provisioner %s is not owned by authority %s", prov.Id, db.authorityID)
	}
	return prov, nil
}

func unmarshalDBProvisioner(data []byte, name string) (*dbProvisioner, error) {
	var dbp = new(dbProvisioner)
	if err := json.Unmarshal(data, dbp); err != nil {
		return nil, errors.Wrapf(err, "error unmarshaling provisioner %s into dbProvisioner", name)
	}
	if !dbp.DeletedAt.IsZero() {
		return nil, mgmt.NewError(mgmt.ErrorDeletedType, "provisioner %s is deleted", name)
	}
	return dbp, nil
}

func unmarshalProvisioner(data []byte, name string) (*linkedca.Provisioner, error) {
	dbp, err := unmarshalDBProvisioner(data, name)
	if err != nil {
		return nil, err
	}

	details, err := linkedca.UnmarshalProvisionerDetails(dbp.Type, dbp.Details)
	if err != nil {
		return nil, err
	}

	prov := &linkedca.Provisioner{
		Id:               dbp.ID,
		AuthorityId:      dbp.AuthorityID,
		Type:             dbp.Type,
		Name:             dbp.Name,
		Claims:           dbp.Claims,
		Details:          details,
		X509Template:     dbp.X509Template,
		X509TemplateData: dbp.X509TemplateData,
		SshTemplate:      dbp.SSHTemplate,
		SshTemplateData:  dbp.SSHTemplateData,
	}
	return prov, nil
}

// GetProvisioners retrieves and unmarshals all active (not deleted) provisioners
// from the database.
func (db *DB) GetProvisioners(ctx context.Context) ([]*linkedca.Provisioner, error) {
	dbEntries, err := db.db.List(authorityProvisionersTable)
	if err != nil {
		return nil, mgmt.WrapErrorISE(err, "error loading provisioners")
	}
	var provs []*linkedca.Provisioner
	for _, entry := range dbEntries {
		prov, err := unmarshalProvisioner(entry.Value, string(entry.Key))
		if err != nil {
			return nil, err
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
		return errors.Wrap(err, "error generating random id for provisioner")
	}

	details, err := json.Marshal(prov.Details)
	if err != nil {
		return mgmt.WrapErrorISE(err, "error marshaling details when creating provisioner %s", prov.Name)
	}

	dbp := &dbProvisioner{
		ID:               prov.Id,
		AuthorityID:      db.authorityID,
		Type:             prov.Type,
		Name:             prov.Name,
		Claims:           prov.Claims,
		Details:          details,
		X509Template:     prov.X509Template,
		X509TemplateData: prov.X509TemplateData,
		SSHTemplate:      prov.SshTemplate,
		SSHTemplateData:  prov.SshTemplateData,
		CreatedAt:        clock.Now(),
	}

	if err := db.save(ctx, prov.Id, dbp, nil, "provisioner", authorityProvisionersTable); err != nil {
		return mgmt.WrapErrorISE(err, "error creating provisioner %s", prov.Name)
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

	nu.Type = prov.Type
	nu.Name = prov.Name
	nu.Claims = prov.Claims
	nu.Details, err = json.Marshal(prov.Details)
	if err != nil {
		return mgmt.WrapErrorISE(err, "error marshaling details when updating provisioner %s", prov.Name)
	}
	nu.X509Template = prov.X509Template
	nu.X509TemplateData = prov.X509TemplateData
	nu.SSHTemplate = prov.SshTemplate
	nu.SSHTemplateData = prov.SshTemplateData

	if err := db.save(ctx, prov.Id, nu, old, "provisioner", authorityProvisionersTable); err != nil {
		return mgmt.WrapErrorISE(err, "error updating provisioner %s", prov.Name)
	}

	return nil
}
