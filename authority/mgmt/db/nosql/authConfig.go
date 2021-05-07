package nosql

import (
	"context"
	"encoding/json"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/mgmt"
	"github.com/smallstep/nosql"
)

type dbAuthConfig struct {
	ID        string         `json:"id"`
	ASN1DN    *config.ASN1DN `json:"asn1dn"`
	Claims    *mgmt.Claims   `json:"claims"`
	Backdate  string         `json:"backdate,omitempty"`
	CreatedAt time.Time      `json:"createdAt"`
	DeletedAt time.Time      `json:"deletedAt"`
}

func (dbp *dbAuthConfig) clone() *dbAuthConfig {
	u := *dbp
	return &u
}

func (db *DB) getDBAuthConfigBytes(ctx context.Context, id string) ([]byte, error) {
	data, err := db.db.Get(authorityConfigsTable, []byte(id))
	if nosql.IsErrNotFound(err) {
		return nil, mgmt.NewError(mgmt.ErrorNotFoundType, "authConfig %s not found", id)
	} else if err != nil {
		return nil, errors.Wrapf(err, "error loading authConfig %s", id)
	}
	return data, nil
}

func (db *DB) getDBAuthConfig(ctx context.Context, id string) (*dbAuthConfig, error) {
	data, err := db.getDBAuthConfigBytes(ctx, id)
	if err != nil {
		return nil, err
	}

	var dba = new(dbAuthConfig)
	if err = json.Unmarshal(data, dba); err != nil {
		return nil, errors.Wrapf(err, "error unmarshaling authority %s into dbAuthConfig", id)
	}

	return dba, nil
}

// GetAuthConfig retrieves an AuthConfig configuration from the DB.
func (db *DB) GetAuthConfig(ctx context.Context, id string) (*mgmt.AuthConfig, error) {
	dba, err := db.getDBAuthConfig(ctx, id)
	if err != nil {
		return nil, err
	}

	provs, err := db.GetProvisioners(ctx)
	if err != nil {
		return nil, err
	}

	return &mgmt.AuthConfig{
		ID:           dba.ID,
		Provisioners: provs,
		ASN1DN:       dba.ASN1DN,
		Backdate:     dba.Backdate,
		Claims:       dba.Claims,
	}, nil
}

// CreateAuthConfig stores a new provisioner to the database.
func (db *DB) CreateAuthConfig(ctx context.Context, ac *mgmt.AuthConfig) error {
	var err error
	if ac.ID == "" {
		ac.ID, err = randID()
		if err != nil {
			return errors.Wrap(err, "error generating random id for provisioner")
		}
	}

	dba := &dbAuthConfig{
		ID:        ac.ID,
		ASN1DN:    ac.ASN1DN,
		Claims:    ac.Claims,
		Backdate:  ac.Backdate,
		CreatedAt: clock.Now(),
	}

	return db.save(ctx, dba.ID, dba, nil, "authConfig", authorityConfigsTable)
}

// UpdateAuthConfig saves an updated provisioner to the database.
func (db *DB) UpdateAuthConfig(ctx context.Context, ac *mgmt.AuthConfig) error {
	old, err := db.getDBAuthConfig(ctx, ac.ID)
	if err != nil {
		return err
	}

	nu := old.clone()

	// If the authority was active but is now deleted ...
	if old.DeletedAt.IsZero() && ac.Status == mgmt.StatusDeleted {
		nu.DeletedAt = clock.Now()
	}
	nu.Claims = ac.Claims
	nu.Backdate = ac.Backdate

	return db.save(ctx, old.ID, nu, old, "authConfig", authorityProvisionersTable)
}
