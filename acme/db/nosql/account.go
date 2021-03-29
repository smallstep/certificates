package nosql

import (
	"context"
	"encoding/json"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/acme"
	nosqlDB "github.com/smallstep/nosql"
	"go.step.sm/crypto/jose"
)

// dbAccount represents an ACME account.
type dbAccount struct {
	ID            string           `json:"id"`
	Key           *jose.JSONWebKey `json:"key"`
	Contact       []string         `json:"contact,omitempty"`
	Status        acme.Status      `json:"status"`
	CreatedAt     time.Time        `json:"createdAt"`
	DeactivatedAt time.Time        `json:"deactivatedAt"`
}

func (dba *dbAccount) clone() *dbAccount {
	nu := *dba
	return &nu
}

func (db *DB) getAccountIDByKeyID(ctx context.Context, kid string) (string, error) {
	id, err := db.db.Get(accountByKeyIDTable, []byte(kid))
	if err != nil {
		if nosqlDB.IsErrNotFound(err) {
			return "", acme.ErrNotFound
		}
		return "", errors.Wrapf(err, "error loading key-account index for key %s", kid)
	}
	return string(id), nil
}

// getDBAccount retrieves and unmarshals dbAccount.
func (db *DB) getDBAccount(ctx context.Context, id string) (*dbAccount, error) {
	data, err := db.db.Get(accountTable, []byte(id))
	if err != nil {
		if nosqlDB.IsErrNotFound(err) {
			return nil, acme.ErrNotFound
		}
		return nil, errors.Wrapf(err, "error loading account %s", id)
	}

	dbacc := new(dbAccount)
	if err = json.Unmarshal(data, dbacc); err != nil {
		return nil, errors.Wrapf(err, "error unmarshaling account %s into dbAccount", id)
	}
	return dbacc, nil
}

// GetAccount retrieves an ACME account by ID.
func (db *DB) GetAccount(ctx context.Context, id string) (*acme.Account, error) {
	dbacc, err := db.getDBAccount(ctx, id)
	if err != nil {
		return nil, err
	}

	return &acme.Account{
		Status:  dbacc.Status,
		Contact: dbacc.Contact,
		Key:     dbacc.Key,
		ID:      dbacc.ID,
	}, nil
}

// GetAccountByKeyID retrieves an ACME account by KeyID (thumbprint of the Account Key -- JWK).
func (db *DB) GetAccountByKeyID(ctx context.Context, kid string) (*acme.Account, error) {
	id, err := db.getAccountIDByKeyID(ctx, kid)
	if err != nil {
		return nil, err
	}
	return db.GetAccount(ctx, id)
}

// CreateAccount imlements the AcmeDB.CreateAccount interface.
func (db *DB) CreateAccount(ctx context.Context, acc *acme.Account) error {
	var err error
	acc.ID, err = randID()
	if err != nil {
		return err
	}

	dba := &dbAccount{
		ID:        acc.ID,
		Key:       acc.Key,
		Contact:   acc.Contact,
		Status:    acc.Status,
		CreatedAt: clock.Now(),
	}

	kid, err := acme.KeyToID(dba.Key)
	if err != nil {
		return err
	}
	kidB := []byte(kid)

	// Set the jwkID -> acme account ID index
	_, swapped, err := db.db.CmpAndSwap(accountByKeyIDTable, kidB, nil, []byte(acc.ID))
	switch {
	case err != nil:
		return errors.Wrap(err, "error storing keyID to accountID index")
	case !swapped:
		return errors.Errorf("key-id to account-id index already exists")
	default:
		if err = db.save(ctx, acc.ID, dba, nil, "account", accountTable); err != nil {
			db.db.Del(accountByKeyIDTable, kidB)
			return err
		}
		return nil
	}
}

// UpdateAccount imlements the AcmeDB.UpdateAccount interface.
func (db *DB) UpdateAccount(ctx context.Context, acc *acme.Account) error {
	old, err := db.getDBAccount(ctx, acc.ID)
	if err != nil {
		return err
	}

	nu := old.clone()
	nu.Contact = acc.Contact
	nu.Status = acc.Status

	// If the status has changed to 'deactivated', then set deactivatedAt timestamp.
	if acc.Status == acme.StatusDeactivated && old.Status != acme.StatusDeactivated {
		nu.DeactivatedAt = clock.Now()
	}

	return db.save(ctx, old.ID, nu, old, "account", accountTable)
}
