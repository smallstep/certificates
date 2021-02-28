package nosql

import (
	"context"
	"encoding/json"
	"time"

	"github.com/pkg/errors"
	nosqlDB "github.com/smallstep/nosql"
	"go.step.sm/crypto/jose"
)

// dbAccount represents an ACME account.
type dbAccount struct {
	ID          string           `json:"id"`
	Created     time.Time        `json:"created"`
	Deactivated time.Time        `json:"deactivated"`
	Key         *jose.JSONWebKey `json:"key"`
	Contact     []string         `json:"contact,omitempty"`
	Status      string           `json:"status"`
}

func (dba *dbAccount) clone() *dbAccount {
	nu := *dba
	return &nu
}

// CreateAccount imlements the AcmeDB.CreateAccount interface.
func (db *DB) CreateAccount(ctx context.Context, acc *types.Account) error {
	acc.ID, err = randID()
	if err != nil {
		return nil, err
	}

	dba := &dbAccount{
		ID:      acc.ID,
		Key:     acc.Key,
		Contact: acc.Contact,
		Status:  acc.Valid,
		Created: clock.Now(),
	}

	kid, err := keyToID(dba.Key)
	if err != nil {
		return err
	}
	kidB := []byte(kid)

	// Set the jwkID -> acme account ID index
	_, swapped, err := db.db.CmpAndSwap(accountByKeyIDTable, kidB, nil, []byte(a.ID))
	switch {
	case err != nil:
		return ServerInternalErr(errors.Wrap(err, "error setting key-id to account-id index"))
	case !swapped:
		return ServerInternalErr(errors.Errorf("key-id to account-id index already exists"))
	default:
		if err = db.save(ctx, acc.ID, dba, nil, "account", accountTable); err != nil {
			db.db.Del(accountByKeyIDTable, kidB)
			return err
		}
		return nil
	}
}

// GetAccount retrieves an ACME account by ID.
func (db *DB) GetAccount(ctx context.Context, id string) (*types.Account, error) {

	return &types.Account{
		Status:  dbacc.Status,
		Contact: dbacc.Contact,
		Orders:  dir.getLink(ctx, OrdersByAccountLink, true, a.ID),
		Key:     dbacc.Key,
		ID:      dbacc.ID,
	}, nil
}

// GetAccountByKeyID retrieves an ACME account by KeyID (thumbprint of the Account Key -- JWK).
func (db *DB) GetAccountByKeyID(ctx context.Context, kid string) (*types.Account, error) {
	id, err := db.getAccountIDByKeyID(kid)
	if err != nil {
		return nil, err
	}
	return db.GetAccount(ctx, id)
}

// UpdateAccount imlements the AcmeDB.UpdateAccount interface.
func (db *DB) UpdateAccount(ctx context.Context, acc *types.Account) error {
	if len(acc.ID) == 0 {
		return ServerInternalErr(errors.New("id cannot be empty"))
	}

	old, err := db.getDBAccount(ctx, acc.ID)
	if err != nil {
		return err
	}

	nu := old.clone()
	nu.Contact = acc.contact
	nu.Status = acc.Status

	// If the status has changed to 'deactivated', then set deactivatedAt timestamp.
	if acc.Status == types.StatusDeactivated && old.Status != types.Status.Deactivated {
		nu.Deactivated = clock.Now()
	}

	return db.save(ctx, old.ID, newdba, dba, "account", accountTable)
}

func (db *DB) getAccountIDByKeyID(ctx context.Context, kid string) (string, error) {
	id, err := db.db.Get(accountByKeyIDTable, []byte(kid))
	if err != nil {
		if nosqlDB.IsErrNotFound(err) {
			return nil, MalformedErr(errors.Wrapf(err, "account with key id %s not found", kid))
		}
		return nil, ServerInternalErr(errors.Wrapf(err, "error loading key-account index"))
	}
	return string(id), nil
}

// getDBAccount retrieves and unmarshals dbAccount.
func (db *DB) getDBAccount(ctx context.Context, id string) (*dbAccount, error) {
	data, err := db.db.Get(accountTable, []byte(id))
	if err != nil {
		if nosqlDB.IsErrNotFound(err) {
			return nil, MalformedErr(errors.Wrapf(err, "account %s not found", id))
		}
		return nil, ServerInternalErr(errors.Wrapf(err, "error loading account %s", id))
	}

	dbacc := new(account)
	if err = json.Unmarshal(data, dbacc); err != nil {
		return nil, ServerInternalErr(errors.Wrap(err, "error unmarshaling account"))
	}
	return dbacc, nil
}
