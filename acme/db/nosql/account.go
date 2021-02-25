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

func (db *DB) saveAccount(nu *dbAccount, old *dbAccount) error {
	var (
		err  error
		oldB []byte
	)
	if old == nil {
		oldB = nil
	} else {
		if oldB, err = json.Marshal(old); err != nil {
			return ServerInternalErr(errors.Wrap(err, "error marshaling old acme order"))
		}
	}

	b, err := json.Marshal(*nu)
	if err != nil {
		return errors.Wrap(err, "error marshaling new account object")
	}
	// Set the Account
	_, swapped, err := db.CmpAndSwap(accountTable, []byte(nu.ID), oldB, b)
	switch {
	case err != nil:
		return ServerInternalErr(errors.Wrap(err, "error storing account"))
	case !swapped:
		return ServerInternalErr(errors.New("error storing account; " +
			"value has changed since last read"))
	default:
		return nil
	}
}

// CreateAccount imlements the AcmeDB.CreateAccount interface.
func (db *DB) CreateAccount(ctx context.Context, acc *Account) error {
	id, err := randID()
	if err != nil {
		return nil, err
	}

	dba := &dbAccount{
		ID:      id,
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
		if err = db.saveAccount(dba, nil); err != nil {
			db.db.Del(accountByKeyIDTable, kidB)
			return err
		}
		return nil
	}
}

// UpdateAccount imlements the AcmeDB.UpdateAccount interface.
func (db *DB) UpdateAccount(ctx context.Context, acc *Account) error {
	kid, err := keyToID(dba.Key)
	if err != nil {
		return err
	}

	dba, err := db.db.getAccountByKeyID(ctx, kid)

	newdba := *dba
	newdba.Contact = acc.contact
	newdba.Status = acc.Status

	// If the status has changed to 'deactivated', then set deactivatedAt timestamp.
	if acc.Status == types.StatusDeactivated && dba.Status != types.Status.Deactivated {
		newdba.Deactivated = clock.Now()
	}

	return db.saveAccount(newdba, dba)
}

// getAccountByID retrieves the account with the given ID.
func (db *DB) getAccountByID(ctx context.Context, id string) (*dbAccount, error) {
	ab, err := db.db.Get(accountTable, []byte(id))
	if err != nil {
		if nosqlDB.IsErrNotFound(err) {
			return nil, MalformedErr(errors.Wrapf(err, "account %s not found", id))
		}
		return nil, ServerInternalErr(errors.Wrapf(err, "error loading account %s", id))
	}

	a := new(account)
	if err = json.Unmarshal(ab, a); err != nil {
		return nil, ServerInternalErr(errors.Wrap(err, "error unmarshaling account"))
	}
	return a, nil
}

// getAccountByKeyID retrieves Id associated with the given Kid.
func (db *DB) getAccountByKeyID(ctx context.Context, kid string) (*dbAccount, error) {
	id, err := db.db.Get(accountByKeyIDTable, []byte(kid))
	if err != nil {
		if nosqlDB.IsErrNotFound(err) {
			return nil, MalformedErr(errors.Wrapf(err, "account with key id %s not found", kid))
		}
		return nil, ServerInternalErr(errors.Wrapf(err, "error loading key-account index"))
	}
	return getAccountByID(db, string(id))
}
