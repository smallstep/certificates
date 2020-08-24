package acme

import (
	"context"
	"encoding/json"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/nosql"
	"go.step.sm/crypto/jose"
)

// Account is a subset of the internal account type containing only those
// attributes required for responses in the ACME protocol.
type Account struct {
	Contact []string         `json:"contact,omitempty"`
	Status  string           `json:"status"`
	Orders  string           `json:"orders"`
	ID      string           `json:"-"`
	Key     *jose.JSONWebKey `json:"-"`
}

// ToLog enables response logging.
func (a *Account) ToLog() (interface{}, error) {
	b, err := json.Marshal(a)
	if err != nil {
		return nil, ServerInternalErr(errors.Wrap(err, "error marshaling account for logging"))
	}
	return string(b), nil
}

// GetID returns the account ID.
func (a *Account) GetID() string {
	return a.ID
}

// GetKey returns the JWK associated with the account.
func (a *Account) GetKey() *jose.JSONWebKey {
	return a.Key
}

// IsValid returns true if the Account is valid.
func (a *Account) IsValid() bool {
	return a.Status == StatusValid
}

// AccountOptions are the options needed to create a new ACME account.
type AccountOptions struct {
	Key     *jose.JSONWebKey
	Contact []string
}

// account represents an ACME account.
type account struct {
	ID          string           `json:"id"`
	Created     time.Time        `json:"created"`
	Deactivated time.Time        `json:"deactivated"`
	Key         *jose.JSONWebKey `json:"key"`
	Contact     []string         `json:"contact,omitempty"`
	Status      string           `json:"status"`
}

// newAccount returns a new acme account type.
func newAccount(db nosql.DB, ops AccountOptions) (*account, error) {
	id, err := randID()
	if err != nil {
		return nil, err
	}

	a := &account{
		ID:      id,
		Key:     ops.Key,
		Contact: ops.Contact,
		Status:  "valid",
		Created: clock.Now(),
	}
	return a, a.saveNew(db)
}

// toACME converts the internal Account type into the public acmeAccount
// type for presentation in the ACME protocol.
func (a *account) toACME(ctx context.Context, db nosql.DB, dir *directory) (*Account, error) {
	return &Account{
		Status:  a.Status,
		Contact: a.Contact,
		Orders:  dir.getLink(ctx, OrdersByAccountLink, true, a.ID),
		Key:     a.Key,
		ID:      a.ID,
	}, nil
}

// save writes the Account to the DB.
// If the account is new then the necessary indices will be created.
// Else, the account in the DB will be updated.
func (a *account) saveNew(db nosql.DB) error {
	kid, err := keyToID(a.Key)
	if err != nil {
		return err
	}
	kidB := []byte(kid)

	// Set the jwkID -> acme account ID index
	_, swapped, err := db.CmpAndSwap(accountByKeyIDTable, kidB, nil, []byte(a.ID))
	switch {
	case err != nil:
		return ServerInternalErr(errors.Wrap(err, "error setting key-id to account-id index"))
	case !swapped:
		return ServerInternalErr(errors.Errorf("key-id to account-id index already exists"))
	default:
		if err = a.save(db, nil); err != nil {
			db.Del(accountByKeyIDTable, kidB)
			return err
		}
		return nil
	}
}

func (a *account) save(db nosql.DB, old *account) error {
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

	b, err := json.Marshal(*a)
	if err != nil {
		return errors.Wrap(err, "error marshaling new account object")
	}
	// Set the Account
	_, swapped, err := db.CmpAndSwap(accountTable, []byte(a.ID), oldB, b)
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

// update updates the acme account object stored in the database if,
// and only if, the account has not changed since the last read.
func (a *account) update(db nosql.DB, contact []string) (*account, error) {
	b := *a
	b.Contact = contact
	if err := b.save(db, a); err != nil {
		return nil, err
	}
	return &b, nil
}

// deactivate deactivates the acme account.
func (a *account) deactivate(db nosql.DB) (*account, error) {
	b := *a
	b.Status = StatusDeactivated
	b.Deactivated = clock.Now()
	if err := b.save(db, a); err != nil {
		return nil, err
	}
	return &b, nil
}

// getAccountByID retrieves the account with the given ID.
func getAccountByID(db nosql.DB, id string) (*account, error) {
	ab, err := db.Get(accountTable, []byte(id))
	if err != nil {
		if nosql.IsErrNotFound(err) {
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
func getAccountByKeyID(db nosql.DB, kid string) (*account, error) {
	id, err := db.Get(accountByKeyIDTable, []byte(kid))
	if err != nil {
		if nosql.IsErrNotFound(err) {
			return nil, MalformedErr(errors.Wrapf(err, "account with key id %s not found", kid))
		}
		return nil, ServerInternalErr(errors.Wrapf(err, "error loading key-account index"))
	}
	return getAccountByID(db, string(id))
}

// getOrderIDsByAccount retrieves a list of Order IDs that were created by the
// account.
func getOrderIDsByAccount(db nosql.DB, accID string) ([]string, error) {
	b, err := db.Get(ordersByAccountIDTable, []byte(accID))
	if err != nil {
		if nosql.IsErrNotFound(err) {
			return []string{}, nil
		}
		return nil, ServerInternalErr(errors.Wrapf(err, "error loading orderIDs for account %s", accID))
	}
	var oids []string
	if err := json.Unmarshal(b, &oids); err != nil {
		return nil, ServerInternalErr(errors.Wrapf(err, "error unmarshaling orderIDs for account %s", accID))
	}

	// Remove any order that is not in PENDING state and update the stored list
	// before returning.
	//
	// According to RFC 8555:
	// The server SHOULD include pending orders and SHOULD NOT include orders
	// that are invalid in the array of URLs.
	pendOids := []string{}
	for _, oid := range oids {
		o, err := getOrder(db, oid)
		if err != nil {
			return nil, ServerInternalErr(errors.Wrapf(err, "error loading order %s for account %s", oid, accID))
		}
		if o, err = o.updateStatus(db); err != nil {
			return nil, ServerInternalErr(errors.Wrapf(err, "error updating order %s for account %s", oid, accID))
		}
		if o.Status == StatusPending {
			pendOids = append(pendOids, oid)
		}
	}
	// If the number of pending orders is less than the number of orders in the
	// list, then update the pending order list.
	if len(pendOids) != len(oids) {
		if err = orderIDs(pendOids).save(db, oids, accID); err != nil {
			return nil, ServerInternalErr(errors.Wrapf(err, "error storing orderIDs as part of getOrderIDsByAccount logic: "+
				"len(orderIDs) = %d", len(pendOids)))
		}
	}

	return pendOids, nil
}
