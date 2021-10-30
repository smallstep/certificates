package nosql

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/nosql"
)

// Mutex for locking ordersByAccount index operations.
var ordersByAccountMux sync.Mutex

type dbOrder struct {
	ID               string            `json:"id"`
	AccountID        string            `json:"accountID"`
	ProvisionerID    string            `json:"provisionerID"`
	Identifiers      []acme.Identifier `json:"identifiers"`
	AuthorizationIDs []string          `json:"authorizationIDs"`
	Status           acme.Status       `json:"status"`
	NotBefore        time.Time         `json:"notBefore,omitempty"`
	NotAfter         time.Time         `json:"notAfter,omitempty"`
	CreatedAt        time.Time         `json:"createdAt"`
	ExpiresAt        time.Time         `json:"expiresAt,omitempty"`
	CertificateID    string            `json:"certificate,omitempty"`
	Error            *acme.Error       `json:"error,omitempty"`
}

func (a *dbOrder) clone() *dbOrder {
	b := *a
	return &b
}

// getDBOrder retrieves and unmarshals an ACME Order type from the database.
func (db *DB) getDBOrder(ctx context.Context, id string) (*dbOrder, error) {
	b, err := db.db.Get(orderTable, []byte(id))
	if nosql.IsErrNotFound(err) {
		return nil, acme.NewError(acme.ErrorMalformedType, "order %s not found", id)
	} else if err != nil {
		return nil, errors.Wrapf(err, "error loading order %s", id)
	}
	o := new(dbOrder)
	if err := json.Unmarshal(b, &o); err != nil {
		return nil, errors.Wrapf(err, "error unmarshaling order %s into dbOrder", id)
	}
	return o, nil
}

// GetOrder retrieves an ACME Order from the database.
func (db *DB) GetOrder(ctx context.Context, id string) (*acme.Order, error) {
	dbo, err := db.getDBOrder(ctx, id)
	if err != nil {
		return nil, err
	}

	o := &acme.Order{
		ID:               dbo.ID,
		AccountID:        dbo.AccountID,
		ProvisionerID:    dbo.ProvisionerID,
		CertificateID:    dbo.CertificateID,
		Status:           dbo.Status,
		ExpiresAt:        dbo.ExpiresAt,
		Identifiers:      dbo.Identifiers,
		NotBefore:        dbo.NotBefore,
		NotAfter:         dbo.NotAfter,
		AuthorizationIDs: dbo.AuthorizationIDs,
		Error:            dbo.Error,
	}

	return o, nil
}

// CreateOrder creates ACME Order resources and saves them to the DB.
func (db *DB) CreateOrder(ctx context.Context, o *acme.Order) error {
	var err error
	o.ID, err = randID()
	if err != nil {
		return err
	}

	now := clock.Now()
	dbo := &dbOrder{
		ID:               o.ID,
		AccountID:        o.AccountID,
		ProvisionerID:    o.ProvisionerID,
		Status:           o.Status,
		CreatedAt:        now,
		ExpiresAt:        o.ExpiresAt,
		Identifiers:      o.Identifiers,
		NotBefore:        o.NotBefore,
		NotAfter:         o.NotAfter,
		AuthorizationIDs: o.AuthorizationIDs,
	}
	if err := db.save(ctx, o.ID, dbo, nil, "order", orderTable); err != nil {
		return err
	}

	_, err = db.updateAddOrderIDs(ctx, o.AccountID, o.ID)
	if err != nil {
		return err
	}
	return nil
}

// UpdateOrder saves an updated ACME Order to the database.
func (db *DB) UpdateOrder(ctx context.Context, o *acme.Order) error {
	old, err := db.getDBOrder(ctx, o.ID)
	if err != nil {
		return err
	}

	nu := old.clone()

	nu.Status = o.Status
	nu.Error = o.Error
	nu.CertificateID = o.CertificateID
	return db.save(ctx, old.ID, nu, old, "order", orderTable)
}

func (db *DB) updateAddOrderIDs(ctx context.Context, accID string, addOids ...string) ([]string, error) {
	ordersByAccountMux.Lock()
	defer ordersByAccountMux.Unlock()

	var oldOids []string
	b, err := db.db.Get(ordersByAccountIDTable, []byte(accID))
	if err != nil {
		if !nosql.IsErrNotFound(err) {
			return nil, errors.Wrapf(err, "error loading orderIDs for account %s", accID)
		}
	} else {
		if err := json.Unmarshal(b, &oldOids); err != nil {
			return nil, errors.Wrapf(err, "error unmarshaling orderIDs for account %s", accID)
		}
	}

	// Remove any order that is not in PENDING state and update the stored list
	// before returning.
	//
	// According to RFC 8555:
	// The server SHOULD include pending orders and SHOULD NOT include orders
	// that are invalid in the array of URLs.
	pendOids := []string{}
	for _, oid := range oldOids {
		o, err := db.GetOrder(ctx, oid)
		if err != nil {
			return nil, acme.WrapErrorISE(err, "error loading order %s for account %s", oid, accID)
		}
		if err = o.UpdateStatus(ctx, db); err != nil {
			return nil, acme.WrapErrorISE(err, "error updating order %s for account %s", oid, accID)
		}
		if o.Status == acme.StatusPending {
			pendOids = append(pendOids, oid)
		}
	}
	pendOids = append(pendOids, addOids...)
	var (
		_old interface{} = oldOids
		_new interface{} = pendOids
	)
	switch {
	case len(oldOids) == 0 && len(pendOids) == 0:
		// If list has not changed from empty, then no need to write the DB.
		return []string{}, nil
	case len(oldOids) == 0:
		_old = nil
	case len(pendOids) == 0:
		_new = nil
	}
	if err = db.save(ctx, accID, _new, _old, "orderIDsByAccountID", ordersByAccountIDTable); err != nil {
		// Delete all orders that may have been previously stored if orderIDsByAccountID update fails.
		for _, oid := range addOids {
			// Ignore error from delete -- we tried our best.
			// TODO when we have logging w/ request ID tracking, logging this error.
			db.db.Del(orderTable, []byte(oid))
		}
		return nil, errors.Wrapf(err, "error saving orderIDs index for account %s", accID)
	}
	return pendOids, nil
}

// GetOrdersByAccountID returns a list of order IDs owned by the account.
func (db *DB) GetOrdersByAccountID(ctx context.Context, accID string) ([]string, error) {
	return db.updateAddOrderIDs(ctx, accID)
}
