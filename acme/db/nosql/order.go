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
	ID             string            `json:"id"`
	AccountID      string            `json:"accountID"`
	ProvisionerID  string            `json:"provisionerID"`
	Created        time.Time         `json:"created"`
	Expires        time.Time         `json:"expires,omitempty"`
	Status         acme.Status       `json:"status"`
	Identifiers    []acme.Identifier `json:"identifiers"`
	NotBefore      time.Time         `json:"notBefore,omitempty"`
	NotAfter       time.Time         `json:"notAfter,omitempty"`
	Error          *acme.Error       `json:"error,omitempty"`
	Authorizations []string          `json:"authorizations"`
	CertificateID  string            `json:"certificate,omitempty"`
}

func (a *dbOrder) clone() *dbOrder {
	b := *a
	return &b
}

// getDBOrder retrieves and unmarshals an ACME Order type from the database.
func (db *DB) getDBOrder(ctx context.Context, id string) (*dbOrder, error) {
	b, err := db.db.Get(orderTable, []byte(id))
	if nosql.IsErrNotFound(err) {
		return nil, acme.WrapError(acme.ErrorMalformedType, err, "order %s not found", id)
	} else if err != nil {
		return nil, errors.Wrapf(err, "error loading order %s", id)
	}
	o := new(dbOrder)
	if err := json.Unmarshal(b, &o); err != nil {
		return nil, errors.Wrap(err, "error unmarshaling order")
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
		Status:           dbo.Status,
		ExpiresAt:        dbo.Expires,
		Identifiers:      dbo.Identifiers,
		NotBefore:        dbo.NotBefore,
		NotAfter:         dbo.NotAfter,
		AuthorizationIDs: dbo.Authorizations,
		ID:               dbo.ID,
		ProvisionerID:    dbo.ProvisionerID,
		CertificateID:    dbo.CertificateID,
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
		ID:             o.ID,
		AccountID:      o.AccountID,
		ProvisionerID:  o.ProvisionerID,
		Created:        now,
		Status:         acme.StatusPending,
		Expires:        o.ExpiresAt,
		Identifiers:    o.Identifiers,
		NotBefore:      o.NotBefore,
		NotAfter:       o.NotBefore,
		Authorizations: o.AuthorizationIDs,
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

type orderIDsByAccount struct{}

func (db *DB) updateAddOrderIDs(ctx context.Context, accID string, addOids ...string) ([]string, error) {
	ordersByAccountMux.Lock()
	defer ordersByAccountMux.Unlock()

	b, err := db.db.Get(ordersByAccountIDTable, []byte(accID))
	if err != nil {
		if nosql.IsErrNotFound(err) {
			return []string{}, nil
		}
		return nil, errors.Wrapf(err, "error loading orderIDs for account %s", accID)
	}
	var oids []string
	if err := json.Unmarshal(b, &oids); err != nil {
		return nil, errors.Wrapf(err, "error unmarshaling orderIDs for account %s", accID)
	}

	// Remove any order that is not in PENDING state and update the stored list
	// before returning.
	//
	// According to RFC 8555:
	// The server SHOULD include pending orders and SHOULD NOT include orders
	// that are invalid in the array of URLs.
	pendOids := []string{}
	for _, oid := range oids {
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
	if len(oids) == 0 {
		oids = nil
	}
	if err = db.save(ctx, accID, pendOids, oids, "orderIDsByAccountID", ordersByAccountIDTable); err != nil {
		// Delete all orders that may have been previously stored if orderIDsByAccountID update fails.
		for _, oid := range addOids {
			db.db.Del(orderTable, []byte(oid))
		}
		return nil, errors.Wrap(err, "error saving OrderIDsByAccountID index")
	}
	return pendOids, nil
}

// GetOrdersByAccountID returns a list of order IDs owned by the account.
func (db *DB) GetOrdersByAccountID(ctx context.Context, accID string) ([]string, error) {
	return db.updateAddOrderIDs(ctx, accID)
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
