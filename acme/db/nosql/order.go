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

var defaultOrderExpiry = time.Hour * 24

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
	Error          *Error            `json:"error,omitempty"`
	Authorizations []string          `json:"authorizations"`
	Certificate    string            `json:"certificate,omitempty"`
}

// getDBOrder retrieves and unmarshals an ACME Order type from the database.
func (db *DB) getDBOrder(id string) (*dbOrder, error) {
	b, err := db.db.Get(orderTable, []byte(id))
	if nosql.IsErrNotFound(err) {
		return nil, errors.Wrapf(err, "order %s not found", id)
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
	dbo, err := db.getDBOrder(id)

	azs := make([]string, len(dbo.Authorizations))
	for i, aid := range dbo.Authorizations {
		azs[i] = dir.getLink(ctx, AuthzLink, true, aid)
	}
	o := &acme.Order{
		Status:         dbo.Status,
		Expires:        dbo.Expires.Format(time.RFC3339),
		Identifiers:    dbo.Identifiers,
		NotBefore:      dbo.NotBefore.Format(time.RFC3339),
		NotAfter:       dbo.NotAfter.Format(time.RFC3339),
		Authorizations: azs,
		FinalizeURL:    dir.getLink(ctx, FinalizeLink, true, o.ID),
		ID:             dbo.ID,
		ProvisionerID:  dbo.ProvisionerID,
	}

	if dbo.Certificate != "" {
		o.Certificate = dir.getLink(ctx, CertificateLink, true, o.Certificate)
	}
	return o, nil
}

// CreateOrder creates ACME Order resources and saves them to the DB.
func (db *DB) CreateOrder(ctx context.Context, o *acme.Order) error {
	o.ID, err = randID()
	if err != nil {
		return nil, err
	}

	now := clock.Now()
	dbo := &dbOrder{
		ID:             o.ID,
		AccountID:      o.AccountID,
		ProvisionerID:  o.ProvisionerID,
		Created:        now,
		Status:         StatusPending,
		Expires:        now.Add(defaultOrderExpiry),
		Identifiers:    o.Identifiers,
		NotBefore:      o.NotBefore,
		NotAfter:       o.NotBefore,
		Authorizations: o.AuthorizationIDs,
	}
	if err := db.save(ctx, o.ID, dbo, nil, orderTable); err != nil {
		return nil, err
	}

	var oidHelper = orderIDsByAccount{}
	_, err = oidHelper.addOrderID(db, o.AccountID, o.ID)
	if err != nil {
		return nil, err
	}
	return o, nil
}

type orderIDsByAccount struct{}

// addOrderID adds an order ID to a users index of in progress order IDs.
// This method will also cull any orders that are no longer in the `pending`
// state from the index before returning it.
func (oiba orderIDsByAccount) addOrderID(db nosql.DB, accID string, oid string) ([]string, error) {
	ordersByAccountMux.Lock()
	defer ordersByAccountMux.Unlock()

	// Update the "order IDs by account ID" index
	oids, err := oiba.unsafeGetOrderIDsByAccount(db, accID)
	if err != nil {
		return nil, err
	}
	newOids := append(oids, oid)
	if err = orderIDs(newOids).save(db, oids, accID); err != nil {
		// Delete the entire order if storing the index fails.
		db.Del(orderTable, []byte(oid))
		return nil, err
	}
	return newOids, nil
}

// unsafeGetOrderIDsByAccount retrieves a list of Order IDs that were created by the
// account.
func (oiba orderIDsByAccount) unsafeGetOrderIDsByAccount(db nosql.DB, accID string) ([]string, error) {
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
		if o, err = o.UpdateStatus(db); err != nil {
			return nil, ServerInternalErr(errors.Wrapf(err, "error updating order %s for account %s", oid, accID))
		}
		if o.Status == StatusPending {
			pendOids = append(pendOids, oid)
		}
	}
	// If the number of pending orders is less than the number of orders in the
	// list, then update the pending order list.
	if len(pendOids) != len(oids) {
		if err = orderIDs(pendOiUs).save(db, oids, accID); err != nil {
			return nil, ServerInternalErr(errors.Wrapf(err, "error storing orderIDs as part of getOrderIDsByAccount logic: "+
				"len(orderIDs) = %d", len(pendOids)))
		}
	}

	return pendOids, nil
}

type orderIDs []string

// save is used to update the list of orderIDs keyed by ACME account ID
// stored in the database.
//
// This method always converts empty lists to 'nil' when storing to the DB. We
// do this to avoid any confusion between an empty list and a nil value in the
// db.
func (oids orderIDs) save(db nosql.DB, old orderIDs, accID string) error {
	var (
		err  error
		oldb []byte
		newb []byte
	)
	if len(old) == 0 {
		oldb = nil
	} else {
		oldb, err = json.Marshal(old)
		if err != nil {
			return ServerInternalErr(errors.Wrap(err, "error marshaling old order IDs slice"))
		}
	}
	if len(oids) == 0 {
		newb = nil
	} else {
		newb, err = json.Marshal(oids)
		if err != nil {
			return ServerInternalErr(errors.Wrap(err, "error marshaling new order IDs slice"))
		}
	}
	_, swapped, err := db.CmpAndSwap(ordersByAccountIDTable, []byte(accID), oldb, newb)
	switch {
	case err != nil:
		return ServerInternalErr(errors.Wrapf(err, "error storing order IDs for account %s", accID))
	case !swapped:
		return ServerInternalErr(errors.Errorf("error storing order IDs "+
			"for account %s; order IDs changed since last read", accID))
	default:
		return nil
	}
}
