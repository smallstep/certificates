package nosql

import (
	"context"
	"encoding/json"

	"github.com/pkg/errors"
	nosqlDB "github.com/smallstep/nosql"
)

var (
	accountTable           = []byte("acme_accounts")
	accountByKeyIDTable    = []byte("acme_keyID_accountID_index")
	authzTable             = []byte("acme_authzs")
	challengeTable         = []byte("acme_challenges")
	nonceTable             = []byte("nonces")
	orderTable             = []byte("acme_orders")
	ordersByAccountIDTable = []byte("acme_account_orders_index")
	certTable              = []byte("acme_certs")
)

// DB is a struct that implements the AcmeDB interface.
type DB struct {
	db nosqlDB.DB
}

// save writes the new data to the database, overwriting the old data if it
// existed.
func (db *DB) save(ctx context.Context, id string, nu interface{}, old interface{}, typ string, table []byte) error {
	newB, err := json.Marshal(nu)
	if err != nil {
		return ServerInternalErr(errors.Wrapf(err,
			"error marshaling new acme %s", typ))
	}
	var oldB []byte
	if old == nil {
		oldB = nil
	} else {
		oldB, err = json.Marshal(old)
		if err != nil {
			return ServerInternalErr(errors.Wrapf(err,
				"error marshaling old acme %s", typ))
		}
	}

	_, swapped, err := db.CmpAndSwap(table, []byte(id), oldB, newB)
	switch {
	case err != nil:
		return ServerInternalErr(errors.Wrapf(err, "error saving acme %s", typ))
	case !swapped:
		return ServerInternalErr(errors.Errorf("error saving acme %s; "+
			"changed since last read", typ))
	default:
		return nil
	}
}
