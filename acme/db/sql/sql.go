package sql

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"time"

	"github.com/pkg/errors"
	sqlDB "github.com/smallstep/certificates/db/sql"
	"go.step.sm/crypto/randutil"
)

var (
	accountTable            = []byte("acme_accounts")
	accountByKeyIDTable     = []byte("acme_keyID_accountID_index")
	authzTable              = []byte("acme_authzs")
	challengeTable          = []byte("acme_challenges")
	nonceTable              = []byte("nonces")
	orderTable              = []byte("acme_orders")
	ordersByAccountIDTable  = []byte("acme_account_orders_index")
	ACMEcertSANsTable       = []byte("acme_sans")
	ACMEcertExtensionsTable = []byte("acme_extensions")
	certTable               = []byte("acme_certs")
)

// DB is a struct that implements the AcmeDB interface.
type DB struct {
	db sqlDB.DB
}

// New configures and returns a new ACME DB backend implemented using a sql DB.
func New(db sqlDB.DB) (*DB, error) {
	tables := [][]byte{accountTable, accountByKeyIDTable, authzTable,
		challengeTable, nonceTable, orderTable, ordersByAccountIDTable}
	for _, b := range tables {
		if err := db.CreateTable(b); err != nil {
			return nil, errors.Wrapf(err, "error creating table %s",
				string(b))
		}
	}
	// Separate schema for Certs Table so that queries on these tables can be done in the future.
	if err := db.CreateX509CertificateTable(certTable); err != nil {
		return nil, errors.Wrapf(err, "error creating table %s",
			string(certTable))
	}
	if err := db.CreateX509CertificateSansTable(ACMEcertSANsTable, []byte("ACMESans"), certTable); err != nil {
		return nil, errors.Wrapf(err, "error creating table %s",
			string(ACMEcertSANsTable))
	}
	if err := db.CreateX509CertificateExtensionsTable(ACMEcertExtensionsTable, []byte("ACMEExtensions"), certTable); err != nil {
		return nil, errors.Wrapf(err, "error creating table %s",
			string(ACMEcertSANsTable))
	}

	return &DB{db}, nil
}

// save writes the new data to the database, overwriting the old data if it
// existed.
func (db *DB) save(ctx context.Context, id string, nu interface{}, old interface{}, typ string, table []byte) error {
	var (
		err  error
		newB []byte
	)
	if nu == nil {
		newB = nil
	} else {
		newB, err = json.Marshal(nu)
		if err != nil {
			return errors.Wrapf(err, "error marshaling acme type: %s, value: %v", typ, nu)
		}
	}
	var oldB []byte
	if old == nil {
		oldB = nil
	} else {
		oldB, err = json.Marshal(old)
		if err != nil {
			return errors.Wrapf(err, "error marshaling acme type: %s, value: %v", typ, old)
		}
	}
	_, swapped, err := db.db.CmpAndSwap(table, []byte(id), oldB, newB)
	switch {
	case err != nil:
		return errors.Wrapf(err, "error saving acme %s", typ)
	case !swapped:
		return errors.Errorf("error saving acme %s; changed since last read", typ)
	default:
		return nil
	}
}

// saveACMECertificate writes the new data to the database, overwriting the old data if it
// existed.
func (db *DB) saveACMECertificate(ctx context.Context, key []byte, cert *x509.Certificate, nu interface{}, old interface{}, typ string, table, extensionBucket, dnsNameBucket []byte, provisionerName string) error {
	var (
		err  error
		newB []byte
	)
	if nu == nil {
		newB = nil
	} else {
		newB, err = json.Marshal(nu)
		if err != nil {
			return errors.Wrapf(err, "error marshaling acme type: %s, value: %v", typ, nu)
		}
	}
	var oldB []byte
	if old == nil {
		oldB = nil
	} else {
		oldB, err = json.Marshal(old)
		if err != nil {
			return errors.Wrapf(err, "error marshaling acme type: %s, value: %v", typ, old)
		}
	}
	_, swapped, err := db.db.CmpAndSwapACMECertificate(table, key, cert, oldB, newB, extensionBucket, dnsNameBucket, provisionerName)
	switch {
	case err != nil:
		return errors.Wrapf(err, "error saving acme %s", typ)
	case !swapped:
		return errors.Errorf("error saving acme %s; changed since last read", typ)
	default:
		return nil
	}
}

var idLen = 32

func randID() (val string, err error) {
	val, err = randutil.Alphanumeric(idLen)
	if err != nil {
		return "", errors.Wrap(err, "error generating random alphanumeric ID")
	}
	return val, nil
}

// Clock that returns time in UTC rounded to seconds.
type Clock struct{}

// Now returns the UTC time rounded to seconds.
func (c *Clock) Now() time.Time {
	return time.Now().UTC().Truncate(time.Second)
}

var clock = new(Clock)
