package sql

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/db/sql/mysql"
	"github.com/smallstep/certificates/db/sql/sql"
)

// Option is just a wrapper over database.Option.
type Option = sql.SQLOption

// DB is just a wrapper over database.DB.
type DB = sql.DB

var (
	// WithDatabase is a wrapper over database.WithDatabase.
	WithDatabase = sql.WithDatabase
	// IsErrNotFound is a wrapper over database.IsErrNotFound.
	IsErrNotFound = sql.IsErrNotFound
	// IsErrOpNotSupported is a wrapper over database.IsErrOpNotSupported.
	IsErrOpNotSupported = sql.IsErrOpNotSupported

	// Available db driver types. //

	// MySQLDriver indicates the default MySQL database.
	MySQLDriver = "mysql"
)

// New returns a database with the given driver.
func New(driver, dataSourceName string, opt ...Option) (db sql.DB, err error) {
	switch strings.ToLower(driver) {
	case MySQLDriver:
		db = &mysql.DB{}
	default:
		return nil, errors.Errorf("%s sql not supported", driver)
	}
	err = db.Open(dataSourceName, opt...)
	return
}
