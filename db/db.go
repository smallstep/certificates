package db

import (
	"crypto/x509"
	"encoding/json"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/nosql"
	"github.com/smallstep/nosql/database"
)

var (
	certsTable        = []byte("x509_certs")
	revokedCertsTable = []byte("revoked_x509_certs")
	usedOTTTable      = []byte("used_ott")
)

// ErrAlreadyExists can be returned if the DB attempts to set a key that has
// been previously set.
var ErrAlreadyExists = errors.New("already exists")

// Config represents the JSON attributes used for configuring a step-ca DB.
type Config struct {
	Type       string `json:"type"`
	DataSource string `json:"dataSource"`
	ValueDir   string `json:"valueDir,omitempty"`
	Database   string `json:"database,omitempty"`
}

// AuthDB is an interface over an Authority DB client that implements a nosql.DB interface.
type AuthDB interface {
	IsRevoked(sn string) (bool, error)
	Revoke(rci *RevokedCertificateInfo) error
	StoreCertificate(crt *x509.Certificate) error
	UseToken(id, tok string) (bool, error)
	Shutdown() error
}

// DB is a wrapper over the nosql.DB interface.
type DB struct {
	nosql.DB
	isUp bool
}

// New returns a new database client that implements the AuthDB interface.
func New(c *Config) (AuthDB, error) {
	if c == nil {
		return newSimpleDB(c)
	}

	db, err := nosql.New(c.Type, c.DataSource, nosql.WithDatabase(c.Database),
		nosql.WithValueDir(c.ValueDir))
	if err != nil {
		return nil, errors.Wrapf(err, "Error opening database of Type %s with source %s", c.Type, c.DataSource)
	}

	tables := [][]byte{revokedCertsTable, certsTable, usedOTTTable}
	for _, b := range tables {
		if err := db.CreateTable(b); err != nil {
			return nil, errors.Wrapf(err, "error creating table %s",
				string(b))
		}
	}

	return &DB{db, true}, nil
}

// RevokedCertificateInfo contains information regarding the certificate
// revocation action.
type RevokedCertificateInfo struct {
	Serial        string
	ProvisionerID string
	ReasonCode    int
	Reason        string
	RevokedAt     time.Time
	TokenID       string
	MTLS          bool
}

// IsRevoked returns whether or not a certificate with the given identifier
// has been revoked.
// In the case of an X509 Certificate the `id` should be the Serial Number of
// the Certificate.
func (db *DB) IsRevoked(sn string) (bool, error) {
	// If the DB is nil then act as pass through.
	if db == nil {
		return false, nil
	}

	// If the error is `Not Found` then the certificate has not been revoked.
	// Any other error should be propagated to the caller.
	if _, err := db.Get(revokedCertsTable, []byte(sn)); err != nil {
		if nosql.IsErrNotFound(err) {
			return false, nil
		}
		return false, errors.Wrap(err, "error checking revocation bucket")
	}

	// This certificate has been revoked.
	return true, nil
}

// Revoke adds a certificate to the revocation table.
func (db *DB) Revoke(rci *RevokedCertificateInfo) error {
	rcib, err := json.Marshal(rci)
	if err != nil {
		return errors.Wrap(err, "error marshaling revoked certificate info")
	}

	_, swapped, err := db.CmpAndSwap(revokedCertsTable, []byte(rci.Serial), nil, rcib)
	switch {
	case err != nil:
		return errors.Wrap(err, "error AuthDB CmpAndSwap")
	case !swapped:
		return ErrAlreadyExists
	default:
		return nil
	}
}

// StoreCertificate stores a certificate PEM.
func (db *DB) StoreCertificate(crt *x509.Certificate) error {
	if err := db.Set(certsTable, []byte(crt.SerialNumber.String()), crt.Raw); err != nil {
		return errors.Wrap(err, "database Set error")
	}
	return nil
}

// UseToken returns true if we were able to successfully store the token for
// for the first time, false otherwise.
func (db *DB) UseToken(id, tok string) (bool, error) {
	_, swapped, err := db.CmpAndSwap(usedOTTTable, []byte(id), nil, []byte(tok))
	if err != nil {
		return false, errors.Wrapf(err, "error storing used token %s/%s",
			string(usedOTTTable), id)
	}
	return swapped, nil
}

// Shutdown sends a shutdown message to the database.
func (db *DB) Shutdown() error {
	if db.isUp {
		if err := db.Close(); err != nil {
			return errors.Wrap(err, "database shutdown error")
		}
		db.isUp = false
	}
	return nil
}

// MockNoSQLDB //
type MockNoSQLDB struct {
	Err          error
	Ret1, Ret2   interface{}
	MGet         func(bucket, key []byte) ([]byte, error)
	MSet         func(bucket, key, value []byte) error
	MOpen        func(dataSourceName string, opt ...database.Option) error
	MClose       func() error
	MCreateTable func(bucket []byte) error
	MDeleteTable func(bucket []byte) error
	MDel         func(bucket, key []byte) error
	MList        func(bucket []byte) ([]*database.Entry, error)
	MUpdate      func(tx *database.Tx) error
	MCmpAndSwap  func(bucket, key, old, newval []byte) ([]byte, bool, error)
}

// CmpAndSwap mock
func (m *MockNoSQLDB) CmpAndSwap(bucket, key, old, newval []byte) ([]byte, bool, error) {
	if m.MCmpAndSwap != nil {
		return m.MCmpAndSwap(bucket, key, old, newval)
	}
	if m.Ret1 == nil {
		return nil, false, m.Err
	}
	return m.Ret1.([]byte), m.Ret2.(bool), m.Err
}

// Get mock
func (m *MockNoSQLDB) Get(bucket, key []byte) ([]byte, error) {
	if m.MGet != nil {
		return m.MGet(bucket, key)
	}
	if m.Ret1 == nil {
		return nil, m.Err
	}
	return m.Ret1.([]byte), m.Err
}

// Set mock
func (m *MockNoSQLDB) Set(bucket, key, value []byte) error {
	if m.MSet != nil {
		return m.MSet(bucket, key, value)
	}
	return m.Err
}

// Open mock
func (m *MockNoSQLDB) Open(dataSourceName string, opt ...database.Option) error {
	if m.MOpen != nil {
		return m.MOpen(dataSourceName, opt...)
	}
	return m.Err
}

// Close mock
func (m *MockNoSQLDB) Close() error {
	if m.MClose != nil {
		return m.MClose()
	}
	return m.Err
}

// CreateTable mock
func (m *MockNoSQLDB) CreateTable(bucket []byte) error {
	if m.MCreateTable != nil {
		return m.MCreateTable(bucket)
	}
	return m.Err
}

// DeleteTable mock
func (m *MockNoSQLDB) DeleteTable(bucket []byte) error {
	if m.MDeleteTable != nil {
		return m.MDeleteTable(bucket)
	}
	return m.Err
}

// Del mock
func (m *MockNoSQLDB) Del(bucket, key []byte) error {
	if m.MDel != nil {
		return m.MDel(bucket, key)
	}
	return m.Err
}

// List mock
func (m *MockNoSQLDB) List(bucket []byte) ([]*database.Entry, error) {
	if m.MList != nil {
		return m.MList(bucket)
	}
	return m.Ret1.([]*database.Entry), m.Err
}

// Update mock
func (m *MockNoSQLDB) Update(tx *database.Tx) error {
	if m.MUpdate != nil {
		return m.MUpdate(tx)
	}
	return m.Err
}
