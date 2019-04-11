package db

import (
	"crypto/x509"
	"encoding/json"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/nosql"
)

var (
	revokedCertsTable = []byte("revoked_x509_certs")
	certsTable        = []byte("x509_certs")
)

// ErrAlreadyExists can be returned if the DB attempts to set a key that has
// been previously set.
var ErrAlreadyExists = errors.New("already exists")

// Config represents the JSON attributes used for configuring a step-ca DB.
type Config struct {
	Type string `json:"type"`
	Path string `json:"path"`
}

// AuthDB is an interface over an Authority DB client that implements a nosql.DB interface.
type AuthDB interface {
	IsRevoked(sn string) (bool, error)
	Revoke(rci *RevokedCertificateInfo) error
	StoreCertificate(crt *x509.Certificate) error
	Shutdown() error
}

// DB is a wrapper over the nosql.DB interface.
type DB struct {
	nosql.DB
}

// New returns a new database client that implements the AuthDB interface.
func New(c *Config) (AuthDB, error) {
	if c == nil {
		return new(NoopDB), nil
	}

	var db nosql.DB
	switch strings.ToLower(c.Type) {
	case "bbolt":
		db = &nosql.BoltDB{}
		if err := db.Open(c.Path); err != nil {
			return nil, err
		}
	default:
		return nil, errors.Errorf("unsupported db.type '%s'", c.Type)
	}

	tables := [][]byte{revokedCertsTable, certsTable}
	for _, b := range tables {
		if err := db.CreateTable(b); err != nil {
			return nil, errors.Wrapf(err, "error creating table %s",
				string(b))
		}
	}

	return &DB{db}, nil
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
	isRvkd, err := db.IsRevoked(rci.Serial)
	if err != nil {
		return err
	}
	if isRvkd {
		return ErrAlreadyExists
	}
	rcib, err := json.Marshal(rci)
	if err != nil {
		return errors.Wrap(err, "error marshaling revoked certificate info")
	}

	if err = db.Set(revokedCertsTable, []byte(rci.Serial), rcib); err != nil {
		return errors.Wrap(err, "database Set error")
	}
	return nil
}

// StoreCertificate stores a certificate PEM.
func (db *DB) StoreCertificate(crt *x509.Certificate) error {
	if err := db.Set(certsTable, []byte(crt.SerialNumber.String()), crt.Raw); err != nil {
		return errors.Wrap(err, "database Set error")
	}
	return nil
}

// Shutdown sends a shutdown message to the database.
func (db *DB) Shutdown() error {
	if err := db.Close(); err != nil {
		return errors.Wrap(err, "database shutdown error")
	}
	return nil
}
