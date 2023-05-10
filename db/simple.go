package db

import (
	"crypto/x509"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/nosql/database"
	"golang.org/x/crypto/ssh"
)

// ErrNotImplemented is an error returned when an operation is Not Implemented.
var ErrNotImplemented = errors.Errorf("not implemented")

// SimpleDB is a barebones implementation of the DB interface. It is NOT an
// in memory implementation of the DB, but rather the bare minimum of
// functionality that the CA requires to operate securely.
type SimpleDB struct {
	usedTokens *sync.Map
}

func newSimpleDB(*Config) (*SimpleDB, error) {
	db := &SimpleDB{}
	db.usedTokens = new(sync.Map)
	return db, nil
}

// IsRevoked noop
func (s *SimpleDB) IsRevoked(string) (bool, error) {
	return false, nil
}

// IsSSHRevoked noop
func (s *SimpleDB) IsSSHRevoked(string) (bool, error) {
	return false, nil
}

// Revoke returns a "NotImplemented" error.
func (s *SimpleDB) Revoke(*RevokedCertificateInfo) error {
	return ErrNotImplemented
}

// GetRevokedCertificates returns a "NotImplemented" error.
func (s *SimpleDB) GetRevokedCertificates() (*[]RevokedCertificateInfo, error) {
	return nil, ErrNotImplemented
}

// GetCRL returns a "NotImplemented" error.
func (s *SimpleDB) GetCRL() (*CertificateRevocationListInfo, error) {
	return nil, ErrNotImplemented
}

// StoreCRL returns a "NotImplemented" error.
func (s *SimpleDB) StoreCRL(*CertificateRevocationListInfo) error {
	return ErrNotImplemented
}

// RevokeSSH returns a "NotImplemented" error.
func (s *SimpleDB) RevokeSSH(*RevokedCertificateInfo) error {
	return ErrNotImplemented
}

// GetCertificate returns a "NotImplemented" error.
func (s *SimpleDB) GetCertificate(string) (*x509.Certificate, error) {
	return nil, ErrNotImplemented
}

// StoreCertificate returns a "NotImplemented" error.
func (s *SimpleDB) StoreCertificate(*x509.Certificate) error {
	return ErrNotImplemented
}

type usedToken struct {
	UsedAt int64  `json:"ua,omitempty"`
	Token  string `json:"tok,omitempty"`
}

// UseToken returns a "NotImplemented" error.
func (s *SimpleDB) UseToken(id, tok string) (bool, error) {
	if _, ok := s.usedTokens.LoadOrStore(id, &usedToken{
		UsedAt: time.Now().Unix(),
		Token:  tok,
	}); ok {
		// Token already exists in DB.
		return false, nil
	}
	// Successfully stored token.
	return true, nil
}

// IsSSHHost returns a "NotImplemented" error.
func (s *SimpleDB) IsSSHHost(string) (bool, error) {
	return false, ErrNotImplemented
}

// StoreSSHCertificate returns a "NotImplemented" error.
func (s *SimpleDB) StoreSSHCertificate(*ssh.Certificate) error {
	return ErrNotImplemented
}

// GetSSHHostPrincipals returns a "NotImplemented" error.
func (s *SimpleDB) GetSSHHostPrincipals() ([]string, error) {
	return nil, ErrNotImplemented
}

// Shutdown returns nil
func (s *SimpleDB) Shutdown() error {
	return nil
}

// nosql.DB interface implementation //

// Open opens the database available with the given options.
func (s *SimpleDB) Open(string, ...database.Option) error {
	return ErrNotImplemented
}

// Close closes the current database.
func (s *SimpleDB) Close() error {
	return ErrNotImplemented
}

// Get returns the value stored in the given table/bucket and key.
func (s *SimpleDB) Get([]byte, []byte) ([]byte, error) {
	return nil, ErrNotImplemented
}

// Set sets the given value in the given table/bucket and key.
func (s *SimpleDB) Set([]byte, []byte, []byte) error {
	return ErrNotImplemented
}

// CmpAndSwap swaps the value at the given bucket and key if the current
// value is equivalent to the oldValue input. Returns 'true' if the
// swap was successful and 'false' otherwise.
func (s *SimpleDB) CmpAndSwap([]byte, []byte, []byte, []byte) ([]byte, bool, error) {
	return nil, false, ErrNotImplemented
}

// Del deletes the data in the given table/bucket and key.
func (s *SimpleDB) Del([]byte, []byte) error {
	return ErrNotImplemented
}

// List returns a list of all the entries in a given table/bucket.
func (s *SimpleDB) List([]byte) ([]*database.Entry, error) {
	return nil, ErrNotImplemented
}

// Update performs a transaction with multiple read-write commands.
func (s *SimpleDB) Update(*database.Tx) error {
	return ErrNotImplemented
}

// CreateTable creates a table or a bucket in the database.
func (s *SimpleDB) CreateTable([]byte) error {
	return ErrNotImplemented
}

// DeleteTable deletes a table or a bucket in the database.
func (s *SimpleDB) DeleteTable([]byte) error {
	return ErrNotImplemented
}
