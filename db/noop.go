package db

import (
	"crypto/x509"

	"github.com/pkg/errors"
)

// ErrNotImplemented is an error returned when an operation is Not Implemented.
var ErrNotImplemented = errors.Errorf("not implemented")

// NoopDB implements the DB interface with Noops
type NoopDB int

// Init noop
func (n *NoopDB) Init(c *Config) (AuthDB, error) {
	return n, nil
}

// IsRevoked noop
func (n *NoopDB) IsRevoked(sn string) (bool, error) {
	return false, nil
}

// Revoke returns a "NotImplemented" error.
func (n *NoopDB) Revoke(rci *RevokedCertificateInfo) error {
	return ErrNotImplemented
}

// StoreCertificate returns a "NotImplemented" error.
func (n *NoopDB) StoreCertificate(crt *x509.Certificate) error {
	return ErrNotImplemented
}

// UseToken returns a "NotImplemented" error.
func (n *NoopDB) UseToken(id, tok string) (bool, error) {
	return false, ErrNotImplemented
}

// Shutdown returns nil
func (n *NoopDB) Shutdown() error {
	return nil
}
