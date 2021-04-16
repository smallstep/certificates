package acme

import (
	"crypto/x509"
)

// Certificate options with which to create and store a cert object.
type Certificate struct {
	ID            string
	AccountID     string
	OrderID       string
	Leaf          *x509.Certificate
	Intermediates []*x509.Certificate
}
