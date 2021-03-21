package scep

import (
	"crypto/x509"

	"github.com/pkg/errors"
)

// CertOptions options with which to create and store a cert object.
type CertOptions struct {
	Leaf          *x509.Certificate
	Intermediates []*x509.Certificate
}

func newCert(db DB, ops CertOptions) error {
	err := db.StoreCertificate(ops.Leaf)
	if err != nil {
		errors.Wrap(err, "error while storing certificate")
	}
	return nil
}
