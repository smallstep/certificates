package scep

import "crypto/x509"

type DB interface {
	StoreCertificate(crt *x509.Certificate) error
}
