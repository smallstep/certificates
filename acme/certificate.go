package acme

import (
	"context"
	"crypto/x509"
	"encoding/pem"
)

// Certificate options with which to create and store a cert object.
type Certificate struct {
	ID            string
	AccountID     string
	OrderID       string
	Leaf          *x509.Certificate
	Intermediates []*x509.Certificate
}

// ToACME encodes the entire X509 chain into a PEM list.
func (cert *Certificate) ToACME(ctx context.Context) ([]byte, error) {
	var ret []byte
	for _, c := range append([]*x509.Certificate{cert.Leaf}, cert.Intermediates...) {
		ret = append(ret, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.Raw,
		})...)
	}
	return ret, nil
}
