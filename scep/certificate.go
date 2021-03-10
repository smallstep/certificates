package scep

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/smallstep/nosql"
)

type certificate struct {
	ID            string    `json:"id"`
	Created       time.Time `json:"created"`
	Leaf          []byte    `json:"leaf"`
	Intermediates []byte    `json:"intermediates"`
}

// CertOptions options with which to create and store a cert object.
type CertOptions struct {
	Leaf          *x509.Certificate
	Intermediates []*x509.Certificate
}

func newCert(db nosql.DB, ops CertOptions) (*certificate, error) {

	// TODO: according to the RFC this should be IssuerAndSerialNumber,
	// but sscep seems to use just the serial number for getcert

	id := ops.Leaf.SerialNumber.String()

	leaf := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ops.Leaf.Raw,
	})
	var intermediates []byte
	for _, cert := range ops.Intermediates {
		intermediates = append(intermediates, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})...)
	}

	cert := &certificate{
		ID:            id,
		Leaf:          leaf,
		Intermediates: intermediates,
		Created:       time.Now().UTC(),
	}
	certB, err := json.Marshal(cert)
	if err != nil {
		return nil, fmt.Errorf("%w: error marshaling certificate", err)
	}

	_, swapped, err := db.CmpAndSwap(certTable, []byte(id), nil, certB)
	switch {
	case err != nil:
		return nil, fmt.Errorf("%w: error storing certificate", err)
	case !swapped:
		return nil, fmt.Errorf("error storing certificate; " +
			"value has changed since last read")
	default:
		return cert, nil
	}
}

// func getCert(db nosql.DB, id string) (*certificate, error) {
// 	b, err := db.Get(certTable, []byte(id))
// 	if nosql.IsErrNotFound(err) {
// 		return nil, fmt.Errorf("certificate %s not found", id)
// 	} else if err != nil {
// 		return nil, fmt.Errorf("error loading certificate")
// 	}
// 	var cert certificate
// 	if err := json.Unmarshal(b, &cert); err != nil {
// 		return nil, fmt.Errorf("%w: error unmarshaling certificate", err)
// 	}
// 	return &cert, nil
// }
