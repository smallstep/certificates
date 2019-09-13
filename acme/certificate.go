package acme

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/nosql"
)

type certificate struct {
	ID            string    `json:"id"`
	Created       time.Time `json:"created"`
	AccountID     string    `json:"accountID"`
	OrderID       string    `json:"orderID"`
	Leaf          []byte    `json:"leaf"`
	Intermediates []byte    `json:"intermediates"`
}

// CertOptions options with which to create and store a cert object.
type CertOptions struct {
	AccountID     string
	OrderID       string
	Leaf          *x509.Certificate
	Intermediates []*x509.Certificate
}

func newCert(db nosql.DB, ops CertOptions) (*certificate, error) {
	id, err := randID()
	if err != nil {
		return nil, err
	}

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
		AccountID:     ops.AccountID,
		OrderID:       ops.OrderID,
		Leaf:          leaf,
		Intermediates: intermediates,
		Created:       time.Now().UTC(),
	}
	certB, err := json.Marshal(cert)
	if err != nil {
		return nil, ServerInternalErr(errors.Wrap(err, "error marshaling certificate"))
	}

	_, swapped, err := db.CmpAndSwap(certTable, []byte(id), nil, certB)
	switch {
	case err != nil:
		return nil, ServerInternalErr(errors.Wrap(err, "error storing certificate"))
	case !swapped:
		return nil, ServerInternalErr(errors.New("error storing certificate; " +
			"value has changed since last read"))
	default:
		return cert, nil
	}
}

func (c *certificate) toACME(db nosql.DB, dir *directory) ([]byte, error) {
	return append(c.Leaf, c.Intermediates...), nil
}

func getCert(db nosql.DB, id string) (*certificate, error) {
	b, err := db.Get(certTable, []byte(id))
	if nosql.IsErrNotFound(err) {
		return nil, MalformedErr(errors.Wrapf(err, "certificate %s not found", id))
	} else if err != nil {
		return nil, ServerInternalErr(errors.Wrap(err, "error loading certificate"))
	}
	var cert certificate
	if err := json.Unmarshal(b, &cert); err != nil {
		return nil, ServerInternalErr(errors.Wrap(err, "error unmarshaling certificate"))
	}
	return &cert, nil
}
