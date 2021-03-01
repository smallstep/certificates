package nosql

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/nosql"
)

type dbCert struct {
	ID            string    `json:"id"`
	Created       time.Time `json:"created"`
	AccountID     string    `json:"accountID"`
	OrderID       string    `json:"orderID"`
	Leaf          []byte    `json:"leaf"`
	Intermediates []byte    `json:"intermediates"`
}

// CreateCertificate creates and stores an ACME certificate type.
func (db *DB) CreateCertificate(ctx context.Context, cert *acme.Certificate) error {
	var err error
	cert.ID, err = randID()
	if err != nil {
		return err
	}

	leaf := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Leaf.Raw,
	})
	var intermediates []byte
	for _, cert := range cert.Intermediates {
		intermediates = append(intermediates, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})...)
	}

	dbch := &dbCert{
		ID:            cert.ID,
		AccountID:     cert.AccountID,
		OrderID:       cert.OrderID,
		Leaf:          leaf,
		Intermediates: intermediates,
		Created:       time.Now().UTC(),
	}
	return db.save(ctx, cert.ID, dbch, nil, "certificate", certTable)
}

// GetCertificate retrieves and unmarshals an ACME certificate type from the
// datastore.
func (db *DB) GetCertificate(ctx context.Context, id string) (*acme.Certificate, error) {
	b, err := db.db.Get(certTable, []byte(id))
	if nosql.IsErrNotFound(err) {
		return nil, errors.Wrapf(err, "certificate %s not found", id)
	} else if err != nil {
		return nil, errors.Wrap(err, "error loading certificate")
	}
	dbC := new(dbCert)
	if err := json.Unmarshal(b, dbC); err != nil {
		return nil, errors.Wrap(err, "error unmarshaling certificate")
	}

	leaf, err := parseCert(dbC.Leaf)
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing leaf of ACME Certificate with ID '%s'", id)
	}

	intermediates, err := parseBundle(dbC.Intermediates)
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing intermediate bundle of ACME Certificate with ID '%s'", id)
	}

	return &acme.Certificate{
		ID:            dbC.ID,
		AccountID:     dbC.AccountID,
		OrderID:       dbC.OrderID,
		Leaf:          leaf,
		Intermediates: intermediates,
	}, nil
}

func parseCert(b []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(b)
	if block == nil || len(rest) > 0 {
		return nil, errors.New("error decoding PEM block: contains unexpected data")
	}
	if block.Type != "CERTIFICATE" {
		return nil, errors.New("error decoding PEM: block is not a certificate bundle")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing x509 certificate")
	}
	return cert, nil
}

func parseBundle(b []byte) ([]*x509.Certificate, error) {
	var (
		err    error
		block  *pem.Block
		bundle []*x509.Certificate
	)
	for len(b) > 0 {
		block, b = pem.Decode(b)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, errors.New("error decoding PEM: data contains block that is not a certificate")
		}
		var crt *x509.Certificate
		crt, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.Wrapf(err, "error parsing x509 certificate")
		}
		bundle = append(bundle, crt)
	}
	if len(b) > 0 {
		return nil, errors.New("error decoding PEM: unexpected data")
	}
	return bundle, nil

}
