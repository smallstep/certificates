package nosql

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"time"

	"github.com/pkg/errors"
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
func (db *DB) CreateCertificate(ctx context.Context, cert *Certificate) error {
	cert.id, err = randID()
	if err != nil {
		return err
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

	cert := &dbCert{
		ID:            cert.ID,
		AccountID:     cert.AccountID,
		OrderID:       cert.OrderID,
		Leaf:          leaf,
		Intermediates: intermediates,
		Created:       time.Now().UTC(),
	}
	return db.save(ctx, cert.ID, cert, nil, "certificate", certTable)
}

// GetCertificate retrieves and unmarshals an ACME certificate type from the
// datastore.
func (db *DB) GetCertificate(ctx context.Context, id string) (*Certificate, error) {
	b, err := db.db.Get(certTable, []byte(id))
	if nosql.IsErrNotFound(err) {
		return nil, MalformedErr(errors.Wrapf(err, "certificate %s not found", id))
	} else if err != nil {
		return nil, ServerInternalErr(errors.Wrap(err, "error loading certificate"))
	}
	var dbCert certificate
	if err := json.Unmarshal(b, &dbCert); err != nil {
		return nil, ServerInternalErr(errors.Wrap(err, "error unmarshaling certificate"))
	}

	leaf, err := parseCert(dbCert.Leaf)
	if err != nil {
		return nil, ServerInternalErr(errors.Wrapf("error parsing leaf of ACME Certificate with ID '%s'", id))
	}

	intermediates, err := parseBundle(dbCert.Intermediates)
	if err != nil {
		return nil, ServerInternalErr(errors.Wrapf("error parsing intermediate bundle of ACME Certificate with ID '%s'", id))
	}

	return &Certificate{
		ID:            dbCert.ID,
		AccountID:     dbCert.AccountID,
		OrderID:       dbCert.OrderID,
		Leaf:          leaf,
		Intermediates: intermediate,
	}
}

func parseCert(b []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(dbCert.Leaf)
	if block == nil || len(rest) > 0 {
		return nil, errors.New("error decoding PEM block: contains unexpected data")
	}
	if block.Type != "CERTIFICATE" {
		return nil, errors.New("error decoding PEM: block is not a certificate bundle")
	}
	var crt *x509.Certificate
	crt, err = x509.ParseCertificate(block.Bytes)
}

func parseBundle(b []byte) ([]*x509.Certificate, error) {
	var block *pem.Block
	var bundle []*x509.Certificate
	for len(b) > 0 {
		block, b = pem.Decode(b)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, errors.Errorf("error decoding PEM: file '%s' is not a certificate bundle", filename)
		}
		var crt *x509.Certificate
		crt, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.Wrapf(err, "error parsing %s", filename)
		}
		bundle = append(bundle, crt)
	}
	if len(b) > 0 {
		return nil, errors.Errorf("error decoding PEM: file '%s' contains unexpected data", filename)
	}
	return bundle, nil

}
