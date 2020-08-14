package acme

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/nosql"
	"github.com/smallstep/nosql/database"
	"go.step.sm/crypto/pemutil"
)

func defaultCertOps() (*CertOptions, error) {
	crt, err := pemutil.ReadCertificate("../authority/testdata/certs/foo.crt")
	if err != nil {
		return nil, err
	}
	inter, err := pemutil.ReadCertificate("../authority/testdata/certs/intermediate_ca.crt")
	if err != nil {
		return nil, err
	}
	root, err := pemutil.ReadCertificate("../authority/testdata/certs/root_ca.crt")
	if err != nil {
		return nil, err
	}
	return &CertOptions{
		AccountID:     "accID",
		OrderID:       "ordID",
		Leaf:          crt,
		Intermediates: []*x509.Certificate{inter, root},
	}, nil
}

func newcert() (*certificate, error) {
	ops, err := defaultCertOps()
	if err != nil {
		return nil, err
	}
	mockdb := &db.MockNoSQLDB{
		MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
			return nil, true, nil
		},
	}
	return newCert(mockdb, *ops)
}

func TestNewCert(t *testing.T) {
	type test struct {
		db  nosql.DB
		ops CertOptions
		err *Error
		id  *string
	}
	tests := map[string]func(t *testing.T) test{
		"fail/cmpAndSwap-error": func(t *testing.T) test {
			ops, err := defaultCertOps()
			assert.FatalError(t, err)
			return test{
				ops: *ops,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, certTable)
						assert.Equals(t, old, nil)
						return nil, false, errors.New("force")
					},
				},
				err: ServerInternalErr(errors.Errorf("error storing certificate: force")),
			}
		},
		"fail/cmpAndSwap-false": func(t *testing.T) test {
			ops, err := defaultCertOps()
			assert.FatalError(t, err)
			return test{
				ops: *ops,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, certTable)
						assert.Equals(t, old, nil)
						return nil, false, nil
					},
				},
				err: ServerInternalErr(errors.Errorf("error storing certificate; value has changed since last read")),
			}
		},
		"ok": func(t *testing.T) test {
			ops, err := defaultCertOps()
			assert.FatalError(t, err)
			var _id string
			id := &_id
			return test{
				ops: *ops,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, certTable)
						assert.Equals(t, old, nil)
						*id = string(key)
						return nil, true, nil
					},
				},
				id: id,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if cert, err := newCert(tc.db, tc.ops); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, cert.ID, *tc.id)
					assert.Equals(t, cert.AccountID, tc.ops.AccountID)
					assert.Equals(t, cert.OrderID, tc.ops.OrderID)

					leaf := pem.EncodeToMemory(&pem.Block{
						Type:  "CERTIFICATE",
						Bytes: tc.ops.Leaf.Raw,
					})
					var intermediates []byte
					for _, cert := range tc.ops.Intermediates {
						intermediates = append(intermediates, pem.EncodeToMemory(&pem.Block{
							Type:  "CERTIFICATE",
							Bytes: cert.Raw,
						})...)
					}
					assert.Equals(t, cert.Leaf, leaf)
					assert.Equals(t, cert.Intermediates, intermediates)

					assert.True(t, cert.Created.Before(time.Now().Add(time.Minute)))
					assert.True(t, cert.Created.After(time.Now().Add(-time.Minute)))
				}
			}
		})
	}
}

func TestGetCert(t *testing.T) {
	type test struct {
		id   string
		db   nosql.DB
		cert *certificate
		err  *Error
	}
	tests := map[string]func(t *testing.T) test{
		"fail/not-found": func(t *testing.T) test {
			cert, err := newcert()
			assert.FatalError(t, err)
			return test{
				cert: cert,
				id:   cert.ID,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, certTable)
						assert.Equals(t, key, []byte(cert.ID))
						return nil, database.ErrNotFound
					},
				},
				err: MalformedErr(errors.Errorf("certificate %s not found: not found", cert.ID)),
			}
		},
		"fail/db-error": func(t *testing.T) test {
			cert, err := newcert()
			assert.FatalError(t, err)
			return test{
				cert: cert,
				id:   cert.ID,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, certTable)
						assert.Equals(t, key, []byte(cert.ID))
						return nil, errors.New("force")
					},
				},
				err: ServerInternalErr(errors.New("error loading certificate: force")),
			}
		},
		"fail/unmarshal-error": func(t *testing.T) test {
			cert, err := newcert()
			assert.FatalError(t, err)
			return test{
				cert: cert,
				id:   cert.ID,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, certTable)
						assert.Equals(t, key, []byte(cert.ID))
						return nil, nil
					},
				},
				err: ServerInternalErr(errors.New("error unmarshaling certificate: unexpected end of JSON input")),
			}
		},
		"ok": func(t *testing.T) test {
			cert, err := newcert()
			assert.FatalError(t, err)
			b, err := json.Marshal(cert)
			assert.FatalError(t, err)
			return test{
				cert: cert,
				id:   cert.ID,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, certTable)
						assert.Equals(t, key, []byte(cert.ID))
						return b, nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if cert, err := getCert(tc.db, tc.id); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, tc.cert.ID, cert.ID)
					assert.Equals(t, tc.cert.AccountID, cert.AccountID)
					assert.Equals(t, tc.cert.OrderID, cert.OrderID)
					assert.Equals(t, tc.cert.Created, cert.Created)
					assert.Equals(t, tc.cert.Leaf, cert.Leaf)
					assert.Equals(t, tc.cert.Intermediates, cert.Intermediates)
				}
			}
		})
	}
}

func TestCertificateToACME(t *testing.T) {
	cert, err := newcert()
	assert.FatalError(t, err)
	acmeCert, err := cert.toACME(nil, nil)
	assert.FatalError(t, err)
	assert.Equals(t, append(cert.Leaf, cert.Intermediates...), acmeCert)
}
