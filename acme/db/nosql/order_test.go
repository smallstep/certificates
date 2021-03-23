package nosql

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/nosql"
	nosqldb "github.com/smallstep/nosql/database"
)

func TestDB_getDBOrder(t *testing.T) {
	orderID := "orderID"
	type test struct {
		db      nosql.DB
		err     error
		acmeErr *acme.Error
		dbo     *dbOrder
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/not-found": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, orderTable)
						assert.Equals(t, string(key), orderID)

						return nil, nosqldb.ErrNotFound
					},
				},
				acmeErr: acme.NewError(acme.ErrorMalformedType, "order orderID not found"),
			}
		},
		"fail/db.Get-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, orderTable)
						assert.Equals(t, string(key), orderID)

						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading order orderID: force"),
			}
		},
		"fail/unmarshal-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, orderTable)
						assert.Equals(t, string(key), orderID)

						return []byte("foo"), nil
					},
				},
				err: errors.New("error unmarshaling order orderID into dbOrder"),
			}
		},
		"ok": func(t *testing.T) test {
			now := clock.Now()
			dbo := &dbOrder{
				ID:            orderID,
				AccountID:     "accID",
				ProvisionerID: "provID",
				CertificateID: "certID",
				Status:        acme.StatusValid,
				ExpiresAt:     now,
				CreatedAt:     now,
				NotBefore:     now,
				NotAfter:      now,
				Identifiers: []acme.Identifier{
					{Type: "dns", Value: "test.ca.smallstep.com"},
					{Type: "dns", Value: "example.foo.com"},
				},
				AuthorizationIDs: []string{"foo", "bar"},
				Error:            acme.NewError(acme.ErrorMalformedType, "force"),
			}
			b, err := json.Marshal(dbo)
			assert.FatalError(t, err)
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, orderTable)
						assert.Equals(t, string(key), orderID)

						return b, nil
					},
				},
				dbo: dbo,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			db := DB{db: tc.db}
			if dbo, err := db.getDBOrder(context.Background(), orderID); err != nil {
				switch k := err.(type) {
				case *acme.Error:
					if assert.NotNil(t, tc.acmeErr) {
						assert.Equals(t, k.Type, tc.acmeErr.Type)
						assert.Equals(t, k.Detail, tc.acmeErr.Detail)
						assert.Equals(t, k.Status, tc.acmeErr.Status)
						assert.Equals(t, k.Err.Error(), tc.acmeErr.Err.Error())
						assert.Equals(t, k.Detail, tc.acmeErr.Detail)
					}
				default:
					if assert.NotNil(t, tc.err) {
						assert.HasPrefix(t, err.Error(), tc.err.Error())
					}
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, dbo.ID, tc.dbo.ID)
					assert.Equals(t, dbo.ProvisionerID, tc.dbo.ProvisionerID)
					assert.Equals(t, dbo.CertificateID, tc.dbo.CertificateID)
					assert.Equals(t, dbo.Status, tc.dbo.Status)
					assert.Equals(t, dbo.CreatedAt, tc.dbo.CreatedAt)
					assert.Equals(t, dbo.ExpiresAt, tc.dbo.ExpiresAt)
					assert.Equals(t, dbo.NotBefore, tc.dbo.NotBefore)
					assert.Equals(t, dbo.NotAfter, tc.dbo.NotAfter)
					assert.Equals(t, dbo.Identifiers, tc.dbo.Identifiers)
					assert.Equals(t, dbo.AuthorizationIDs, tc.dbo.AuthorizationIDs)
					assert.Equals(t, dbo.Error.Error(), tc.dbo.Error.Error())
				}
			}
		})
	}
}

func TestDB_GetOrder(t *testing.T) {
	orderID := "orderID"
	type test struct {
		db      nosql.DB
		err     error
		acmeErr *acme.Error
		dbo     *dbOrder
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/db.Get-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, orderTable)
						assert.Equals(t, string(key), orderID)

						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading order orderID: force"),
			}
		},
		"fail/forward-acme-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, orderTable)
						assert.Equals(t, string(key), orderID)

						return nil, nosqldb.ErrNotFound
					},
				},
				acmeErr: acme.NewError(acme.ErrorMalformedType, "order orderID not found"),
			}
		},
		"ok": func(t *testing.T) test {
			now := clock.Now()
			dbo := &dbOrder{
				ID:            orderID,
				AccountID:     "accID",
				ProvisionerID: "provID",
				CertificateID: "certID",
				Status:        acme.StatusValid,
				ExpiresAt:     now,
				CreatedAt:     now,
				NotBefore:     now,
				NotAfter:      now,
				Identifiers: []acme.Identifier{
					{Type: "dns", Value: "test.ca.smallstep.com"},
					{Type: "dns", Value: "example.foo.com"},
				},
				AuthorizationIDs: []string{"foo", "bar"},
				Error:            acme.NewError(acme.ErrorMalformedType, "force"),
			}
			b, err := json.Marshal(dbo)
			assert.FatalError(t, err)
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, orderTable)
						assert.Equals(t, string(key), orderID)
						return b, nil
					},
				},
				dbo: dbo,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			db := DB{db: tc.db}
			if o, err := db.GetOrder(context.Background(), orderID); err != nil {
				switch k := err.(type) {
				case *acme.Error:
					if assert.NotNil(t, tc.acmeErr) {
						assert.Equals(t, k.Type, tc.acmeErr.Type)
						assert.Equals(t, k.Detail, tc.acmeErr.Detail)
						assert.Equals(t, k.Status, tc.acmeErr.Status)
						assert.Equals(t, k.Err.Error(), tc.acmeErr.Err.Error())
						assert.Equals(t, k.Detail, tc.acmeErr.Detail)
					}
				default:
					if assert.NotNil(t, tc.err) {
						assert.HasPrefix(t, err.Error(), tc.err.Error())
					}
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, o.ID, tc.dbo.ID)
					assert.Equals(t, o.AccountID, tc.dbo.AccountID)
					assert.Equals(t, o.ProvisionerID, tc.dbo.ProvisionerID)
					assert.Equals(t, o.CertificateID, tc.dbo.CertificateID)
					assert.Equals(t, o.Status, tc.dbo.Status)
					assert.Equals(t, o.ExpiresAt, tc.dbo.ExpiresAt)
					assert.Equals(t, o.NotBefore, tc.dbo.NotBefore)
					assert.Equals(t, o.NotAfter, tc.dbo.NotAfter)
					assert.Equals(t, o.Identifiers, tc.dbo.Identifiers)
					assert.Equals(t, o.AuthorizationIDs, tc.dbo.AuthorizationIDs)
					assert.Equals(t, o.Error.Error(), tc.dbo.Error.Error())
				}
			}
		})
	}
}

func TestDB_UpdateOrder(t *testing.T) {
	orderID := "orderID"
	now := clock.Now()
	dbo := &dbOrder{
		ID:            orderID,
		AccountID:     "accID",
		ProvisionerID: "provID",
		Status:        acme.StatusPending,
		ExpiresAt:     now,
		CreatedAt:     now,
		NotBefore:     now,
		NotAfter:      now,
		Identifiers: []acme.Identifier{
			{Type: "dns", Value: "test.ca.smallstep.com"},
			{Type: "dns", Value: "example.foo.com"},
		},
		AuthorizationIDs: []string{"foo", "bar"},
	}
	b, err := json.Marshal(dbo)
	assert.FatalError(t, err)
	type test struct {
		db  nosql.DB
		o   *acme.Order
		err error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/db.Get-error": func(t *testing.T) test {
			return test{
				o: &acme.Order{
					ID: orderID,
				},
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, orderTable)
						assert.Equals(t, string(key), orderID)

						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading order orderID: force"),
			}
		},
		"fail/save-error": func(t *testing.T) test {
			o := &acme.Order{
				ID:            orderID,
				Status:        acme.StatusValid,
				CertificateID: "certID",
				Error:         acme.NewError(acme.ErrorMalformedType, "force"),
			}
			return test{
				o: o,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, orderTable)
						assert.Equals(t, string(key), orderID)

						return b, nil
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, orderTable)
						assert.Equals(t, old, b)

						dbNew := new(dbOrder)
						assert.FatalError(t, json.Unmarshal(nu, dbNew))
						assert.Equals(t, dbNew.ID, dbo.ID)
						assert.Equals(t, dbNew.AccountID, dbo.AccountID)
						assert.Equals(t, dbNew.ProvisionerID, dbo.ProvisionerID)
						assert.Equals(t, dbNew.CertificateID, o.CertificateID)
						assert.Equals(t, dbNew.Status, o.Status)
						assert.Equals(t, dbNew.CreatedAt, dbo.CreatedAt)
						assert.Equals(t, dbNew.ExpiresAt, dbo.ExpiresAt)
						assert.Equals(t, dbNew.NotBefore, dbo.NotBefore)
						assert.Equals(t, dbNew.NotAfter, dbo.NotAfter)
						assert.Equals(t, dbNew.AuthorizationIDs, dbo.AuthorizationIDs)
						assert.Equals(t, dbNew.Identifiers, dbo.Identifiers)
						assert.Equals(t, dbNew.Error.Error(), o.Error.Error())
						return nil, false, errors.New("force")
					},
				},
				err: errors.New("error saving acme order: force"),
			}
		},
		"ok": func(t *testing.T) test {
			o := &acme.Order{
				ID:            orderID,
				Status:        acme.StatusValid,
				CertificateID: "certID",
				Error:         acme.NewError(acme.ErrorMalformedType, "force"),
			}
			return test{
				o: o,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, orderTable)
						assert.Equals(t, string(key), orderID)

						return b, nil
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, orderTable)
						assert.Equals(t, old, b)

						dbNew := new(dbOrder)
						assert.FatalError(t, json.Unmarshal(nu, dbNew))
						assert.Equals(t, dbNew.ID, dbo.ID)
						assert.Equals(t, dbNew.AccountID, dbo.AccountID)
						assert.Equals(t, dbNew.ProvisionerID, dbo.ProvisionerID)
						assert.Equals(t, dbNew.CertificateID, o.CertificateID)
						assert.Equals(t, dbNew.Status, o.Status)
						assert.Equals(t, dbNew.CreatedAt, dbo.CreatedAt)
						assert.Equals(t, dbNew.ExpiresAt, dbo.ExpiresAt)
						assert.Equals(t, dbNew.NotBefore, dbo.NotBefore)
						assert.Equals(t, dbNew.NotAfter, dbo.NotAfter)
						assert.Equals(t, dbNew.AuthorizationIDs, dbo.AuthorizationIDs)
						assert.Equals(t, dbNew.Identifiers, dbo.Identifiers)
						assert.Equals(t, dbNew.Error.Error(), o.Error.Error())
						return nu, true, nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			db := DB{db: tc.db}
			if err := db.UpdateOrder(context.Background(), tc.o); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, tc.o.ID, dbo.ID)
					assert.Equals(t, tc.o.CertificateID, "certID")
					assert.Equals(t, tc.o.Status, acme.StatusValid)
					assert.Equals(t, tc.o.Error.Error(), acme.NewError(acme.ErrorMalformedType, "force").Error())
				}
			}
		})
	}
}

func TestDB_CreateOrder(t *testing.T) {
	now := clock.Now()
	type test struct {
		db  nosql.DB
		o   *acme.Order
		err error
		_id *string
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/order-save-error": func(t *testing.T) test {
			o := &acme.Order{
				AccountID:     "accID",
				ProvisionerID: "provID",
				CertificateID: "certID",
				Status:        acme.StatusValid,
				ExpiresAt:     now,
				NotBefore:     now,
				NotAfter:      now,
				Identifiers: []acme.Identifier{
					{Type: "dns", Value: "test.ca.smallstep.com"},
					{Type: "dns", Value: "example.foo.com"},
				},
				AuthorizationIDs: []string{"foo", "bar"},
			}
			return test{
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, string(bucket), string(orderTable))
						assert.Equals(t, string(key), o.ID)
						assert.Equals(t, old, nil)

						dbo := new(dbOrder)
						assert.FatalError(t, json.Unmarshal(nu, dbo))
						assert.Equals(t, dbo.ID, o.ID)
						assert.Equals(t, dbo.AccountID, o.AccountID)
						assert.Equals(t, dbo.ProvisionerID, o.ProvisionerID)
						assert.Equals(t, dbo.CertificateID, "")
						assert.Equals(t, dbo.Status, o.Status)
						assert.True(t, dbo.CreatedAt.Add(-time.Minute).Before(now))
						assert.True(t, dbo.CreatedAt.Add(time.Minute).After(now))
						assert.Equals(t, dbo.ExpiresAt, o.ExpiresAt)
						assert.Equals(t, dbo.NotBefore, o.NotBefore)
						assert.Equals(t, dbo.NotAfter, o.NotAfter)
						assert.Equals(t, dbo.AuthorizationIDs, o.AuthorizationIDs)
						assert.Equals(t, dbo.Identifiers, o.Identifiers)
						assert.Equals(t, dbo.Error, nil)
						return nil, false, errors.New("force")
					},
				},
				o:   o,
				err: errors.New("error saving acme order: force"),
			}
		},
		"fail/orderIDsByOrderUpdate-error": func(t *testing.T) test {
			o := &acme.Order{
				AccountID:     "accID",
				ProvisionerID: "provID",
				CertificateID: "certID",
				Status:        acme.StatusValid,
				ExpiresAt:     now,
				NotBefore:     now,
				NotAfter:      now,
				Identifiers: []acme.Identifier{
					{Type: "dns", Value: "test.ca.smallstep.com"},
					{Type: "dns", Value: "example.foo.com"},
				},
				AuthorizationIDs: []string{"foo", "bar"},
			}
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, string(bucket), string(ordersByAccountIDTable))
						assert.Equals(t, string(key), o.AccountID)
						return nil, errors.New("force")
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, string(bucket), string(orderTable))
						assert.Equals(t, string(key), o.ID)
						assert.Equals(t, old, nil)

						dbo := new(dbOrder)
						assert.FatalError(t, json.Unmarshal(nu, dbo))
						assert.Equals(t, dbo.ID, o.ID)
						assert.Equals(t, dbo.AccountID, o.AccountID)
						assert.Equals(t, dbo.ProvisionerID, o.ProvisionerID)
						assert.Equals(t, dbo.CertificateID, "")
						assert.Equals(t, dbo.Status, o.Status)
						assert.True(t, dbo.CreatedAt.Add(-time.Minute).Before(now))
						assert.True(t, dbo.CreatedAt.Add(time.Minute).After(now))
						assert.Equals(t, dbo.ExpiresAt, o.ExpiresAt)
						assert.Equals(t, dbo.NotBefore, o.NotBefore)
						assert.Equals(t, dbo.NotAfter, o.NotAfter)
						assert.Equals(t, dbo.AuthorizationIDs, o.AuthorizationIDs)
						assert.Equals(t, dbo.Identifiers, o.Identifiers)
						assert.Equals(t, dbo.Error, nil)
						return nu, true, nil
					},
				},
				o:   o,
				err: errors.New("error loading orderIDs for account accID: force"),
			}
		},
		"ok": func(t *testing.T) test {
			var (
				id    string
				idptr = &id
			)

			o := &acme.Order{
				AccountID:     "accID",
				ProvisionerID: "provID",
				Status:        acme.StatusValid,
				ExpiresAt:     now,
				NotBefore:     now,
				NotAfter:      now,
				Identifiers: []acme.Identifier{
					{Type: "dns", Value: "test.ca.smallstep.com"},
					{Type: "dns", Value: "example.foo.com"},
				},
				AuthorizationIDs: []string{"foo", "bar"},
			}
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, string(bucket), string(ordersByAccountIDTable))
						assert.Equals(t, string(key), o.AccountID)
						return nil, nosqldb.ErrNotFound
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						*idptr = string(key)
						assert.Equals(t, string(bucket), string(orderTable))
						assert.Equals(t, string(key), o.ID)
						assert.Equals(t, old, nil)

						dbo := new(dbOrder)
						assert.FatalError(t, json.Unmarshal(nu, dbo))
						assert.Equals(t, dbo.ID, o.ID)
						assert.Equals(t, dbo.AccountID, o.AccountID)
						assert.Equals(t, dbo.ProvisionerID, o.ProvisionerID)
						assert.Equals(t, dbo.CertificateID, "")
						assert.Equals(t, dbo.Status, o.Status)
						assert.True(t, dbo.CreatedAt.Add(-time.Minute).Before(now))
						assert.True(t, dbo.CreatedAt.Add(time.Minute).After(now))
						assert.Equals(t, dbo.ExpiresAt, o.ExpiresAt)
						assert.Equals(t, dbo.NotBefore, o.NotBefore)
						assert.Equals(t, dbo.NotAfter, o.NotAfter)
						assert.Equals(t, dbo.AuthorizationIDs, o.AuthorizationIDs)
						assert.Equals(t, dbo.Identifiers, o.Identifiers)
						assert.Equals(t, dbo.Error, nil)
						return nu, true, nil
					},
				},
				o:   o,
				_id: idptr,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			db := DB{db: tc.db}
			if err := db.CreateOrder(context.Background(), tc.o); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, tc.o.ID, *tc._id)
				}
			}
		})
	}
}
