package nosql

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/nosql"
	"github.com/smallstep/nosql/database"
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

						return nil, database.ErrNotFound
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
				Error:            acme.NewError(acme.ErrorMalformedType, "The request message was malformed"),
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
			d := DB{db: tc.db}
			if dbo, err := d.getDBOrder(context.Background(), orderID); err != nil {
				var ae *acme.Error
				if errors.As(err, &ae) {
					if assert.NotNil(t, tc.acmeErr) {
						assert.Equals(t, ae.Type, tc.acmeErr.Type)
						assert.Equals(t, ae.Detail, tc.acmeErr.Detail)
						assert.Equals(t, ae.Status, tc.acmeErr.Status)
						assert.Equals(t, ae.Err.Error(), tc.acmeErr.Err.Error())
						assert.Equals(t, ae.Detail, tc.acmeErr.Detail)
					}
				} else {
					if assert.NotNil(t, tc.err) {
						assert.HasPrefix(t, err.Error(), tc.err.Error())
					}
				}
			} else if assert.Nil(t, tc.err) {
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

						return nil, database.ErrNotFound
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
				Error:            acme.NewError(acme.ErrorMalformedType, "The request message was malformed"),
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
			d := DB{db: tc.db}
			if o, err := d.GetOrder(context.Background(), orderID); err != nil {
				var ae *acme.Error
				if errors.As(err, &ae) {
					if assert.NotNil(t, tc.acmeErr) {
						assert.Equals(t, ae.Type, tc.acmeErr.Type)
						assert.Equals(t, ae.Detail, tc.acmeErr.Detail)
						assert.Equals(t, ae.Status, tc.acmeErr.Status)
						assert.Equals(t, ae.Err.Error(), tc.acmeErr.Err.Error())
						assert.Equals(t, ae.Detail, tc.acmeErr.Detail)
					}
				} else {
					if assert.NotNil(t, tc.err) {
						assert.HasPrefix(t, err.Error(), tc.err.Error())
					}
				}
			} else if assert.Nil(t, tc.err) {
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
				Error:         acme.NewError(acme.ErrorMalformedType, "The request message was malformed"),
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
				Error:         acme.NewError(acme.ErrorMalformedType, "The request message was malformed"),
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
			d := DB{db: tc.db}
			if err := d.UpdateOrder(context.Background(), tc.o); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, tc.o.ID, dbo.ID)
					assert.Equals(t, tc.o.CertificateID, "certID")
					assert.Equals(t, tc.o.Status, acme.StatusValid)
					assert.Equals(t, tc.o.Error.Error(), acme.NewError(acme.ErrorMalformedType, "The request message was malformed").Error())
				}
			}
		})
	}
}

func TestDB_CreateOrder(t *testing.T) {
	now := clock.Now()
	nbf := now.Add(5 * time.Minute)
	naf := now.Add(15 * time.Minute)
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
				NotBefore:     nbf,
				NotAfter:      naf,
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
				NotBefore:     nbf,
				NotAfter:      naf,
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
				NotBefore:     nbf,
				NotAfter:      naf,
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
						return nil, database.ErrNotFound
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						switch string(bucket) {
						case string(ordersByAccountIDTable):
							b, err := json.Marshal([]string{o.ID})
							assert.FatalError(t, err)
							assert.Equals(t, string(key), "accID")
							assert.Equals(t, old, nil)
							assert.Equals(t, nu, b)
							return nu, true, nil
						case string(orderTable):
							*idptr = string(key)
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
						default:
							assert.FatalError(t, errors.Errorf("unexpected bucket %s", string(bucket)))
							return nil, false, errors.New("force")
						}
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
			d := DB{db: tc.db}
			if err := d.CreateOrder(context.Background(), tc.o); err != nil {
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

func TestDB_updateAddOrderIDs(t *testing.T) {
	accID := "accID"
	type test struct {
		db      nosql.DB
		err     error
		acmeErr *acme.Error
		addOids []string
		res     []string
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/db.Get-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, ordersByAccountIDTable)
						assert.Equals(t, key, []byte(accID))
						return nil, errors.New("force")
					},
				},
				err: errors.Errorf("error loading orderIDs for account %s", accID),
			}
		},
		"fail/unmarshal-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, ordersByAccountIDTable)
						assert.Equals(t, key, []byte(accID))
						return []byte("foo"), nil
					},
				},
				err: errors.Errorf("error unmarshaling orderIDs for account %s", accID),
			}
		},
		"fail/db.Get-order-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						switch string(bucket) {
						case string(ordersByAccountIDTable):
							assert.Equals(t, key, []byte(accID))
							b, err := json.Marshal([]string{"foo", "bar"})
							assert.FatalError(t, err)
							return b, nil
						case string(orderTable):
							assert.Equals(t, key, []byte("foo"))
							return nil, errors.New("force")
						default:
							assert.FatalError(t, errors.Errorf("unexpected bucket %s", string(bucket)))
							return nil, errors.New("force")
						}
					},
				},
				acmeErr: acme.NewErrorISE("error loading order foo for account accID: error loading order foo: force"),
			}
		},
		"fail/update-order-status-error": func(t *testing.T) test {
			expiry := clock.Now().Add(-5 * time.Minute)
			ofoo := &dbOrder{
				ID:        "foo",
				Status:    acme.StatusPending,
				ExpiresAt: expiry,
			}
			bfoo, err := json.Marshal(ofoo)
			assert.FatalError(t, err)
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						switch string(bucket) {
						case string(ordersByAccountIDTable):
							assert.Equals(t, key, []byte(accID))
							b, err := json.Marshal([]string{"foo", "bar"})
							assert.FatalError(t, err)
							return b, nil
						case string(orderTable):
							assert.Equals(t, key, []byte("foo"))
							return bfoo, nil
						default:
							assert.FatalError(t, errors.Errorf("unexpected bucket %s", string(bucket)))
							return nil, errors.New("force")
						}
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, orderTable)
						assert.Equals(t, key, []byte("foo"))
						assert.Equals(t, old, bfoo)

						newdbo := new(dbOrder)
						assert.FatalError(t, json.Unmarshal(nu, newdbo))
						assert.Equals(t, newdbo.ID, "foo")
						assert.Equals(t, newdbo.Status, acme.StatusInvalid)
						assert.Equals(t, newdbo.ExpiresAt, expiry)
						assert.Equals(t, newdbo.Error.Error(), acme.NewError(acme.ErrorMalformedType, "The request message was malformed").Error())
						return nil, false, errors.New("force")
					},
				},
				acmeErr: acme.NewErrorISE("error updating order foo for account accID: error updating order: error saving acme order: force"),
			}
		},
		"fail/db.save-order-error": func(t *testing.T) test {
			addOids := []string{"foo", "bar"}
			b, err := json.Marshal(addOids)
			assert.FatalError(t, err)
			delCount := 0
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, ordersByAccountIDTable)
						assert.Equals(t, key, []byte(accID))
						return nil, database.ErrNotFound
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, ordersByAccountIDTable)
						assert.Equals(t, key, []byte(accID))
						assert.Equals(t, old, nil)
						assert.Equals(t, nu, b)
						return nil, false, errors.New("force")
					},
					MDel: func(bucket, key []byte) error {
						delCount++
						switch delCount {
						case 1:
							assert.Equals(t, bucket, orderTable)
							assert.Equals(t, key, []byte("foo"))
							return nil
						case 2:
							assert.Equals(t, bucket, orderTable)
							assert.Equals(t, key, []byte("bar"))
							return nil
						default:
							assert.FatalError(t, errors.New("delete should only be called twice"))
							return errors.New("force")
						}
					},
				},
				addOids: addOids,
				err:     errors.Errorf("error saving orderIDs index for account %s", accID),
			}
		},
		"ok/no-old": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						switch string(bucket) {
						case string(ordersByAccountIDTable):
							return nil, database.ErrNotFound
						default:
							assert.FatalError(t, errors.Errorf("unexpected bucket %s", string(bucket)))
							return nil, errors.New("force")
						}
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						switch string(bucket) {
						case string(ordersByAccountIDTable):
							assert.Equals(t, key, []byte(accID))
							assert.Equals(t, old, nil)
							assert.Equals(t, nu, nil)
							return nil, true, nil
						default:
							assert.FatalError(t, errors.Errorf("unexpected bucket %s", string(bucket)))
							return nil, false, errors.New("force")
						}
					},
				},
				res: []string{},
			}
		},
		"ok/all-old-not-pending": func(t *testing.T) test {
			oldOids := []string{"foo", "bar"}
			bOldOids, err := json.Marshal(oldOids)
			assert.FatalError(t, err)
			expiry := clock.Now().Add(-5 * time.Minute)
			ofoo := &dbOrder{
				ID:        "foo",
				Status:    acme.StatusPending,
				ExpiresAt: expiry,
			}
			bfoo, err := json.Marshal(ofoo)
			assert.FatalError(t, err)
			obar := &dbOrder{
				ID:        "bar",
				Status:    acme.StatusPending,
				ExpiresAt: expiry,
			}
			bbar, err := json.Marshal(obar)
			assert.FatalError(t, err)
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						switch string(bucket) {
						case string(ordersByAccountIDTable):
							return bOldOids, nil
						case string(orderTable):
							switch string(key) {
							case "foo":
								assert.Equals(t, key, []byte("foo"))
								return bfoo, nil
							case "bar":
								assert.Equals(t, key, []byte("bar"))
								return bbar, nil
							default:
								assert.FatalError(t, errors.Errorf("unexpected key %s", string(key)))
								return nil, errors.New("force")
							}
						default:
							assert.FatalError(t, errors.Errorf("unexpected bucket %s", string(bucket)))
							return nil, errors.New("force")
						}
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						switch string(bucket) {
						case string(orderTable):
							return nil, true, nil
						case string(ordersByAccountIDTable):
							assert.Equals(t, key, []byte(accID))
							assert.Equals(t, old, bOldOids)
							assert.Equals(t, nu, nil)
							return nil, true, nil
						default:
							assert.FatalError(t, errors.Errorf("unexpected bucket %s", string(bucket)))
							return nil, false, errors.New("force")
						}
					},
				},
				res: []string{},
			}
		},
		"ok/old-and-new": func(t *testing.T) test {
			oldOids := []string{"foo", "bar"}
			bOldOids, err := json.Marshal(oldOids)
			assert.FatalError(t, err)
			addOids := []string{"zap", "zar"}
			bAddOids, err := json.Marshal(addOids)
			assert.FatalError(t, err)
			expiry := clock.Now().Add(-5 * time.Minute)
			ofoo := &dbOrder{
				ID:        "foo",
				Status:    acme.StatusPending,
				ExpiresAt: expiry,
			}
			bfoo, err := json.Marshal(ofoo)
			assert.FatalError(t, err)
			obar := &dbOrder{
				ID:        "bar",
				Status:    acme.StatusPending,
				ExpiresAt: expiry,
			}
			bbar, err := json.Marshal(obar)
			assert.FatalError(t, err)
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						switch string(bucket) {
						case string(ordersByAccountIDTable):
							return bOldOids, nil
						case string(orderTable):
							switch string(key) {
							case "foo":
								assert.Equals(t, key, []byte("foo"))
								return bfoo, nil
							case "bar":
								assert.Equals(t, key, []byte("bar"))
								return bbar, nil
							default:
								assert.FatalError(t, errors.Errorf("unexpected key %s", string(key)))
								return nil, errors.New("force")
							}
						default:
							assert.FatalError(t, errors.Errorf("unexpected bucket %s", string(bucket)))
							return nil, errors.New("force")
						}
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						switch string(bucket) {
						case string(orderTable):
							return nil, true, nil
						case string(ordersByAccountIDTable):
							assert.Equals(t, key, []byte(accID))
							assert.Equals(t, old, bOldOids)
							assert.Equals(t, nu, bAddOids)
							return nil, true, nil
						default:
							assert.FatalError(t, errors.Errorf("unexpected bucket %s", string(bucket)))
							return nil, false, errors.New("force")
						}
					},
				},
				addOids: addOids,
				res:     addOids,
			}
		},
		"ok/old-and-new-2": func(t *testing.T) test {
			oldOids := []string{"foo", "bar", "baz"}
			bOldOids, err := json.Marshal(oldOids)
			assert.FatalError(t, err)
			addOids := []string{"zap", "zar"}
			now := clock.Now()
			min5 := now.Add(5 * time.Minute)
			expiry := now.Add(-5 * time.Minute)

			o1 := &dbOrder{
				ID:               "foo",
				Status:           acme.StatusPending,
				ExpiresAt:        min5,
				AuthorizationIDs: []string{"a"},
			}
			bo1, err := json.Marshal(o1)
			assert.FatalError(t, err)
			o2 := &dbOrder{
				ID:        "bar",
				Status:    acme.StatusPending,
				ExpiresAt: expiry,
			}
			bo2, err := json.Marshal(o2)
			assert.FatalError(t, err)
			o3 := &dbOrder{
				ID:               "baz",
				Status:           acme.StatusPending,
				ExpiresAt:        min5,
				AuthorizationIDs: []string{"b"},
			}
			bo3, err := json.Marshal(o3)
			assert.FatalError(t, err)

			az1 := &dbAuthz{
				ID:           "a",
				Status:       acme.StatusPending,
				ExpiresAt:    min5,
				ChallengeIDs: []string{"aa"},
			}
			baz1, err := json.Marshal(az1)
			assert.FatalError(t, err)
			az2 := &dbAuthz{
				ID:           "b",
				Status:       acme.StatusPending,
				ExpiresAt:    min5,
				ChallengeIDs: []string{"bb"},
			}
			baz2, err := json.Marshal(az2)
			assert.FatalError(t, err)

			ch1 := &dbChallenge{
				ID:     "aa",
				Status: acme.StatusPending,
			}
			bch1, err := json.Marshal(ch1)
			assert.FatalError(t, err)
			ch2 := &dbChallenge{
				ID:     "bb",
				Status: acme.StatusPending,
			}
			bch2, err := json.Marshal(ch2)
			assert.FatalError(t, err)

			newOids := append([]string{"foo", "baz"}, addOids...)
			bNewOids, err := json.Marshal(newOids)
			assert.FatalError(t, err)

			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						switch string(bucket) {
						case string(authzTable):
							switch string(key) {
							case "a":
								return baz1, nil
							case "b":
								return baz2, nil
							default:
								assert.FatalError(t, errors.Errorf("unexpected authz key %s", string(key)))
								return nil, errors.New("force")
							}
						case string(challengeTable):
							switch string(key) {
							case "aa":
								return bch1, nil
							case "bb":
								return bch2, nil
							default:
								assert.FatalError(t, errors.Errorf("unexpected challenge key %s", string(key)))
								return nil, errors.New("force")
							}
						case string(ordersByAccountIDTable):
							return bOldOids, nil
						case string(orderTable):
							switch string(key) {
							case "foo":
								return bo1, nil
							case "bar":
								return bo2, nil
							case "baz":
								return bo3, nil
							default:
								assert.FatalError(t, errors.Errorf("unexpected key %s", string(key)))
								return nil, errors.New("force")
							}
						default:
							assert.FatalError(t, errors.Errorf("unexpected bucket %s", string(bucket)))
							return nil, errors.New("force")
						}
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						switch string(bucket) {
						case string(orderTable):
							return nil, true, nil
						case string(ordersByAccountIDTable):
							assert.Equals(t, key, []byte(accID))
							assert.Equals(t, old, bOldOids)
							assert.Equals(t, nu, bNewOids)
							return nil, true, nil
						default:
							assert.FatalError(t, errors.Errorf("unexpected bucket %s", string(bucket)))
							return nil, false, errors.New("force")
						}
					},
				},
				addOids: addOids,
				res:     newOids,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{db: tc.db}
			var (
				res []string
				err error
			)
			if tc.addOids == nil {
				res, err = d.updateAddOrderIDs(context.Background(), accID)
			} else {
				res, err = d.updateAddOrderIDs(context.Background(), accID, tc.addOids...)
			}

			if err != nil {
				var ae *acme.Error
				if errors.As(err, &ae) {
					if assert.NotNil(t, tc.acmeErr) {
						assert.Equals(t, ae.Type, tc.acmeErr.Type)
						assert.Equals(t, ae.Detail, tc.acmeErr.Detail)
						assert.Equals(t, ae.Status, tc.acmeErr.Status)
						assert.Equals(t, ae.Err.Error(), tc.acmeErr.Err.Error())
						assert.Equals(t, ae.Detail, tc.acmeErr.Detail)
					}
				} else {
					if assert.NotNil(t, tc.err) {
						assert.HasPrefix(t, err.Error(), tc.err.Error())
					}
				}
			} else if assert.Nil(t, tc.err) {
				assert.True(t, reflect.DeepEqual(res, tc.res))
			}
		})
	}
}
