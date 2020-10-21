package acme

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/nosql"
	"github.com/smallstep/nosql/database"
)

var certDuration = 6 * time.Hour

func defaultOrderOps() OrderOptions {
	return OrderOptions{
		AccountID: "accID",
		Identifiers: []Identifier{
			{Type: "dns", Value: "acme.example.com"},
			{Type: "dns", Value: "step.example.com"},
		},
		NotBefore: clock.Now(),
		NotAfter:  clock.Now().Add(certDuration),
	}
}

func newO() (*order, error) {
	mockdb := &db.MockNoSQLDB{
		MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
			return []byte("foo"), true, nil
		},
		MGet: func(bucket, key []byte) ([]byte, error) {
			return nil, database.ErrNotFound
		},
	}
	return newOrder(mockdb, defaultOrderOps())
}

func Test_getOrder(t *testing.T) {
	type test struct {
		id  string
		db  nosql.DB
		o   *order
		err *Error
	}
	tests := map[string]func(t *testing.T) test{
		"fail/not-found": func(t *testing.T) test {
			o, err := newO()
			assert.FatalError(t, err)
			return test{
				o:  o,
				id: o.ID,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						return nil, database.ErrNotFound
					},
				},
				err: MalformedErr(errors.Errorf("order %s not found: not found", o.ID)),
			}
		},
		"fail/db-error": func(t *testing.T) test {
			o, err := newO()
			assert.FatalError(t, err)
			return test{
				o:  o,
				id: o.ID,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						return nil, errors.New("force")
					},
				},
				err: ServerInternalErr(errors.Errorf("error loading order %s: force", o.ID)),
			}
		},
		"fail/unmarshal-error": func(t *testing.T) test {
			o, err := newO()
			assert.FatalError(t, err)
			return test{
				o:  o,
				id: o.ID,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, orderTable)
						assert.Equals(t, key, []byte(o.ID))
						return nil, nil
					},
				},
				err: ServerInternalErr(errors.New("error unmarshaling order: unexpected end of JSON input")),
			}
		},
		"ok": func(t *testing.T) test {
			o, err := newO()
			assert.FatalError(t, err)
			b, err := json.Marshal(o)
			assert.FatalError(t, err)
			return test{
				o:  o,
				id: o.ID,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, orderTable)
						assert.Equals(t, key, []byte(o.ID))
						return b, nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if o, err := getOrder(tc.db, tc.id); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, tc.o.ID, o.ID)
					assert.Equals(t, tc.o.AccountID, o.AccountID)
					assert.Equals(t, tc.o.Status, o.Status)
					assert.Equals(t, tc.o.Identifiers, o.Identifiers)
					assert.Equals(t, tc.o.Created, o.Created)
					assert.Equals(t, tc.o.Expires, o.Expires)
					assert.Equals(t, tc.o.Authorizations, o.Authorizations)
					assert.Equals(t, tc.o.NotBefore, o.NotBefore)
					assert.Equals(t, tc.o.NotAfter, o.NotAfter)
					assert.Equals(t, tc.o.Certificate, o.Certificate)
					assert.Equals(t, tc.o.Error, o.Error)
				}
			}
		})
	}
}

func TestOrderToACME(t *testing.T) {
	dir := newDirectory("ca.smallstep.com", "acme")
	prov := newProv()
	provName := url.PathEscape(prov.GetName())
	baseURL := &url.URL{Scheme: "https", Host: "test.ca.smallstep.com"}
	ctx := context.WithValue(context.Background(), ProvisionerContextKey, prov)
	ctx = context.WithValue(ctx, BaseURLContextKey, baseURL)

	type test struct {
		o   *order
		err *Error
	}
	tests := map[string]func(t *testing.T) test{
		"ok/no-cert": func(t *testing.T) test {
			o, err := newO()
			assert.FatalError(t, err)
			return test{o: o}
		},
		"ok/cert": func(t *testing.T) test {
			o, err := newO()
			assert.FatalError(t, err)
			o.Status = StatusValid
			o.Certificate = "cert-id"
			return test{o: o}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			acmeOrder, err := tc.o.toACME(ctx, nil, dir)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, acmeOrder.ID, tc.o.ID)
					assert.Equals(t, acmeOrder.Status, tc.o.Status)
					assert.Equals(t, acmeOrder.Identifiers, tc.o.Identifiers)
					assert.Equals(t, acmeOrder.Finalize,
						fmt.Sprintf("%s/acme/%s/order/%s/finalize", baseURL.String(), provName, tc.o.ID))
					if tc.o.Certificate != "" {
						assert.Equals(t, acmeOrder.Certificate, fmt.Sprintf("%s/acme/%s/certificate/%s", baseURL.String(), provName, tc.o.Certificate))
					}

					expiry, err := time.Parse(time.RFC3339, acmeOrder.Expires)
					assert.FatalError(t, err)
					assert.Equals(t, expiry.String(), tc.o.Expires.String())
					nbf, err := time.Parse(time.RFC3339, acmeOrder.NotBefore)
					assert.FatalError(t, err)
					assert.Equals(t, nbf.String(), tc.o.NotBefore.String())
					naf, err := time.Parse(time.RFC3339, acmeOrder.NotAfter)
					assert.FatalError(t, err)
					assert.Equals(t, naf.String(), tc.o.NotAfter.String())
				}
			}
		})
	}
}

func TestOrderSave(t *testing.T) {
	type test struct {
		o, old *order
		db     nosql.DB
		err    *Error
	}
	tests := map[string]func(t *testing.T) test{
		"fail/old-nil/swap-error": func(t *testing.T) test {
			o, err := newO()
			assert.FatalError(t, err)
			return test{
				o:   o,
				old: nil,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						return nil, false, errors.New("force")
					},
				},
				err: ServerInternalErr(errors.New("error storing order: force")),
			}
		},
		"fail/old-nil/swap-false": func(t *testing.T) test {
			o, err := newO()
			assert.FatalError(t, err)
			return test{
				o:   o,
				old: nil,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						return []byte("foo"), false, nil
					},
				},
				err: ServerInternalErr(errors.New("error storing order; value has changed since last read")),
			}
		},
		"ok/old-nil": func(t *testing.T) test {
			o, err := newO()
			assert.FatalError(t, err)
			b, err := json.Marshal(o)
			assert.FatalError(t, err)
			return test{
				o:   o,
				old: nil,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						assert.Equals(t, old, nil)
						assert.Equals(t, b, newval)
						assert.Equals(t, bucket, orderTable)
						assert.Equals(t, []byte(o.ID), key)
						return nil, true, nil
					},
				},
			}
		},
		"ok/old-not-nil": func(t *testing.T) test {
			oldo, err := newO()
			assert.FatalError(t, err)
			o, err := newO()
			assert.FatalError(t, err)

			oldb, err := json.Marshal(oldo)
			assert.FatalError(t, err)
			b, err := json.Marshal(o)
			assert.FatalError(t, err)
			return test{
				o:   o,
				old: oldo,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						assert.Equals(t, old, oldb)
						assert.Equals(t, b, newval)
						assert.Equals(t, bucket, orderTable)
						assert.Equals(t, []byte(o.ID), key)
						return []byte("foo"), true, nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if err := tc.o.save(tc.db, tc.old); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

func Test_newOrder(t *testing.T) {
	type test struct {
		ops    OrderOptions
		db     nosql.DB
		err    *Error
		authzs *([]string)
	}
	tests := map[string]func(t *testing.T) test{
		"fail/unexpected-identifier-type": func(t *testing.T) test {
			ops := defaultOrderOps()
			ops.Identifiers[0].Type = "foo"
			return test{
				ops: ops,
				err: MalformedErr(errors.New("unexpected authz type foo")),
			}
		},
		"fail/save-order-error": func(t *testing.T) test {
			count := 0
			return test{
				ops: defaultOrderOps(),
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						if count >= 8 {
							return nil, false, errors.New("force")
						}
						count++
						return nil, true, nil
					},
				},
				err: ServerInternalErr(errors.New("error storing order: force")),
			}
		},
		"fail/get-orderIDs-error": func(t *testing.T) test {
			count := 0
			ops := defaultOrderOps()
			return test{
				ops: ops,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						if count >= 9 {
							return nil, false, errors.New("force")
						}
						count++
						return nil, true, nil
					},
					MGet: func(bucket, key []byte) ([]byte, error) {
						return nil, errors.New("force")
					},
				},
				err: ServerInternalErr(errors.Errorf("error loading orderIDs for account %s: force", ops.AccountID)),
			}
		},
		"fail/save-orderIDs-error": func(t *testing.T) test {
			count := 0
			var (
				_oid = ""
				oid  = &_oid
			)
			ops := defaultOrderOps()
			return test{
				ops: ops,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						if count >= 9 {
							assert.Equals(t, bucket, ordersByAccountIDTable)
							assert.Equals(t, key, []byte(ops.AccountID))
							return nil, false, errors.New("force")
						} else if count == 8 {
							*oid = string(key)
						}
						count++
						return nil, true, nil
					},
					MGet: func(bucket, key []byte) ([]byte, error) {
						return nil, database.ErrNotFound
					},
					MDel: func(bucket, key []byte) error {
						assert.Equals(t, bucket, orderTable)
						assert.Equals(t, key, []byte(*oid))
						return nil
					},
				},
				err: ServerInternalErr(errors.Errorf("error storing order IDs for account %s: force", ops.AccountID)),
			}
		},
		"ok": func(t *testing.T) test {
			count := 0
			authzs := &([]string{})
			var (
				_oid = ""
				oid  = &_oid
			)
			ops := defaultOrderOps()
			return test{
				ops: ops,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						if count >= 9 {
							assert.Equals(t, bucket, ordersByAccountIDTable)
							assert.Equals(t, key, []byte(ops.AccountID))
							assert.Equals(t, old, nil)
							newB, err := json.Marshal([]string{*oid})
							assert.FatalError(t, err)
							assert.Equals(t, newval, newB)
						} else if count == 8 {
							*oid = string(key)
						} else if count == 7 {
							*authzs = append(*authzs, string(key))
						} else if count == 3 {
							*authzs = []string{string(key)}
						}
						count++
						return nil, true, nil
					},
					MGet: func(bucket, key []byte) ([]byte, error) {
						return nil, database.ErrNotFound
					},
				},
				authzs: authzs,
			}
		},
		"ok/validity-bounds-not-set": func(t *testing.T) test {
			count := 0
			authzs := &([]string{})
			var (
				_oid = ""
				oid  = &_oid
			)
			ops := defaultOrderOps()
			ops.backdate = time.Minute
			ops.defaultDuration = 12 * time.Hour
			ops.NotBefore = time.Time{}
			ops.NotAfter = time.Time{}
			return test{
				ops: ops,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						if count >= 9 {
							assert.Equals(t, bucket, ordersByAccountIDTable)
							assert.Equals(t, key, []byte(ops.AccountID))
							assert.Equals(t, old, nil)
							newB, err := json.Marshal([]string{*oid})
							assert.FatalError(t, err)
							assert.Equals(t, newval, newB)
						} else if count == 8 {
							*oid = string(key)
						} else if count == 7 {
							*authzs = append(*authzs, string(key))
						} else if count == 3 {
							*authzs = []string{string(key)}
						}
						count++
						return nil, true, nil
					},
					MGet: func(bucket, key []byte) ([]byte, error) {
						return nil, database.ErrNotFound
					},
				},
				authzs: authzs,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			o, err := newOrder(tc.db, tc.ops)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, o.AccountID, tc.ops.AccountID)
					assert.Equals(t, o.Status, StatusPending)
					assert.Equals(t, o.Identifiers, tc.ops.Identifiers)
					assert.Equals(t, o.Error, nil)
					assert.Equals(t, o.Certificate, "")
					assert.Equals(t, o.Authorizations, *tc.authzs)

					assert.True(t, o.Created.Before(time.Now().UTC().Add(time.Minute)))
					assert.True(t, o.Created.After(time.Now().UTC().Add(-1*time.Minute)))

					expiry := o.Created.Add(defaultExpiryDuration)
					assert.True(t, o.Expires.Before(expiry.Add(time.Minute)))
					assert.True(t, o.Expires.After(expiry.Add(-1*time.Minute)))

					nbf := tc.ops.NotBefore
					now := time.Now().UTC()
					if !tc.ops.NotBefore.IsZero() {
						assert.Equals(t, o.NotBefore, tc.ops.NotBefore)
					} else {
						nbf = o.NotBefore.Add(tc.ops.backdate)
						assert.True(t, o.NotBefore.Before(now.Add(-tc.ops.backdate+time.Second)))
						assert.True(t, o.NotBefore.Add(tc.ops.backdate+2*time.Second).After(now))
					}
					if !tc.ops.NotAfter.IsZero() {
						assert.Equals(t, o.NotAfter, tc.ops.NotAfter)
					} else {
						naf := nbf.Add(tc.ops.defaultDuration)
						assert.Equals(t, o.NotAfter, naf)
					}
				}
			}
		})
	}
}

func TestOrderIDs_save(t *testing.T) {
	accID := "acc-id"
	newOids := func() orderIDs {
		return []string{"1", "2"}
	}
	type test struct {
		oids, old orderIDs
		db        nosql.DB
		err       *Error
	}
	tests := map[string]func(t *testing.T) test{
		"fail/old-nil/swap-error": func(t *testing.T) test {
			return test{
				oids: newOids(),
				old:  nil,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						return nil, false, errors.New("force")
					},
				},
				err: ServerInternalErr(errors.Errorf("error storing order IDs for account %s: force", accID)),
			}
		},
		"fail/old-nil/swap-false": func(t *testing.T) test {
			return test{
				oids: newOids(),
				old:  nil,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						return []byte("foo"), false, nil
					},
				},
				err: ServerInternalErr(errors.Errorf("error storing order IDs for account %s; order IDs changed since last read", accID)),
			}
		},
		"ok/old-nil": func(t *testing.T) test {
			oids := newOids()
			b, err := json.Marshal(oids)
			assert.FatalError(t, err)
			return test{
				oids: oids,
				old:  nil,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						assert.Equals(t, old, nil)
						assert.Equals(t, b, newval)
						assert.Equals(t, bucket, ordersByAccountIDTable)
						assert.Equals(t, key, []byte(accID))
						return nil, true, nil
					},
				},
			}
		},
		"ok/old-not-nil": func(t *testing.T) test {
			oldOids := newOids()
			oids := append(oldOids, "3")

			oldb, err := json.Marshal(oldOids)
			assert.FatalError(t, err)
			b, err := json.Marshal(oids)
			assert.FatalError(t, err)
			return test{
				oids: oids,
				old:  oldOids,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						assert.Equals(t, old, oldb)
						assert.Equals(t, newval, b)
						assert.Equals(t, bucket, ordersByAccountIDTable)
						assert.Equals(t, key, []byte(accID))
						return nil, true, nil
					},
				},
			}
		},
		"ok/new-empty-saved-as-nil": func(t *testing.T) test {
			oldOids := newOids()
			oids := []string{}

			oldb, err := json.Marshal(oldOids)
			assert.FatalError(t, err)
			return test{
				oids: oids,
				old:  oldOids,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						assert.Equals(t, old, oldb)
						assert.Equals(t, newval, nil)
						assert.Equals(t, bucket, ordersByAccountIDTable)
						assert.Equals(t, key, []byte(accID))
						return nil, true, nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if err := tc.oids.save(tc.db, tc.old, accID); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

func TestOrderUpdateStatus(t *testing.T) {
	type test struct {
		o, res *order
		err    *Error
		db     nosql.DB
	}
	tests := map[string]func(t *testing.T) test{
		"fail/already-invalid": func(t *testing.T) test {
			o, err := newO()
			assert.FatalError(t, err)
			o.Status = StatusInvalid
			return test{
				o:   o,
				res: o,
			}
		},
		"fail/already-valid": func(t *testing.T) test {
			o, err := newO()
			assert.FatalError(t, err)
			o.Status = StatusValid
			return test{
				o:   o,
				res: o,
			}
		},
		"fail/unexpected-status": func(t *testing.T) test {
			o, err := newO()
			assert.FatalError(t, err)
			o.Status = StatusDeactivated
			return test{
				o:   o,
				res: o,
				err: ServerInternalErr(errors.New("unrecognized order status: deactivated")),
			}
		},
		"fail/save-error": func(t *testing.T) test {
			o, err := newO()
			assert.FatalError(t, err)
			o.Expires = time.Now().UTC().Add(-time.Minute)
			return test{
				o:   o,
				res: o,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						return nil, false, errors.New("force")
					},
				},
				err: ServerInternalErr(errors.New("error storing order: force")),
			}
		},
		"ok/expired": func(t *testing.T) test {
			o, err := newO()
			assert.FatalError(t, err)
			o.Expires = time.Now().UTC().Add(-time.Minute)

			_o := *o
			clone := &_o
			clone.Error = MalformedErr(errors.New("order has expired"))
			clone.Status = StatusInvalid
			return test{
				o:   o,
				res: clone,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						return nil, true, nil
					},
				},
			}
		},
		"fail/get-authz-error": func(t *testing.T) test {
			o, err := newO()
			assert.FatalError(t, err)
			return test{
				o:   o,
				res: o,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						return nil, errors.New("force")
					},
				},
				err: ServerInternalErr(errors.New("error loading authz")),
			}
		},
		"ok/still-pending": func(t *testing.T) test {
			az1, err := newAz()
			assert.FatalError(t, err)
			az2, err := newAz()
			assert.FatalError(t, err)
			az3, err := newAz()
			assert.FatalError(t, err)

			ch1, err := newHTTPCh()
			assert.FatalError(t, err)
			ch2, err := newTLSALPNCh()
			assert.FatalError(t, err)
			ch3, err := newDNSCh()
			assert.FatalError(t, err)

			ch1b, err := json.Marshal(ch1)
			assert.FatalError(t, err)
			ch2b, err := json.Marshal(ch2)
			assert.FatalError(t, err)
			ch3b, err := json.Marshal(ch3)
			assert.FatalError(t, err)

			o, err := newO()
			assert.FatalError(t, err)
			o.Authorizations = []string{az1.getID(), az2.getID(), az3.getID()}

			_az3, ok := az3.(*dnsAuthz)
			assert.Fatal(t, ok)
			_az3.baseAuthz.Status = StatusValid

			b1, err := json.Marshal(az1)
			assert.FatalError(t, err)
			b2, err := json.Marshal(az2)
			assert.FatalError(t, err)
			b3, err := json.Marshal(az3)
			assert.FatalError(t, err)

			count := 0
			return test{
				o:   o,
				res: o,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						var ret []byte
						switch count {
						case 0:
							ret = b1
						case 1:
							ret = ch1b
						case 2:
							ret = ch2b
						case 3:
							ret = ch3b
						case 4:
							ret = b2
						case 5:
							ret = ch1b
						case 6:
							ret = ch2b
						case 7:
							ret = ch3b
						case 8:
							ret = b3
						default:
							return nil, errors.New("unexpected count")
						}
						count++
						return ret, nil
					},
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						return nil, true, nil
					},
				},
			}
		},
		"ok/invalid": func(t *testing.T) test {
			az1, err := newAz()
			assert.FatalError(t, err)
			az2, err := newAz()
			assert.FatalError(t, err)
			az3, err := newAz()
			assert.FatalError(t, err)

			ch1, err := newHTTPCh()
			assert.FatalError(t, err)
			ch2, err := newTLSALPNCh()
			assert.FatalError(t, err)
			ch3, err := newDNSCh()
			assert.FatalError(t, err)

			ch1b, err := json.Marshal(ch1)
			assert.FatalError(t, err)
			ch2b, err := json.Marshal(ch2)
			assert.FatalError(t, err)
			ch3b, err := json.Marshal(ch3)
			assert.FatalError(t, err)

			o, err := newO()
			assert.FatalError(t, err)
			o.Authorizations = []string{az1.getID(), az2.getID(), az3.getID()}

			_az3, ok := az3.(*dnsAuthz)
			assert.Fatal(t, ok)
			_az3.baseAuthz.Status = StatusInvalid

			b1, err := json.Marshal(az1)
			assert.FatalError(t, err)
			b2, err := json.Marshal(az2)
			assert.FatalError(t, err)
			b3, err := json.Marshal(az3)
			assert.FatalError(t, err)

			_o := *o
			clone := &_o
			clone.Status = StatusInvalid

			count := 0
			return test{
				o:   o,
				res: clone,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						var ret []byte
						switch count {
						case 0:
							ret = b1
						case 1:
							ret = ch1b
						case 2:
							ret = ch2b
						case 3:
							ret = ch3b
						case 4:
							ret = b2
						case 5:
							ret = ch1b
						case 6:
							ret = ch2b
						case 7:
							ret = ch3b
						case 8:
							ret = b3
						default:
							return nil, errors.New("unexpected count")
						}
						count++
						return ret, nil
					},
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						return nil, true, nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			o, err := tc.o.updateStatus(tc.db)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					expB, err := json.Marshal(tc.res)
					assert.FatalError(t, err)
					b, err := json.Marshal(o)
					assert.FatalError(t, err)
					assert.Equals(t, expB, b)
				}
			}
		})
	}
}

type mockSignAuth struct {
	sign                func(csr *x509.CertificateRequest, signOpts provisioner.SignOptions, extraOpts ...provisioner.SignOption) ([]*x509.Certificate, error)
	loadProvisionerByID func(string) (provisioner.Interface, error)
	ret1, ret2          interface{}
	err                 error
}

func (m *mockSignAuth) Sign(csr *x509.CertificateRequest, signOpts provisioner.SignOptions, extraOpts ...provisioner.SignOption) ([]*x509.Certificate, error) {
	if m.sign != nil {
		return m.sign(csr, signOpts, extraOpts...)
	} else if m.err != nil {
		return nil, m.err
	}
	return []*x509.Certificate{m.ret1.(*x509.Certificate), m.ret2.(*x509.Certificate)}, m.err
}

func (m *mockSignAuth) LoadProvisionerByID(id string) (provisioner.Interface, error) {
	if m.loadProvisionerByID != nil {
		return m.loadProvisionerByID(id)
	}
	return m.ret1.(provisioner.Interface), m.err
}

func TestOrderFinalize(t *testing.T) {
	prov := newProv()
	type test struct {
		o, res *order
		err    *Error
		db     nosql.DB
		csr    *x509.CertificateRequest
		sa     SignAuthority
		prov   Provisioner
	}
	tests := map[string]func(t *testing.T) test{
		"fail/already-invalid": func(t *testing.T) test {
			o, err := newO()
			assert.FatalError(t, err)
			o.Status = StatusInvalid
			return test{
				o:   o,
				err: OrderNotReadyErr(errors.Errorf("order %s has been abandoned", o.ID)),
			}
		},
		"ok/already-valid": func(t *testing.T) test {
			o, err := newO()
			assert.FatalError(t, err)
			o.Status = StatusValid
			o.Certificate = "cert-id"
			return test{
				o:   o,
				res: o,
			}
		},
		"fail/still-pending": func(t *testing.T) test {
			az1, err := newAz()
			assert.FatalError(t, err)
			az2, err := newAz()
			assert.FatalError(t, err)
			az3, err := newAz()
			assert.FatalError(t, err)

			ch1, err := newHTTPCh()
			assert.FatalError(t, err)
			ch2, err := newTLSALPNCh()
			assert.FatalError(t, err)
			ch3, err := newDNSCh()
			assert.FatalError(t, err)

			ch1b, err := json.Marshal(ch1)
			assert.FatalError(t, err)
			ch2b, err := json.Marshal(ch2)
			assert.FatalError(t, err)
			ch3b, err := json.Marshal(ch3)
			assert.FatalError(t, err)

			o, err := newO()
			assert.FatalError(t, err)
			o.Authorizations = []string{az1.getID(), az2.getID(), az3.getID()}

			_az3, ok := az3.(*dnsAuthz)
			assert.Fatal(t, ok)
			_az3.baseAuthz.Status = StatusValid

			b1, err := json.Marshal(az1)
			assert.FatalError(t, err)
			b2, err := json.Marshal(az2)
			assert.FatalError(t, err)
			b3, err := json.Marshal(az3)
			assert.FatalError(t, err)

			count := 0
			return test{
				o:   o,
				res: o,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						var ret []byte
						switch count {
						case 0:
							ret = b1
						case 1:
							ret = ch1b
						case 2:
							ret = ch2b
						case 3:
							ret = ch3b
						case 4:
							ret = b2
						case 5:
							ret = ch1b
						case 6:
							ret = ch2b
						case 7:
							ret = ch3b
						case 8:
							ret = b3
						default:
							return nil, errors.New("unexpected count")
						}
						count++
						return ret, nil
					},
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						return nil, true, nil
					},
				},
				err: OrderNotReadyErr(errors.Errorf("order %s is not ready", o.ID)),
			}
		},
		"fail/ready/csr-names-match-error": func(t *testing.T) test {
			o, err := newO()
			assert.FatalError(t, err)
			o.Status = StatusReady

			csr := &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "acme.example.com",
				},
				DNSNames: []string{"acme.example.com", "fail.smallstep.com"},
			}
			return test{
				o:   o,
				csr: csr,
				err: BadCSRErr(errors.Errorf("CSR names do not match identifiers exactly")),
			}
		},
		"fail/ready/csr-names-match-error-2": func(t *testing.T) test {
			o, err := newO()
			assert.FatalError(t, err)
			o.Status = StatusReady

			csr := &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "",
				},
				DNSNames: []string{"acme.example.com"},
			}
			return test{
				o:   o,
				csr: csr,
				err: BadCSRErr(errors.Errorf("CSR names do not match identifiers exactly")),
			}
		},
		"fail/ready/no-ipAddresses": func(t *testing.T) test {
			o, err := newO()
			assert.FatalError(t, err)
			o.Status = StatusReady

			csr := &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "",
				},
				// DNSNames:    []string{"acme.example.com", "step.example.com"},
				IPAddresses: []net.IP{net.ParseIP("1.1.1.1")},
			}
			return test{
				o:   o,
				csr: csr,
				err: BadCSRErr(errors.Errorf("CSR names do not match identifiers exactly")),
			}
		},
		"fail/ready/no-emailAddresses": func(t *testing.T) test {
			o, err := newO()
			assert.FatalError(t, err)
			o.Status = StatusReady

			csr := &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "",
				},
				// DNSNames:       []string{"acme.example.com", "step.example.com"},
				EmailAddresses: []string{"max@smallstep.com", "mariano@smallstep.com"},
			}
			return test{
				o:   o,
				csr: csr,
				err: BadCSRErr(errors.Errorf("CSR names do not match identifiers exactly")),
			}
		},
		"fail/ready/no-URIs": func(t *testing.T) test {
			o, err := newO()
			assert.FatalError(t, err)
			o.Status = StatusReady

			u, err := url.Parse("https://google.com")
			assert.FatalError(t, err)
			csr := &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "",
				},
				// DNSNames: []string{"acme.example.com", "step.example.com"},
				URIs: []*url.URL{u},
			}
			return test{
				o:   o,
				csr: csr,
				err: BadCSRErr(errors.Errorf("CSR names do not match identifiers exactly")),
			}
		},
		"fail/ready/provisioner-auth-sign-error": func(t *testing.T) test {
			o, err := newO()
			assert.FatalError(t, err)
			o.Status = StatusReady

			csr := &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "acme.example.com",
				},
				DNSNames: []string{"step.example.com", "acme.example.com"},
			}
			return test{
				o:   o,
				csr: csr,
				err: ServerInternalErr(errors.New("error retrieving authorization options from ACME provisioner: force")),
				prov: &MockProvisioner{
					MauthorizeSign: func(ctx context.Context, token string) ([]provisioner.SignOption, error) {
						return nil, errors.New("force")
					},
				},
			}
		},
		"fail/ready/sign-cert-error": func(t *testing.T) test {
			o, err := newO()
			assert.FatalError(t, err)
			o.Status = StatusReady

			csr := &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "acme.example.com",
				},
				DNSNames: []string{"step.example.com", "acme.example.com"},
			}
			return test{
				o:   o,
				csr: csr,
				err: ServerInternalErr(errors.Errorf("error generating certificate for order %s: force", o.ID)),
				sa: &mockSignAuth{
					err: errors.New("force"),
				},
			}
		},
		"fail/ready/store-cert-error": func(t *testing.T) test {
			o, err := newO()
			assert.FatalError(t, err)
			o.Status = StatusReady

			csr := &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "acme.example.com",
				},
				DNSNames: []string{"step.example.com", "acme.example.com"},
			}
			crt := &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "acme.example.com",
				},
			}
			inter := &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "intermediate",
				},
			}
			return test{
				o:   o,
				csr: csr,
				err: ServerInternalErr(errors.Errorf("error storing certificate: force")),
				sa: &mockSignAuth{
					ret1: crt, ret2: inter,
				},
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						return nil, false, errors.New("force")
					},
				},
			}
		},
		"fail/ready/store-order-error": func(t *testing.T) test {
			o, err := newO()
			assert.FatalError(t, err)
			o.Status = StatusReady

			csr := &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "acme.example.com",
				},
				DNSNames: []string{"acme.example.com", "step.example.com"},
			}
			crt := &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "acme.example.com",
				},
			}
			inter := &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "intermediate",
				},
			}
			count := 0
			return test{
				o:   o,
				csr: csr,
				err: ServerInternalErr(errors.Errorf("error storing order: force")),
				sa: &mockSignAuth{
					ret1: crt, ret2: inter,
				},
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						if count == 1 {
							return nil, false, errors.New("force")
						}
						count++
						return nil, true, nil
					},
				},
			}
		},
		"ok/ready/sign": func(t *testing.T) test {
			o, err := newO()
			assert.FatalError(t, err)
			o.Status = StatusReady

			csr := &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "acme.example.com",
				},
				DNSNames: []string{"acme.example.com", "step.example.com"},
			}
			crt := &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "acme.example.com",
				},
			}
			inter := &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "intermediate",
				},
			}

			_o := *o
			clone := &_o
			clone.Status = StatusValid

			count := 0
			return test{
				o:   o,
				res: clone,
				csr: csr,
				sa: &mockSignAuth{
					sign: func(csr *x509.CertificateRequest, pops provisioner.SignOptions, signOps ...provisioner.SignOption) ([]*x509.Certificate, error) {
						assert.Equals(t, len(signOps), 6)
						return []*x509.Certificate{crt, inter}, nil
					},
				},
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						if count == 0 {
							clone.Certificate = string(key)
						}
						count++
						return nil, true, nil
					},
				},
			}
		},
		"ok/ready/no-sans": func(t *testing.T) test {
			o, err := newO()
			assert.FatalError(t, err)
			o.Status = StatusReady
			o.Identifiers = []Identifier{
				{Type: "dns", Value: "step.example.com"},
			}

			csr := &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "step.example.com",
				},
			}
			crt := &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "step.example.com",
				},
				DNSNames: []string{"step.example.com"},
			}
			inter := &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "intermediate",
				},
			}

			clone := *o
			clone.Status = StatusValid
			count := 0
			return test{
				o:   o,
				res: &clone,
				csr: csr,
				sa: &mockSignAuth{
					sign: func(csr *x509.CertificateRequest, pops provisioner.SignOptions, signOps ...provisioner.SignOption) ([]*x509.Certificate, error) {
						assert.Equals(t, len(signOps), 6)
						return []*x509.Certificate{crt, inter}, nil
					},
				},
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						if count == 0 {
							clone.Certificate = string(key)
						}
						count++
						return nil, true, nil
					},
				},
			}
		},
		"ok/ready/sans-and-name": func(t *testing.T) test {
			o, err := newO()
			assert.FatalError(t, err)
			o.Status = StatusReady

			csr := &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "acme.example.com",
				},
				DNSNames: []string{"step.example.com"},
			}
			crt := &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "acme.example.com",
				},
				DNSNames: []string{"acme.example.com", "step.example.com"},
			}
			inter := &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "intermediate",
				},
			}

			clone := *o
			clone.Status = StatusValid
			count := 0
			return test{
				o:   o,
				res: &clone,
				csr: csr,
				sa: &mockSignAuth{
					sign: func(csr *x509.CertificateRequest, pops provisioner.SignOptions, signOps ...provisioner.SignOption) ([]*x509.Certificate, error) {
						assert.Equals(t, len(signOps), 6)
						return []*x509.Certificate{crt, inter}, nil
					},
				},
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						if count == 0 {
							clone.Certificate = string(key)
						}
						count++
						return nil, true, nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			p := tc.prov
			if p == nil {
				p = prov
			}
			o, err := tc.o.finalize(tc.db, tc.csr, tc.sa, p)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					expB, err := json.Marshal(tc.res)
					assert.FatalError(t, err)
					b, err := json.Marshal(o)
					assert.FatalError(t, err)
					assert.Equals(t, expB, b)
				}
			}
		})
	}
}

func Test_getOrderIDsByAccount(t *testing.T) {
	type test struct {
		id  string
		db  nosql.DB
		res []string
		err *Error
	}
	tests := map[string]func(t *testing.T) test{
		"ok/not-found": func(t *testing.T) test {
			return test{
				id: "foo",
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						return nil, database.ErrNotFound
					},
				},
				res: []string{},
			}
		},
		"fail/db-error": func(t *testing.T) test {
			return test{
				id: "foo",
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						return nil, errors.New("force")
					},
				},
				err: ServerInternalErr(errors.New("error loading orderIDs for account foo: force")),
			}
		},
		"fail/unmarshal-error": func(t *testing.T) test {
			return test{
				id: "foo",
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, ordersByAccountIDTable)
						assert.Equals(t, key, []byte("foo"))
						return nil, nil
					},
				},
				err: ServerInternalErr(errors.New("error unmarshaling orderIDs for account foo: unexpected end of JSON input")),
			}
		},
		"fail/error-loading-order-from-order-IDs": func(t *testing.T) test {
			oids := []string{"o1", "o2", "o3"}
			boids, err := json.Marshal(oids)
			assert.FatalError(t, err)
			dbHit := 0
			return test{
				id: "foo",
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						dbHit++
						switch dbHit {
						case 1:
							assert.Equals(t, bucket, ordersByAccountIDTable)
							assert.Equals(t, key, []byte("foo"))
							return boids, nil
						case 2:
							assert.Equals(t, bucket, orderTable)
							assert.Equals(t, key, []byte("o1"))
							return nil, errors.New("force")
						default:
							assert.FatalError(t, errors.New("should not be here"))
							return nil, nil
						}
					},
				},
				err: ServerInternalErr(errors.New("error loading order o1 for account foo: error loading order o1: force")),
			}
		},
		"fail/error-updating-order-from-order-IDs": func(t *testing.T) test {
			oids := []string{"o1", "o2", "o3"}
			boids, err := json.Marshal(oids)
			assert.FatalError(t, err)

			o, err := newO()
			assert.FatalError(t, err)
			bo, err := json.Marshal(o)
			assert.FatalError(t, err)

			dbHit := 0
			return test{
				id: "foo",
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						dbHit++
						switch dbHit {
						case 1:
							assert.Equals(t, bucket, ordersByAccountIDTable)
							assert.Equals(t, key, []byte("foo"))
							return boids, nil
						case 2:
							assert.Equals(t, bucket, orderTable)
							assert.Equals(t, key, []byte("o1"))
							return bo, nil
						case 3:
							assert.Equals(t, bucket, authzTable)
							assert.Equals(t, key, []byte(o.Authorizations[0]))
							return nil, errors.New("force")
						default:
							assert.FatalError(t, errors.New("should not be here"))
							return nil, nil
						}
					},
				},
				err: ServerInternalErr(errors.Errorf("error updating order o1 for account foo: error loading authz %s: force", o.Authorizations[0])),
			}
		},
		"ok/no-change-to-pending-orders": func(t *testing.T) test {
			oids := []string{"o1", "o2", "o3"}
			boids, err := json.Marshal(oids)
			assert.FatalError(t, err)

			o, err := newO()
			assert.FatalError(t, err)
			bo, err := json.Marshal(o)
			assert.FatalError(t, err)

			az, err := newAz()
			assert.FatalError(t, err)
			baz, err := json.Marshal(az)
			assert.FatalError(t, err)

			ch, err := newDNSCh()
			assert.FatalError(t, err)
			bch, err := json.Marshal(ch)
			assert.FatalError(t, err)

			return test{
				id: "foo",
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						switch string(bucket) {
						case string(ordersByAccountIDTable):
							assert.Equals(t, key, []byte("foo"))
							return boids, nil
						case string(orderTable):
							return bo, nil
						case string(authzTable):
							return baz, nil
						case string(challengeTable):
							return bch, nil
						default:
							assert.FatalError(t, errors.Errorf("did not expect query to table %s", bucket))
							return nil, nil
						}
					},
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						return nil, false, errors.New("should not be attempting to store anything")
					},
				},
				res: oids,
			}
		},
		"fail/error-storing-new-oids": func(t *testing.T) test {
			oids := []string{"o1", "o2", "o3"}
			boids, err := json.Marshal(oids)
			assert.FatalError(t, err)

			o, err := newO()
			assert.FatalError(t, err)
			bo, err := json.Marshal(o)
			assert.FatalError(t, err)

			invalidOrder, err := newO()
			assert.FatalError(t, err)
			invalidOrder.Status = StatusInvalid
			binvalidOrder, err := json.Marshal(invalidOrder)
			assert.FatalError(t, err)

			az, err := newAz()
			assert.FatalError(t, err)
			baz, err := json.Marshal(az)
			assert.FatalError(t, err)

			ch, err := newDNSCh()
			assert.FatalError(t, err)
			bch, err := json.Marshal(ch)
			assert.FatalError(t, err)

			dbGetOrder := 0
			return test{
				id: "foo",
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						switch string(bucket) {
						case string(ordersByAccountIDTable):
							assert.Equals(t, key, []byte("foo"))
							return boids, nil
						case string(orderTable):
							dbGetOrder++
							if dbGetOrder == 1 {
								return binvalidOrder, nil
							}
							return bo, nil
						case string(authzTable):
							return baz, nil
						case string(challengeTable):
							return bch, nil
						default:
							assert.FatalError(t, errors.Errorf("did not expect query to table %s", bucket))
							return nil, nil
						}
					},
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, ordersByAccountIDTable)
						assert.Equals(t, key, []byte("foo"))
						return nil, false, errors.New("force")
					},
				},
				err: ServerInternalErr(errors.New("error storing orderIDs as part of getOrderIDsByAccount logic: len(orderIDs) = 2: error storing order IDs for account foo: force")),
			}
		},
		"ok": func(t *testing.T) test {
			oids := []string{"o1", "o2", "o3", "o4"}
			boids, err := json.Marshal(oids)
			assert.FatalError(t, err)

			o, err := newO()
			assert.FatalError(t, err)
			bo, err := json.Marshal(o)
			assert.FatalError(t, err)

			invalidOrder, err := newO()
			assert.FatalError(t, err)
			invalidOrder.Status = StatusInvalid
			binvalidOrder, err := json.Marshal(invalidOrder)
			assert.FatalError(t, err)

			az, err := newAz()
			assert.FatalError(t, err)
			baz, err := json.Marshal(az)
			assert.FatalError(t, err)

			ch, err := newDNSCh()
			assert.FatalError(t, err)
			bch, err := json.Marshal(ch)
			assert.FatalError(t, err)

			dbGetOrder := 0
			return test{
				id: "foo",
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						switch string(bucket) {
						case string(ordersByAccountIDTable):
							assert.Equals(t, key, []byte("foo"))
							return boids, nil
						case string(orderTable):
							dbGetOrder++
							if dbGetOrder == 1 || dbGetOrder == 3 {
								return binvalidOrder, nil
							}
							return bo, nil
						case string(authzTable):
							return baz, nil
						case string(challengeTable):
							return bch, nil
						default:
							assert.FatalError(t, errors.Errorf("did not expect query to table %s", bucket))
							return nil, nil
						}
					},
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, ordersByAccountIDTable)
						assert.Equals(t, key, []byte("foo"))
						return nil, true, nil
					},
				},
				res: []string{"o2", "o4"},
			}
		},
		"ok/no-pending-orders": func(t *testing.T) test {
			oids := []string{"o1"}
			boids, err := json.Marshal(oids)
			assert.FatalError(t, err)

			invalidOrder, err := newO()
			assert.FatalError(t, err)
			invalidOrder.Status = StatusInvalid
			binvalidOrder, err := json.Marshal(invalidOrder)
			assert.FatalError(t, err)

			return test{
				id: "foo",
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						switch string(bucket) {
						case string(ordersByAccountIDTable):
							assert.Equals(t, key, []byte("foo"))
							return boids, nil
						case string(orderTable):
							return binvalidOrder, nil
						default:
							assert.FatalError(t, errors.Errorf("did not expect query to table %s", bucket))
							return nil, nil
						}
					},
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, ordersByAccountIDTable)
						assert.Equals(t, key, []byte("foo"))
						assert.Equals(t, old, boids)
						assert.Nil(t, newval)
						return nil, true, nil
					},
				},
				res: []string{},
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			var oiba = orderIDsByAccount{}
			if oids, err := oiba.unsafeGetOrderIDsByAccount(tc.db, tc.id); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, tc.res, oids)
				}
			}
		})
	}
}
