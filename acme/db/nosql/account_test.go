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
	"go.step.sm/crypto/jose"
)

func TestDB_getDBAccount(t *testing.T) {
	accID := "accID"
	type test struct {
		db      nosql.DB
		err     error
		acmeErr *acme.Error
		dbacc   *dbAccount
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/not-found": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, accountTable)
						assert.Equals(t, string(key), accID)

						return nil, nosqldb.ErrNotFound
					},
				},
				err: acme.ErrNotFound,
			}
		},
		"fail/db.Get-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, accountTable)
						assert.Equals(t, string(key), accID)

						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading account accID: force"),
			}
		},
		"fail/unmarshal-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, accountTable)
						assert.Equals(t, string(key), accID)

						return []byte("foo"), nil
					},
				},
				err: errors.New("error unmarshaling account accID into dbAccount"),
			}
		},
		"ok": func(t *testing.T) test {
			now := clock.Now()
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			dbacc := &dbAccount{
				ID:            accID,
				Status:        acme.StatusDeactivated,
				CreatedAt:     now,
				DeactivatedAt: now,
				Contact:       []string{"foo", "bar"},
				Key:           jwk,
			}
			b, err := json.Marshal(dbacc)
			assert.FatalError(t, err)
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, accountTable)
						assert.Equals(t, string(key), accID)

						return b, nil
					},
				},
				dbacc: dbacc,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{db: tc.db}
			if dbacc, err := d.getDBAccount(context.Background(), accID); err != nil {
				var acmeErr *acme.Error
				if errors.As(err, &acmeErr) {
					if assert.NotNil(t, tc.acmeErr) {
						assert.Equals(t, acmeErr.Type, tc.acmeErr.Type)
						assert.Equals(t, acmeErr.Detail, tc.acmeErr.Detail)
						assert.Equals(t, acmeErr.Status, tc.acmeErr.Status)
						assert.Equals(t, acmeErr.Err.Error(), tc.acmeErr.Err.Error())
						assert.Equals(t, acmeErr.Detail, tc.acmeErr.Detail)
					}
				} else {
					if assert.NotNil(t, tc.err) {
						assert.HasPrefix(t, err.Error(), tc.err.Error())
					}
				}
			} else if assert.Nil(t, tc.err) {
				assert.Equals(t, dbacc.ID, tc.dbacc.ID)
				assert.Equals(t, dbacc.Status, tc.dbacc.Status)
				assert.Equals(t, dbacc.CreatedAt, tc.dbacc.CreatedAt)
				assert.Equals(t, dbacc.DeactivatedAt, tc.dbacc.DeactivatedAt)
				assert.Equals(t, dbacc.Contact, tc.dbacc.Contact)
				assert.Equals(t, dbacc.Key.KeyID, tc.dbacc.Key.KeyID)
			}
		})
	}
}

func TestDB_getAccountIDByKeyID(t *testing.T) {
	accID := "accID"
	kid := "kid"
	type test struct {
		db      nosql.DB
		err     error
		acmeErr *acme.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/not-found": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, accountByKeyIDTable)
						assert.Equals(t, string(key), kid)

						return nil, nosqldb.ErrNotFound
					},
				},
				err: acme.ErrNotFound,
			}
		},
		"fail/db.Get-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, accountByKeyIDTable)
						assert.Equals(t, string(key), kid)

						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading key-account index for key kid: force"),
			}
		},
		"ok": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, accountByKeyIDTable)
						assert.Equals(t, string(key), kid)

						return []byte(accID), nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{db: tc.db}
			if retAccID, err := d.getAccountIDByKeyID(context.Background(), kid); err != nil {
				var acmeErr *acme.Error
				if errors.As(err, &acmeErr) {
					if assert.NotNil(t, tc.acmeErr) {
						assert.Equals(t, acmeErr.Type, tc.acmeErr.Type)
						assert.Equals(t, acmeErr.Detail, tc.acmeErr.Detail)
						assert.Equals(t, acmeErr.Status, tc.acmeErr.Status)
						assert.Equals(t, acmeErr.Err.Error(), tc.acmeErr.Err.Error())
						assert.Equals(t, acmeErr.Detail, tc.acmeErr.Detail)
					}
				} else {
					if assert.NotNil(t, tc.err) {
						assert.HasPrefix(t, err.Error(), tc.err.Error())
					}
				}
			} else if assert.Nil(t, tc.err) {
				assert.Equals(t, retAccID, accID)
			}
		})
	}
}

func TestDB_GetAccount(t *testing.T) {
	accID := "accID"
	type test struct {
		db      nosql.DB
		err     error
		acmeErr *acme.Error
		dbacc   *dbAccount
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/db.Get-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, accountTable)
						assert.Equals(t, string(key), accID)

						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading account accID: force"),
			}
		},
		"ok": func(t *testing.T) test {
			now := clock.Now()
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			dbacc := &dbAccount{
				ID:            accID,
				Status:        acme.StatusDeactivated,
				CreatedAt:     now,
				DeactivatedAt: now,
				Contact:       []string{"foo", "bar"},
				Key:           jwk,
			}
			b, err := json.Marshal(dbacc)
			assert.FatalError(t, err)
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, accountTable)
						assert.Equals(t, string(key), accID)
						return b, nil
					},
				},
				dbacc: dbacc,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{db: tc.db}
			if acc, err := d.GetAccount(context.Background(), accID); err != nil {
				var acmeErr *acme.Error
				if errors.As(err, &acmeErr) {
					if assert.NotNil(t, tc.acmeErr) {
						assert.Equals(t, acmeErr.Type, tc.acmeErr.Type)
						assert.Equals(t, acmeErr.Detail, tc.acmeErr.Detail)
						assert.Equals(t, acmeErr.Status, tc.acmeErr.Status)
						assert.Equals(t, acmeErr.Err.Error(), tc.acmeErr.Err.Error())
						assert.Equals(t, acmeErr.Detail, tc.acmeErr.Detail)
					}
				} else {
					if assert.NotNil(t, tc.err) {
						assert.HasPrefix(t, err.Error(), tc.err.Error())
					}
				}
			} else if assert.Nil(t, tc.err) {
				assert.Equals(t, acc.ID, tc.dbacc.ID)
				assert.Equals(t, acc.Status, tc.dbacc.Status)
				assert.Equals(t, acc.Contact, tc.dbacc.Contact)
				assert.Equals(t, acc.Key.KeyID, tc.dbacc.Key.KeyID)
			}
		})
	}
}

func TestDB_GetAccountByKeyID(t *testing.T) {
	accID := "accID"
	kid := "kid"
	type test struct {
		db      nosql.DB
		err     error
		acmeErr *acme.Error
		dbacc   *dbAccount
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/db.getAccountIDByKeyID-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, string(bucket), string(accountByKeyIDTable))
						assert.Equals(t, string(key), kid)

						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading key-account index for key kid: force"),
			}
		},
		"fail/db.GetAccount-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						switch string(bucket) {
						case string(accountByKeyIDTable):
							assert.Equals(t, string(key), kid)
							return []byte(accID), nil
						case string(accountTable):
							assert.Equals(t, string(key), accID)
							return nil, errors.New("force")
						default:
							assert.FatalError(t, errors.Errorf("unexpected bucket %s", string(bucket)))
							return nil, errors.New("force")
						}
					},
				},
				err: errors.New("error loading account accID: force"),
			}
		},
		"ok": func(t *testing.T) test {
			now := clock.Now()
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			dbacc := &dbAccount{
				ID:            accID,
				Status:        acme.StatusDeactivated,
				CreatedAt:     now,
				DeactivatedAt: now,
				Contact:       []string{"foo", "bar"},
				Key:           jwk,
			}
			b, err := json.Marshal(dbacc)
			assert.FatalError(t, err)
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						switch string(bucket) {
						case string(accountByKeyIDTable):
							assert.Equals(t, string(key), kid)
							return []byte(accID), nil
						case string(accountTable):
							assert.Equals(t, string(key), accID)
							return b, nil
						default:
							assert.FatalError(t, errors.Errorf("unexpected bucket %s", string(bucket)))
							return nil, errors.New("force")
						}
					},
				},
				dbacc: dbacc,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{db: tc.db}
			if acc, err := d.GetAccountByKeyID(context.Background(), kid); err != nil {
				var acmeErr *acme.Error
				if errors.As(err, &acmeErr) {
					if assert.NotNil(t, tc.acmeErr) {
						assert.Equals(t, acmeErr.Type, tc.acmeErr.Type)
						assert.Equals(t, acmeErr.Detail, tc.acmeErr.Detail)
						assert.Equals(t, acmeErr.Status, tc.acmeErr.Status)
						assert.Equals(t, acmeErr.Err.Error(), tc.acmeErr.Err.Error())
						assert.Equals(t, acmeErr.Detail, tc.acmeErr.Detail)
					}
				} else {
					if assert.NotNil(t, tc.err) {
						assert.HasPrefix(t, err.Error(), tc.err.Error())
					}
				}
			} else if assert.Nil(t, tc.err) {
				assert.Equals(t, acc.ID, tc.dbacc.ID)
				assert.Equals(t, acc.Status, tc.dbacc.Status)
				assert.Equals(t, acc.Contact, tc.dbacc.Contact)
				assert.Equals(t, acc.Key.KeyID, tc.dbacc.Key.KeyID)
			}
		})
	}
}

func TestDB_CreateAccount(t *testing.T) {
	type test struct {
		db  nosql.DB
		acc *acme.Account
		err error
		_id *string
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/keyID-cmpAndSwap-error": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			acc := &acme.Account{
				Status:  acme.StatusValid,
				Contact: []string{"foo", "bar"},
				Key:     jwk,
			}
			return test{
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, accountByKeyIDTable)
						assert.Equals(t, string(key), jwk.KeyID)
						assert.Equals(t, old, nil)

						assert.Equals(t, nu, []byte(acc.ID))
						return nil, false, errors.New("force")
					},
				},
				acc: acc,
				err: errors.New("error storing keyID to accountID index: force"),
			}
		},
		"fail/keyID-cmpAndSwap-false": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			acc := &acme.Account{
				Status:  acme.StatusValid,
				Contact: []string{"foo", "bar"},
				Key:     jwk,
			}
			return test{
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, accountByKeyIDTable)
						assert.Equals(t, string(key), jwk.KeyID)
						assert.Equals(t, old, nil)

						assert.Equals(t, nu, []byte(acc.ID))
						return nil, false, nil
					},
				},
				acc: acc,
				err: errors.New("key-id to account-id index already exists"),
			}
		},
		"fail/account-save-error": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			acc := &acme.Account{
				Status:  acme.StatusValid,
				Contact: []string{"foo", "bar"},
				Key:     jwk,
			}
			return test{
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						switch string(bucket) {
						case string(accountByKeyIDTable):
							assert.Equals(t, string(key), jwk.KeyID)
							assert.Equals(t, old, nil)
							return nu, true, nil
						case string(accountTable):
							assert.Equals(t, string(key), acc.ID)
							assert.Equals(t, old, nil)

							dbacc := new(dbAccount)
							assert.FatalError(t, json.Unmarshal(nu, dbacc))
							assert.Equals(t, dbacc.ID, string(key))
							assert.Equals(t, dbacc.Contact, acc.Contact)
							assert.Equals(t, dbacc.Key.KeyID, acc.Key.KeyID)
							assert.True(t, clock.Now().Add(-time.Minute).Before(dbacc.CreatedAt))
							assert.True(t, clock.Now().Add(time.Minute).After(dbacc.CreatedAt))
							assert.True(t, dbacc.DeactivatedAt.IsZero())
							return nil, false, errors.New("force")
						default:
							assert.FatalError(t, errors.Errorf("unexpected bucket %s", string(bucket)))
							return nil, false, errors.New("force")
						}
					},
				},
				acc: acc,
				err: errors.New("error saving acme account: force"),
			}
		},
		"ok": func(t *testing.T) test {
			var (
				id    string
				idPtr = &id
			)
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			acc := &acme.Account{
				Status:  acme.StatusValid,
				Contact: []string{"foo", "bar"},
				Key:     jwk,
			}
			return test{
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						id = string(key)
						switch string(bucket) {
						case string(accountByKeyIDTable):
							assert.Equals(t, string(key), jwk.KeyID)
							assert.Equals(t, old, nil)
							return nu, true, nil
						case string(accountTable):
							assert.Equals(t, string(key), acc.ID)
							assert.Equals(t, old, nil)

							dbacc := new(dbAccount)
							assert.FatalError(t, json.Unmarshal(nu, dbacc))
							assert.Equals(t, dbacc.ID, string(key))
							assert.Equals(t, dbacc.Contact, acc.Contact)
							assert.Equals(t, dbacc.Key.KeyID, acc.Key.KeyID)
							assert.True(t, clock.Now().Add(-time.Minute).Before(dbacc.CreatedAt))
							assert.True(t, clock.Now().Add(time.Minute).After(dbacc.CreatedAt))
							assert.True(t, dbacc.DeactivatedAt.IsZero())
							return nu, true, nil
						default:
							assert.FatalError(t, errors.Errorf("unexpected bucket %s", string(bucket)))
							return nil, false, errors.New("force")
						}
					},
				},
				acc: acc,
				_id: idPtr,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{db: tc.db}
			if err := d.CreateAccount(context.Background(), tc.acc); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, tc.acc.ID, *tc._id)
				}
			}
		})
	}
}

func TestDB_UpdateAccount(t *testing.T) {
	accID := "accID"
	now := clock.Now()
	jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
	assert.FatalError(t, err)
	dbacc := &dbAccount{
		ID:            accID,
		Status:        acme.StatusDeactivated,
		CreatedAt:     now,
		DeactivatedAt: now,
		Contact:       []string{"foo", "bar"},
		Key:           jwk,
	}
	b, err := json.Marshal(dbacc)
	assert.FatalError(t, err)
	type test struct {
		db  nosql.DB
		acc *acme.Account
		err error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/db.Get-error": func(t *testing.T) test {
			return test{
				acc: &acme.Account{
					ID: accID,
				},
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, accountTable)
						assert.Equals(t, string(key), accID)

						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading account accID: force"),
			}
		},
		"fail/already-deactivated": func(t *testing.T) test {
			clone := dbacc.clone()
			clone.Status = acme.StatusDeactivated
			clone.DeactivatedAt = now
			dbaccb, err := json.Marshal(clone)
			assert.FatalError(t, err)
			acc := &acme.Account{
				ID:      accID,
				Status:  acme.StatusDeactivated,
				Contact: []string{"foo", "bar"},
			}
			return test{
				acc: acc,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, accountTable)
						assert.Equals(t, string(key), accID)

						return dbaccb, nil
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, accountTable)
						assert.Equals(t, old, b)

						dbNew := new(dbAccount)
						assert.FatalError(t, json.Unmarshal(nu, dbNew))
						assert.Equals(t, dbNew.ID, clone.ID)
						assert.Equals(t, dbNew.Status, clone.Status)
						assert.Equals(t, dbNew.Contact, clone.Contact)
						assert.Equals(t, dbNew.Key.KeyID, clone.Key.KeyID)
						assert.Equals(t, dbNew.CreatedAt, clone.CreatedAt)
						assert.Equals(t, dbNew.DeactivatedAt, clone.DeactivatedAt)
						return nil, false, errors.New("force")
					},
				},
				err: errors.New("error saving acme account: force"),
			}
		},
		"fail/db.CmpAndSwap-error": func(t *testing.T) test {
			acc := &acme.Account{
				ID:      accID,
				Status:  acme.StatusDeactivated,
				Contact: []string{"foo", "bar"},
			}
			return test{
				acc: acc,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, accountTable)
						assert.Equals(t, string(key), accID)

						return b, nil
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, accountTable)
						assert.Equals(t, old, b)

						dbNew := new(dbAccount)
						assert.FatalError(t, json.Unmarshal(nu, dbNew))
						assert.Equals(t, dbNew.ID, dbacc.ID)
						assert.Equals(t, dbNew.Status, acc.Status)
						assert.Equals(t, dbNew.Contact, dbacc.Contact)
						assert.Equals(t, dbNew.Key.KeyID, dbacc.Key.KeyID)
						assert.Equals(t, dbNew.CreatedAt, dbacc.CreatedAt)
						assert.True(t, dbNew.DeactivatedAt.Add(-time.Minute).Before(now))
						assert.True(t, dbNew.DeactivatedAt.Add(time.Minute).After(now))
						return nil, false, errors.New("force")
					},
				},
				err: errors.New("error saving acme account: force"),
			}
		},
		"ok": func(t *testing.T) test {
			acc := &acme.Account{
				ID:      accID,
				Status:  acme.StatusDeactivated,
				Contact: []string{"foo", "bar"},
				Key:     jwk,
			}
			return test{
				acc: acc,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, accountTable)
						assert.Equals(t, string(key), accID)

						return b, nil
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, accountTable)
						assert.Equals(t, old, b)

						dbNew := new(dbAccount)
						assert.FatalError(t, json.Unmarshal(nu, dbNew))
						assert.Equals(t, dbNew.ID, dbacc.ID)
						assert.Equals(t, dbNew.Status, acc.Status)
						assert.Equals(t, dbNew.Contact, dbacc.Contact)
						assert.Equals(t, dbNew.Key.KeyID, dbacc.Key.KeyID)
						assert.Equals(t, dbNew.CreatedAt, dbacc.CreatedAt)
						assert.True(t, dbNew.DeactivatedAt.Add(-time.Minute).Before(now))
						assert.True(t, dbNew.DeactivatedAt.Add(time.Minute).After(now))
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
			if err := d.UpdateAccount(context.Background(), tc.acc); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, tc.acc.ID, dbacc.ID)
					assert.Equals(t, tc.acc.Status, dbacc.Status)
					assert.Equals(t, tc.acc.Contact, dbacc.Contact)
					assert.Equals(t, tc.acc.Key.KeyID, dbacc.Key.KeyID)
				}
			}
		})
	}
}
