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
							assert.FatalError(t, errors.Errorf("unrecognized bucket %s", string(bucket)))
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
							assert.FatalError(t, errors.Errorf("unrecognized bucket %s", string(bucket)))
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
							assert.FatalError(t, errors.Errorf("unrecognized bucket %s", string(bucket)))
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
							assert.FatalError(t, errors.Errorf("unrecognized bucket %s", string(bucket)))
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

func TestDB_getDBExternalAccountKey(t *testing.T) {
	keyID := "keyID"
	type test struct {
		db      nosql.DB
		err     error
		acmeErr *acme.Error
		dbeak   *dbExternalAccountKey
	}
	var tests = map[string]func(t *testing.T) test{
		"ok": func(t *testing.T) test {
			now := clock.Now()
			dbeak := &dbExternalAccountKey{
				ID:          keyID,
				Provisioner: "prov",
				Reference:   "ref",
				AccountID:   "",
				KeyBytes:    []byte{1, 3, 3, 7},
				CreatedAt:   now,
			}
			b, err := json.Marshal(dbeak)
			assert.FatalError(t, err)
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, externalAccountKeyTable)
						assert.Equals(t, string(key), keyID)
						return b, nil
					},
				},
				err:   nil,
				dbeak: dbeak,
			}
		},
		"fail/not-found": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, externalAccountKeyTable)
						assert.Equals(t, string(key), keyID)
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
						assert.Equals(t, bucket, externalAccountKeyTable)
						assert.Equals(t, string(key), keyID)
						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading external account key keyID: force"),
			}
		},
		"fail/unmarshal-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, externalAccountKeyTable)
						assert.Equals(t, string(key), keyID)

						return []byte("foo"), nil
					},
				},
				err: errors.New("error unmarshaling external account key keyID into dbExternalAccountKey"),
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{db: tc.db}
			if dbeak, err := d.getDBExternalAccountKey(context.Background(), keyID); err != nil {
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
			} else if assert.Nil(t, tc.err) {
				assert.Equals(t, dbeak.ID, tc.dbeak.ID)
				assert.Equals(t, dbeak.KeyBytes, tc.dbeak.KeyBytes)
				assert.Equals(t, dbeak.Provisioner, tc.dbeak.Provisioner)
				assert.Equals(t, dbeak.Reference, tc.dbeak.Reference)
				assert.Equals(t, dbeak.CreatedAt, tc.dbeak.CreatedAt)
				assert.Equals(t, dbeak.AccountID, tc.dbeak.AccountID)
				assert.Equals(t, dbeak.BoundAt, tc.dbeak.BoundAt)
			}
		})
	}
}

func TestDB_GetExternalAccountKey(t *testing.T) {
	keyID := "keyID"
	prov := "acmeProv"
	type test struct {
		db      nosql.DB
		err     error
		acmeErr *acme.Error
		eak     *acme.ExternalAccountKey
	}
	var tests = map[string]func(t *testing.T) test{
		"ok": func(t *testing.T) test {
			now := clock.Now()
			dbeak := &dbExternalAccountKey{
				ID:          keyID,
				Provisioner: prov,
				Reference:   "ref",
				AccountID:   "",
				KeyBytes:    []byte{1, 3, 3, 7},
				CreatedAt:   now,
			}
			b, err := json.Marshal(dbeak)
			assert.FatalError(t, err)
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, externalAccountKeyTable)
						assert.Equals(t, string(key), keyID)
						return b, nil
					},
				},
				eak: &acme.ExternalAccountKey{
					ID:          keyID,
					Provisioner: prov,
					Reference:   "ref",
					AccountID:   "",
					KeyBytes:    []byte{1, 3, 3, 7},
					CreatedAt:   now,
				},
			}
		},
		"fail/db.Get-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, externalAccountKeyTable)
						assert.Equals(t, string(key), keyID)

						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading external account key keyID: force"),
			}
		},
		"fail/non-matching-provisioner": func(t *testing.T) test {
			now := clock.Now()
			dbeak := &dbExternalAccountKey{
				ID:          keyID,
				Provisioner: "aDifferentProv",
				Reference:   "ref",
				AccountID:   "",
				KeyBytes:    []byte{1, 3, 3, 7},
				CreatedAt:   now,
			}
			b, err := json.Marshal(dbeak)
			assert.FatalError(t, err)
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, externalAccountKeyTable)
						assert.Equals(t, string(key), keyID)
						return b, nil
					},
				},
				eak: &acme.ExternalAccountKey{
					ID:          keyID,
					Provisioner: prov,
					Reference:   "ref",
					AccountID:   "",
					KeyBytes:    []byte{1, 3, 3, 7},
					CreatedAt:   now,
				},
				acmeErr: acme.NewError(acme.ErrorUnauthorizedType, "name of provisioner does not match provisioner for which the EAB key was created"),
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{db: tc.db}
			if eak, err := d.GetExternalAccountKey(context.Background(), prov, keyID); err != nil {
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
			} else if assert.Nil(t, tc.err) {
				assert.Equals(t, eak.ID, tc.eak.ID)
				assert.Equals(t, eak.KeyBytes, tc.eak.KeyBytes)
				assert.Equals(t, eak.Provisioner, tc.eak.Provisioner)
				assert.Equals(t, eak.Reference, tc.eak.Reference)
				assert.Equals(t, eak.CreatedAt, tc.eak.CreatedAt)
				assert.Equals(t, eak.AccountID, tc.eak.AccountID)
				assert.Equals(t, eak.BoundAt, tc.eak.BoundAt)
			}
		})
	}
}

func TestDB_GetExternalAccountKeyByReference(t *testing.T) {
	keyID := "keyID"
	prov := "acmeProv"
	ref := "ref"
	type test struct {
		db      nosql.DB
		err     error
		ref     string
		acmeErr *acme.Error
		eak     *acme.ExternalAccountKey
	}
	var tests = map[string]func(t *testing.T) test{
		"ok": func(t *testing.T) test {
			now := clock.Now()
			dbeak := &dbExternalAccountKey{
				ID:          keyID,
				Provisioner: prov,
				Reference:   ref,
				AccountID:   "",
				KeyBytes:    []byte{1, 3, 3, 7},
				CreatedAt:   now,
			}
			dbref := &dbExternalAccountKeyReference{
				Reference:            ref,
				ExternalAccountKeyID: keyID,
			}
			b, err := json.Marshal(dbeak)
			assert.FatalError(t, err)
			dbrefBytes, err := json.Marshal(dbref)
			assert.FatalError(t, err)
			return test{
				ref: ref,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						switch string(bucket) {
						case string(externalAccountKeysByReferenceTable):
							assert.Equals(t, string(key), ref)
							return dbrefBytes, nil
						case string(externalAccountKeyTable):
							assert.Equals(t, string(key), keyID)
							return b, nil
						default:
							assert.FatalError(t, errors.Errorf("unrecognized bucket %s", string(bucket)))
							return nil, errors.New("force")
						}
					},
				},
				eak: &acme.ExternalAccountKey{
					ID:          keyID,
					Provisioner: prov,
					Reference:   ref,
					AccountID:   "",
					KeyBytes:    []byte{1, 3, 3, 7},
					CreatedAt:   now,
				},
				err: nil,
			}
		},
		"ok/no-reference": func(t *testing.T) test {
			return test{
				ref: "",
				eak: nil,
				err: nil,
			}
		},
		"fail/reference-not-found": func(t *testing.T) test {
			return test{
				ref: ref,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, string(bucket), string(externalAccountKeysByReferenceTable))
						assert.Equals(t, string(key), ref)
						return nil, nosqldb.ErrNotFound
					},
				},
				err: errors.New("not found"),
			}
		},
		"fail/reference-load-error": func(t *testing.T) test {
			return test{
				ref: ref,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, string(bucket), string(externalAccountKeysByReferenceTable))
						assert.Equals(t, string(key), ref)
						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading ACME EAB key for reference ref: force"),
			}
		},
		"fail/reference-unmarshal-error": func(t *testing.T) test {
			return test{
				ref: ref,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, string(bucket), string(externalAccountKeysByReferenceTable))
						assert.Equals(t, string(key), ref)
						return []byte{0}, nil
					},
				},
				err: errors.New("error unmarshaling ACME EAB key for reference ref"),
			}
		},
		"fail/db.GetExternalAccountKey-error": func(t *testing.T) test {
			dbref := &dbExternalAccountKeyReference{
				Reference:            ref,
				ExternalAccountKeyID: keyID,
			}
			dbrefBytes, err := json.Marshal(dbref)
			assert.FatalError(t, err)
			return test{
				ref: ref,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						switch string(bucket) {
						case string(externalAccountKeysByReferenceTable):
							assert.Equals(t, string(key), ref)
							return dbrefBytes, nil
						case string(externalAccountKeyTable):
							assert.Equals(t, string(key), keyID)
							return nil, errors.New("force")
						default:
							assert.FatalError(t, errors.Errorf("unrecognized bucket %s", string(bucket)))
							return nil, errors.New("force")
						}
					},
				},
				err: errors.New("error loading external account key keyID: force"),
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{db: tc.db}
			if eak, err := d.GetExternalAccountKeyByReference(context.Background(), prov, tc.ref); err != nil {
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
			} else if assert.Nil(t, tc.err) && tc.eak != nil {
				assert.Equals(t, eak.ID, tc.eak.ID)
				assert.Equals(t, eak.AccountID, tc.eak.AccountID)
				assert.Equals(t, eak.BoundAt, tc.eak.BoundAt)
				assert.Equals(t, eak.CreatedAt, tc.eak.CreatedAt)
				assert.Equals(t, eak.KeyBytes, tc.eak.KeyBytes)
				assert.Equals(t, eak.Provisioner, tc.eak.Provisioner)
				assert.Equals(t, eak.Reference, tc.eak.Reference)
			}
		})
	}
}

func TestDB_GetExternalAccountKeys(t *testing.T) {
	keyID1 := "keyID1"
	keyID2 := "keyID2"
	keyID3 := "keyID3"
	prov := "acmeProv"
	ref := "ref"
	type test struct {
		db      nosql.DB
		err     error
		acmeErr *acme.Error
		eaks    []*acme.ExternalAccountKey
	}
	var tests = map[string]func(t *testing.T) test{
		"ok": func(t *testing.T) test {
			now := clock.Now()
			dbeak1 := &dbExternalAccountKey{
				ID:          keyID1,
				Provisioner: prov,
				Reference:   ref,
				AccountID:   "",
				KeyBytes:    []byte{1, 3, 3, 7},
				CreatedAt:   now,
			}
			b1, err := json.Marshal(dbeak1)
			assert.FatalError(t, err)
			dbeak2 := &dbExternalAccountKey{
				ID:          keyID2,
				Provisioner: prov,
				Reference:   ref,
				AccountID:   "",
				KeyBytes:    []byte{1, 3, 3, 7},
				CreatedAt:   now,
			}
			b2, err := json.Marshal(dbeak2)
			assert.FatalError(t, err)
			dbeak3 := &dbExternalAccountKey{
				ID:          keyID3,
				Provisioner: "differentProvisioner",
				Reference:   ref,
				AccountID:   "",
				KeyBytes:    []byte{1, 3, 3, 7},
				CreatedAt:   now,
			}
			b3, err := json.Marshal(dbeak3)
			assert.FatalError(t, err)
			return test{
				db: &db.MockNoSQLDB{
					MList: func(bucket []byte) ([]*nosqldb.Entry, error) {
						assert.Equals(t, bucket, externalAccountKeyTable)
						return []*nosqldb.Entry{
							{
								Bucket: bucket,
								Key:    []byte(keyID1),
								Value:  b1,
							},
							{
								Bucket: bucket,
								Key:    []byte(keyID2),
								Value:  b2,
							},
							{
								Bucket: bucket,
								Key:    []byte(keyID3),
								Value:  b3,
							},
						}, nil
					},
				},
				eaks: []*acme.ExternalAccountKey{
					{
						ID:          keyID1,
						Provisioner: prov,
						Reference:   ref,
						AccountID:   "",
						KeyBytes:    []byte{1, 3, 3, 7},
						CreatedAt:   now,
					},
					{
						ID:          keyID2,
						Provisioner: prov,
						Reference:   ref,
						AccountID:   "",
						KeyBytes:    []byte{1, 3, 3, 7},
						CreatedAt:   now,
					},
				},
			}
		},
		"fail/db.List-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MList: func(bucket []byte) ([]*nosqldb.Entry, error) {
						assert.Equals(t, string(bucket), string(externalAccountKeyTable))
						return nil, errors.New("force")
					},
				},
				err: errors.New("force"),
			}
		},
		"fail/unmarshal-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MList: func(bucket []byte) ([]*nosqldb.Entry, error) {
						assert.Equals(t, bucket, externalAccountKeyTable)
						return []*nosqldb.Entry{
							{
								Bucket: bucket,
								Key:    []byte(keyID1),
								Value:  []byte("foo"),
							},
						}, nil
					},
				},
				eaks: []*acme.ExternalAccountKey{},
				err:  errors.Errorf("error unmarshaling external account key %s into ExternalAccountKey", keyID1),
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{db: tc.db}
			if eaks, err := d.GetExternalAccountKeys(context.Background(), prov); err != nil {
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
			} else if assert.Nil(t, tc.err) {
				assert.Equals(t, len(eaks), len(tc.eaks))
				for i, eak := range eaks {
					assert.Equals(t, eak.ID, tc.eaks[i].ID)
					assert.Equals(t, eak.KeyBytes, tc.eaks[i].KeyBytes)
					assert.Equals(t, eak.Provisioner, tc.eaks[i].Provisioner)
					assert.Equals(t, eak.Reference, tc.eaks[i].Reference)
					assert.Equals(t, eak.CreatedAt, tc.eaks[i].CreatedAt)
					assert.Equals(t, eak.AccountID, tc.eaks[i].AccountID)
					assert.Equals(t, eak.BoundAt, tc.eaks[i].BoundAt)
				}
			}
		})
	}
}

func TestDB_DeleteExternalAccountKey(t *testing.T) {
	keyID := "keyID"
	prov := "acmeProv"
	ref := "ref"
	type test struct {
		db      nosql.DB
		err     error
		acmeErr *acme.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"ok": func(t *testing.T) test {
			now := clock.Now()
			dbeak := &dbExternalAccountKey{
				ID:          keyID,
				Provisioner: prov,
				Reference:   ref,
				AccountID:   "",
				KeyBytes:    []byte{1, 3, 3, 7},
				CreatedAt:   now,
			}
			dbref := &dbExternalAccountKeyReference{
				Reference:            ref,
				ExternalAccountKeyID: keyID,
			}
			b, err := json.Marshal(dbeak)
			assert.FatalError(t, err)
			dbrefBytes, err := json.Marshal(dbref)
			assert.FatalError(t, err)
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						switch string(bucket) {
						case string(externalAccountKeysByReferenceTable):
							assert.Equals(t, string(key), ref)
							return dbrefBytes, nil
						case string(externalAccountKeyTable):
							assert.Equals(t, string(key), keyID)
							return b, nil
						default:
							assert.FatalError(t, errors.Errorf("unrecognized bucket %s", string(bucket)))
							return nil, errors.New("force")
						}
					},
					MDel: func(bucket, key []byte) error {
						switch string(bucket) {
						case string(externalAccountKeysByReferenceTable):
							assert.Equals(t, string(key), ref)
							return nil
						case string(externalAccountKeyTable):
							assert.Equals(t, string(key), keyID)
							return nil
						default:
							assert.FatalError(t, errors.Errorf("unrecognized bucket %s", string(bucket)))
							return errors.New("force")
						}
					},
				},
			}
		},
		"fail/not-found": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, string(bucket), string(externalAccountKeyTable))
						assert.Equals(t, string(key), keyID)
						return nil, nosqldb.ErrNotFound
					},
				},
				err: errors.New("error loading ACME EAB Key with Key ID keyID"),
			}
		},
		"fail/non-matching-provisioner": func(t *testing.T) test {
			now := clock.Now()
			dbeak := &dbExternalAccountKey{
				ID:          keyID,
				Provisioner: "differentProvisioner",
				Reference:   ref,
				AccountID:   "",
				KeyBytes:    []byte{1, 3, 3, 7},
				CreatedAt:   now,
			}
			b, err := json.Marshal(dbeak)
			assert.FatalError(t, err)
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, string(bucket), string(externalAccountKeyTable))
						assert.Equals(t, string(key), keyID)
						return b, nil
					},
				},
				err: errors.New("name of provisioner does not match provisioner for which the EAB key was created"),
			}
		},
		"fail/delete-reference": func(t *testing.T) test {
			now := clock.Now()
			dbeak := &dbExternalAccountKey{
				ID:          keyID,
				Provisioner: prov,
				Reference:   ref,
				AccountID:   "",
				KeyBytes:    []byte{1, 3, 3, 7},
				CreatedAt:   now,
			}
			dbref := &dbExternalAccountKeyReference{
				Reference:            ref,
				ExternalAccountKeyID: keyID,
			}
			b, err := json.Marshal(dbeak)
			assert.FatalError(t, err)
			dbrefBytes, err := json.Marshal(dbref)
			assert.FatalError(t, err)
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						switch string(bucket) {
						case string(externalAccountKeysByReferenceTable):
							assert.Equals(t, string(key), ref)
							return dbrefBytes, nil
						case string(externalAccountKeyTable):
							assert.Equals(t, string(key), keyID)
							return b, nil
						default:
							assert.FatalError(t, errors.Errorf("unrecognized bucket %s", string(bucket)))
							return nil, errors.New("force")
						}
					},
					MDel: func(bucket, key []byte) error {
						switch string(bucket) {
						case string(externalAccountKeysByReferenceTable):
							assert.Equals(t, string(key), ref)
							return errors.New("force")
						case string(externalAccountKeyTable):
							assert.Equals(t, string(key), keyID)
							return nil
						default:
							assert.FatalError(t, errors.Errorf("unrecognized bucket %s", string(bucket)))
							return errors.New("force")
						}
					},
				},
				err: errors.New("error deleting ACME EAB Key Reference with Key ID keyID and reference ref"),
			}
		},
		"fail/delete-eak": func(t *testing.T) test {
			now := clock.Now()
			dbeak := &dbExternalAccountKey{
				ID:          keyID,
				Provisioner: prov,
				Reference:   ref,
				AccountID:   "",
				KeyBytes:    []byte{1, 3, 3, 7},
				CreatedAt:   now,
			}
			dbref := &dbExternalAccountKeyReference{
				Reference:            ref,
				ExternalAccountKeyID: keyID,
			}
			b, err := json.Marshal(dbeak)
			assert.FatalError(t, err)
			dbrefBytes, err := json.Marshal(dbref)
			assert.FatalError(t, err)
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						switch string(bucket) {
						case string(externalAccountKeysByReferenceTable):
							assert.Equals(t, string(key), ref)
							return dbrefBytes, nil
						case string(externalAccountKeyTable):
							assert.Equals(t, string(key), keyID)
							return b, nil
						default:
							assert.FatalError(t, errors.Errorf("unrecognized bucket %s", string(bucket)))
							return nil, errors.New("force")
						}
					},
					MDel: func(bucket, key []byte) error {
						switch string(bucket) {
						case string(externalAccountKeysByReferenceTable):
							assert.Equals(t, string(key), ref)
							return nil
						case string(externalAccountKeyTable):
							assert.Equals(t, string(key), keyID)
							return errors.New("force")
						default:
							assert.FatalError(t, errors.Errorf("unrecognized bucket %s", string(bucket)))
							return errors.New("force")
						}
					},
				},
				err: errors.New("error deleting ACME EAB Key with Key ID keyID"),
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{db: tc.db}
			if err := d.DeleteExternalAccountKey(context.Background(), prov, keyID); err != nil {
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
				assert.Nil(t, tc.err)
			}
		})
	}
}

func TestDB_CreateExternalAccountKey(t *testing.T) {
	keyID := "keyID"
	prov := "acmeProv"
	ref := "ref"
	type test struct {
		db  nosql.DB
		err error
		_id *string
		eak *acme.ExternalAccountKey
	}
	var tests = map[string]func(t *testing.T) test{
		"ok": func(t *testing.T) test {
			var (
				id    string
				idPtr = &id
			)
			now := clock.Now()
			eak := &acme.ExternalAccountKey{
				ID:          keyID,
				Provisioner: prov,
				Reference:   "ref",
				AccountID:   "",
				CreatedAt:   now,
			}
			return test{
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {

						switch string(bucket) {
						case string(externalAccountKeysByReferenceTable):
							assert.Equals(t, string(key), ref)
							assert.Equals(t, old, nil)
							return nu, true, nil
						case string(externalAccountKeyTable):
							assert.Equals(t, old, nil)

							id = string(key)

							dbeak := new(dbExternalAccountKey)
							assert.FatalError(t, json.Unmarshal(nu, dbeak))
							assert.Equals(t, string(key), dbeak.ID)
							assert.Equals(t, eak.Provisioner, dbeak.Provisioner)
							assert.Equals(t, eak.Reference, dbeak.Reference)
							assert.Equals(t, 32, len(dbeak.KeyBytes))
							assert.False(t, dbeak.CreatedAt.IsZero())
							assert.Equals(t, dbeak.AccountID, eak.AccountID)
							assert.True(t, dbeak.BoundAt.IsZero())
							return nu, true, nil
						default:
							assert.FatalError(t, errors.Errorf("unrecognized bucket %s", string(bucket)))
							return nil, false, errors.New("force")
						}
					},
				},
				eak: eak,
				_id: idPtr,
			}
		},
		"fail/externalAccountKeyID-cmpAndSwap-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {

						switch string(bucket) {
						case string(externalAccountKeysByReferenceTable):
							assert.Equals(t, string(key), ref)
							assert.Equals(t, old, nil)
							return nu, true, nil
						case string(externalAccountKeyTable):
							assert.Equals(t, old, nil)
							return nu, true, errors.New("force")
						default:
							assert.FatalError(t, errors.Errorf("unrecognized bucket %s", string(bucket)))
							return nil, false, errors.New("force")
						}
					},
				},
				err: errors.New("error saving acme external_account_key"),
			}
		},
		"fail/externalAccountKeyReference-cmpAndSwap-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {

						switch string(bucket) {
						case string(externalAccountKeysByReferenceTable):
							assert.Equals(t, string(key), ref)
							assert.Equals(t, old, nil)
							return nu, true, errors.New("force")
						case string(externalAccountKeyTable):
							assert.Equals(t, old, nil)
							return nu, true, nil
						default:
							assert.FatalError(t, errors.Errorf("unrecognized bucket %s", string(bucket)))
							return nil, false, errors.New("force")
						}
					},
				},
				err: errors.New("error saving acme external_account_key"),
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{db: tc.db}
			eak, err := d.CreateExternalAccountKey(context.Background(), prov, ref)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else if assert.Nil(t, tc.err) {
				assert.Equals(t, *tc._id, eak.ID)
				assert.Equals(t, prov, eak.Provisioner)
				assert.Equals(t, ref, eak.Reference)
				assert.Equals(t, "", eak.AccountID)
				assert.False(t, eak.CreatedAt.IsZero())
				assert.False(t, eak.AlreadyBound())
				assert.True(t, eak.BoundAt.IsZero())
			}
		})
	}
}

func TestDB_UpdateExternalAccountKey(t *testing.T) {
	keyID := "keyID"
	prov := "acmeProv"
	ref := "ref"
	now := clock.Now()
	dbeak := &dbExternalAccountKey{
		ID:          keyID,
		Provisioner: prov,
		Reference:   ref,
		AccountID:   "",
		KeyBytes:    []byte{1, 3, 3, 7},
		CreatedAt:   now,
	}
	b, err := json.Marshal(dbeak)
	assert.FatalError(t, err)
	type test struct {
		db  nosql.DB
		eak *acme.ExternalAccountKey
		err error
	}
	var tests = map[string]func(t *testing.T) test{

		"ok": func(t *testing.T) test {
			eak := &acme.ExternalAccountKey{
				ID:          keyID,
				Provisioner: prov,
				Reference:   ref,
				AccountID:   "",
				KeyBytes:    []byte{1, 3, 3, 7},
				CreatedAt:   now,
			}
			return test{
				eak: eak,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, externalAccountKeyTable)
						assert.Equals(t, string(key), keyID)

						return b, nil
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, externalAccountKeyTable)
						assert.Equals(t, old, b)

						dbNew := new(dbExternalAccountKey)
						assert.FatalError(t, json.Unmarshal(nu, dbNew))
						assert.Equals(t, dbNew.ID, dbeak.ID)
						assert.Equals(t, dbNew.Provisioner, dbeak.Provisioner)
						assert.Equals(t, dbNew.Reference, dbeak.Reference)
						assert.Equals(t, dbNew.AccountID, dbeak.AccountID)
						assert.Equals(t, dbNew.CreatedAt, dbeak.CreatedAt)
						assert.Equals(t, dbNew.BoundAt, dbeak.BoundAt)
						assert.Equals(t, dbNew.KeyBytes, dbeak.KeyBytes)
						return nu, true, nil
					},
				},
			}
		},
		"fail/provisioner-mismatch": func(t *testing.T) test {
			newDBEAK := &dbExternalAccountKey{
				ID:          keyID,
				Provisioner: "differentProvisioner",
				Reference:   ref,
				AccountID:   "",
				KeyBytes:    []byte{1, 3, 3, 7},
				CreatedAt:   now,
			}
			b, err := json.Marshal(newDBEAK)
			assert.FatalError(t, err)
			return test{
				eak: &acme.ExternalAccountKey{
					ID: keyID,
				},
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, externalAccountKeyTable)
						assert.Equals(t, string(key), keyID)

						return b, nil
					},
				},
				err: errors.New("name of provisioner does not match provisioner for which the EAB key was created"),
			}
		},
		"fail/db.Get-error": func(t *testing.T) test {
			return test{
				eak: &acme.ExternalAccountKey{
					ID: keyID,
				},
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, externalAccountKeyTable)
						assert.Equals(t, string(key), keyID)

						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading external account key keyID: force"),
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{db: tc.db}
			if err := d.UpdateExternalAccountKey(context.Background(), prov, tc.eak); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else if assert.Nil(t, tc.err) {
				assert.Equals(t, dbeak.ID, tc.eak.ID)
				assert.Equals(t, dbeak.Provisioner, tc.eak.Provisioner)
				assert.Equals(t, dbeak.Reference, tc.eak.Reference)
				assert.Equals(t, dbeak.AccountID, tc.eak.AccountID)
				assert.Equals(t, dbeak.CreatedAt, tc.eak.CreatedAt)
				assert.Equals(t, dbeak.BoundAt, tc.eak.BoundAt)
				assert.Equals(t, dbeak.KeyBytes, tc.eak.KeyBytes)
			}
		})
	}
}
