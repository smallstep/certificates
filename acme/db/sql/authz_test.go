package sql

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/certificates/db/sql/sqldatabase"
	nosqldb "github.com/smallstep/nosql/database"
)

func TestDB_getDBAuthz(t *testing.T) {
	azID := "azID"
	type test struct {
		db      sqldatabase.SQLDB
		err     error
		acmeErr *acme.Error
		dbaz    *dbAuthz
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/not-found": func(t *testing.T) test {
			return test{
				db: &db.MockSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, authzTable)
						assert.Equals(t, string(key), azID)

						return nil, sqldatabase.ErrNotFound
					},
				},
				acmeErr: acme.NewError(acme.ErrorMalformedType, "authz azID not found"),
			}
		},
		"fail/db.Get-error": func(t *testing.T) test {
			return test{
				db: &db.MockSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, authzTable)
						assert.Equals(t, string(key), azID)

						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading authz azID: force"),
			}
		},
		"fail/unmarshal-error": func(t *testing.T) test {
			return test{
				db: &db.MockSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, authzTable)
						assert.Equals(t, string(key), azID)

						return []byte("foo"), nil
					},
				},
				err: errors.New("error unmarshaling authz azID into dbAuthz"),
			}
		},
		"ok": func(t *testing.T) test {
			now := clock.Now()
			dbaz := &dbAuthz{
				ID:        azID,
				AccountID: "accountID",
				Identifier: acme.Identifier{
					Type:  "dns",
					Value: "test.ca.smallstep.com",
				},
				Status:       acme.StatusPending,
				Token:        "token",
				CreatedAt:    now,
				ExpiresAt:    now.Add(5 * time.Minute),
				Error:        acme.NewErrorISE("force"),
				ChallengeIDs: []string{"foo", "bar"},
				Wildcard:     true,
			}
			b, err := json.Marshal(dbaz)
			assert.FatalError(t, err)
			return test{
				db: &db.MockSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, authzTable)
						assert.Equals(t, string(key), azID)

						return b, nil
					},
				},
				dbaz: dbaz,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			db := DB{db: tc.db}
			if dbaz, err := db.getDBAuthz(context.Background(), azID); err != nil {
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
					assert.Equals(t, dbaz.ID, tc.dbaz.ID)
					assert.Equals(t, dbaz.AccountID, tc.dbaz.AccountID)
					assert.Equals(t, dbaz.Identifier, tc.dbaz.Identifier)
					assert.Equals(t, dbaz.Status, tc.dbaz.Status)
					assert.Equals(t, dbaz.Token, tc.dbaz.Token)
					assert.Equals(t, dbaz.CreatedAt, tc.dbaz.CreatedAt)
					assert.Equals(t, dbaz.ExpiresAt, tc.dbaz.ExpiresAt)
					assert.Equals(t, dbaz.Error.Error(), tc.dbaz.Error.Error())
					assert.Equals(t, dbaz.Wildcard, tc.dbaz.Wildcard)
				}
			}
		})
	}
}

func TestDB_GetAuthorization(t *testing.T) {
	azID := "azID"
	type test struct {
		db      sqldatabase.SQLDB
		err     error
		acmeErr *acme.Error
		dbaz    *dbAuthz
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/db.Get-error": func(t *testing.T) test {
			return test{
				db: &db.MockSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, authzTable)
						assert.Equals(t, string(key), azID)

						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading authz azID: force"),
			}
		},
		"fail/forward-acme-error": func(t *testing.T) test {
			return test{
				db: &db.MockSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, authzTable)
						assert.Equals(t, string(key), azID)

						return nil, nosqldb.ErrNotFound
					},
				},
				acmeErr: acme.NewError(acme.ErrorMalformedType, "authz azID not found"),
			}
		},
		"fail/db.GetChallenge-error": func(t *testing.T) test {
			now := clock.Now()
			dbaz := &dbAuthz{
				ID:        azID,
				AccountID: "accountID",
				Identifier: acme.Identifier{
					Type:  "dns",
					Value: "test.ca.smallstep.com",
				},
				Status:       acme.StatusPending,
				Token:        "token",
				CreatedAt:    now,
				ExpiresAt:    now.Add(5 * time.Minute),
				Error:        acme.NewErrorISE("force"),
				ChallengeIDs: []string{"foo", "bar"},
				Wildcard:     true,
			}
			b, err := json.Marshal(dbaz)
			assert.FatalError(t, err)
			return test{
				db: &db.MockSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						switch string(bucket) {
						case string(authzTable):
							assert.Equals(t, string(key), azID)
							return b, nil
						case string(challengeTable):
							assert.Equals(t, string(key), "foo")
							return nil, errors.New("force")
						default:
							assert.FatalError(t, errors.Errorf("unexpected bucket '%s'", string(bucket)))
							return nil, errors.New("force")
						}
					},
				},
				err: errors.New("error loading acme challenge foo: force"),
			}
		},
		"fail/db.GetChallenge-not-found": func(t *testing.T) test {
			now := clock.Now()
			dbaz := &dbAuthz{
				ID:        azID,
				AccountID: "accountID",
				Identifier: acme.Identifier{
					Type:  "dns",
					Value: "test.ca.smallstep.com",
				},
				Status:       acme.StatusPending,
				Token:        "token",
				CreatedAt:    now,
				ExpiresAt:    now.Add(5 * time.Minute),
				Error:        acme.NewErrorISE("force"),
				ChallengeIDs: []string{"foo", "bar"},
				Wildcard:     true,
			}
			b, err := json.Marshal(dbaz)
			assert.FatalError(t, err)
			return test{
				db: &db.MockSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						switch string(bucket) {
						case string(authzTable):
							assert.Equals(t, string(key), azID)
							return b, nil
						case string(challengeTable):
							assert.Equals(t, string(key), "foo")
							return nil, nosqldb.ErrNotFound
						default:
							assert.FatalError(t, errors.Errorf("unexpected bucket '%s'", string(bucket)))
							return nil, errors.New("force")
						}
					},
				},
				acmeErr: acme.NewError(acme.ErrorMalformedType, "challenge foo not found"),
			}
		},
		"ok": func(t *testing.T) test {
			now := clock.Now()
			dbaz := &dbAuthz{
				ID:        azID,
				AccountID: "accountID",
				Identifier: acme.Identifier{
					Type:  "dns",
					Value: "test.ca.smallstep.com",
				},
				Status:       acme.StatusPending,
				Token:        "token",
				CreatedAt:    now,
				ExpiresAt:    now.Add(5 * time.Minute),
				Error:        acme.NewErrorISE("force"),
				ChallengeIDs: []string{"foo", "bar"},
				Wildcard:     true,
			}
			b, err := json.Marshal(dbaz)
			assert.FatalError(t, err)
			chCount := 0
			fooChb, err := json.Marshal(&dbChallenge{ID: "foo"})
			assert.FatalError(t, err)
			barChb, err := json.Marshal(&dbChallenge{ID: "bar"})
			assert.FatalError(t, err)
			return test{
				db: &db.MockSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						switch string(bucket) {
						case string(authzTable):
							assert.Equals(t, string(key), azID)
							return b, nil
						case string(challengeTable):
							if chCount == 0 {
								chCount++
								assert.Equals(t, string(key), "foo")
								return fooChb, nil
							}
							assert.Equals(t, string(key), "bar")
							return barChb, nil
						default:
							assert.FatalError(t, errors.Errorf("unexpected bucket '%s'", string(bucket)))
							return nil, errors.New("force")
						}
					},
				},
				dbaz: dbaz,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			db := DB{db: tc.db}
			if az, err := db.GetAuthorization(context.Background(), azID); err != nil {
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
					assert.Equals(t, az.ID, tc.dbaz.ID)
					assert.Equals(t, az.AccountID, tc.dbaz.AccountID)
					assert.Equals(t, az.Identifier, tc.dbaz.Identifier)
					assert.Equals(t, az.Status, tc.dbaz.Status)
					assert.Equals(t, az.Token, tc.dbaz.Token)
					assert.Equals(t, az.Wildcard, tc.dbaz.Wildcard)
					assert.Equals(t, az.ExpiresAt, tc.dbaz.ExpiresAt)
					assert.Equals(t, az.Challenges, []*acme.Challenge{
						{ID: "foo"},
						{ID: "bar"},
					})
					assert.Equals(t, az.Error.Error(), tc.dbaz.Error.Error())
				}
			}
		})
	}
}

func TestDB_CreateAuthorization(t *testing.T) {
	azID := "azID"
	type test struct {
		db  sqldatabase.SQLDB
		az  *acme.Authorization
		err error
		_id *string
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/cmpAndSwap-error": func(t *testing.T) test {
			now := clock.Now()
			az := &acme.Authorization{
				ID:        azID,
				AccountID: "accountID",
				Identifier: acme.Identifier{
					Type:  "dns",
					Value: "test.ca.smallstep.com",
				},
				Status:    acme.StatusPending,
				Token:     "token",
				ExpiresAt: now.Add(5 * time.Minute),
				Challenges: []*acme.Challenge{
					{ID: "foo"},
					{ID: "bar"},
				},
				Wildcard: true,
				Error:    acme.NewErrorISE("force"),
			}
			return test{
				db: &db.MockSQLDB{
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, authzTable)
						assert.Equals(t, string(key), az.ID)
						assert.Equals(t, old, nil)

						dbaz := new(dbAuthz)
						assert.FatalError(t, json.Unmarshal(nu, dbaz))
						assert.Equals(t, dbaz.ID, string(key))
						assert.Equals(t, dbaz.AccountID, az.AccountID)
						assert.Equals(t, dbaz.Identifier, acme.Identifier{
							Type:  "dns",
							Value: "test.ca.smallstep.com",
						})
						assert.Equals(t, dbaz.Status, az.Status)
						assert.Equals(t, dbaz.Token, az.Token)
						assert.Equals(t, dbaz.ChallengeIDs, []string{"foo", "bar"})
						assert.Equals(t, dbaz.Wildcard, az.Wildcard)
						assert.Equals(t, dbaz.ExpiresAt, az.ExpiresAt)
						assert.Nil(t, dbaz.Error)
						assert.True(t, clock.Now().Add(-time.Minute).Before(dbaz.CreatedAt))
						assert.True(t, clock.Now().Add(time.Minute).After(dbaz.CreatedAt))
						return nil, false, errors.New("force")
					},
				},
				az:  az,
				err: errors.New("error saving acme authz: force"),
			}
		},
		"ok": func(t *testing.T) test {
			var (
				id    string
				idPtr = &id
				now   = clock.Now()
				az    = &acme.Authorization{
					ID:        azID,
					AccountID: "accountID",
					Identifier: acme.Identifier{
						Type:  "dns",
						Value: "test.ca.smallstep.com",
					},
					Status:    acme.StatusPending,
					Token:     "token",
					ExpiresAt: now.Add(5 * time.Minute),
					Challenges: []*acme.Challenge{
						{ID: "foo"},
						{ID: "bar"},
					},
					Wildcard: true,
					Error:    acme.NewErrorISE("force"),
				}
			)
			return test{
				db: &db.MockSQLDB{
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						*idPtr = string(key)
						assert.Equals(t, bucket, authzTable)
						assert.Equals(t, string(key), az.ID)
						assert.Equals(t, old, nil)

						dbaz := new(dbAuthz)
						assert.FatalError(t, json.Unmarshal(nu, dbaz))
						assert.Equals(t, dbaz.ID, string(key))
						assert.Equals(t, dbaz.AccountID, az.AccountID)
						assert.Equals(t, dbaz.Identifier, acme.Identifier{
							Type:  "dns",
							Value: "test.ca.smallstep.com",
						})
						assert.Equals(t, dbaz.Status, az.Status)
						assert.Equals(t, dbaz.Token, az.Token)
						assert.Equals(t, dbaz.ChallengeIDs, []string{"foo", "bar"})
						assert.Equals(t, dbaz.Wildcard, az.Wildcard)
						assert.Equals(t, dbaz.ExpiresAt, az.ExpiresAt)
						assert.Nil(t, dbaz.Error)
						assert.True(t, clock.Now().Add(-time.Minute).Before(dbaz.CreatedAt))
						assert.True(t, clock.Now().Add(time.Minute).After(dbaz.CreatedAt))
						return nu, true, nil
					},
				},
				az:  az,
				_id: idPtr,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			db := DB{db: tc.db}
			if err := db.CreateAuthorization(context.Background(), tc.az); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, tc.az.ID, *tc._id)
				}
			}
		})
	}
}

func TestDB_UpdateAuthorization(t *testing.T) {
	azID := "azID"
	now := clock.Now()
	dbaz := &dbAuthz{
		ID:        azID,
		AccountID: "accountID",
		Identifier: acme.Identifier{
			Type:  "dns",
			Value: "test.ca.smallstep.com",
		},
		Status:       acme.StatusPending,
		Token:        "token",
		CreatedAt:    now,
		ExpiresAt:    now.Add(5 * time.Minute),
		ChallengeIDs: []string{"foo", "bar"},
		Wildcard:     true,
	}
	b, err := json.Marshal(dbaz)
	assert.FatalError(t, err)
	type test struct {
		db  sqldatabase.SQLDB
		az  *acme.Authorization
		err error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/db.Get-error": func(t *testing.T) test {
			return test{
				az: &acme.Authorization{
					ID: azID,
				},
				db: &db.MockSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, authzTable)
						assert.Equals(t, string(key), azID)

						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading authz azID: force"),
			}
		},
		"fail/db.CmpAndSwap-error": func(t *testing.T) test {
			updAz := &acme.Authorization{
				ID:     azID,
				Status: acme.StatusValid,
				Error:  acme.NewError(acme.ErrorMalformedType, "malformed"),
			}
			return test{
				az: updAz,
				db: &db.MockSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, authzTable)
						assert.Equals(t, string(key), azID)

						return b, nil
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, authzTable)
						assert.Equals(t, old, b)

						dbOld := new(dbAuthz)
						assert.FatalError(t, json.Unmarshal(old, dbOld))
						assert.Equals(t, dbaz, dbOld)

						dbNew := new(dbAuthz)
						assert.FatalError(t, json.Unmarshal(nu, dbNew))
						assert.Equals(t, dbNew.ID, dbaz.ID)
						assert.Equals(t, dbNew.AccountID, dbaz.AccountID)
						assert.Equals(t, dbNew.Identifier, dbaz.Identifier)
						assert.Equals(t, dbNew.Status, acme.StatusValid)
						assert.Equals(t, dbNew.Token, dbaz.Token)
						assert.Equals(t, dbNew.ChallengeIDs, dbaz.ChallengeIDs)
						assert.Equals(t, dbNew.Wildcard, dbaz.Wildcard)
						assert.Equals(t, dbNew.CreatedAt, dbaz.CreatedAt)
						assert.Equals(t, dbNew.ExpiresAt, dbaz.ExpiresAt)
						assert.Equals(t, dbNew.Error.Error(), acme.NewError(acme.ErrorMalformedType, "malformed").Error())
						return nil, false, errors.New("force")
					},
				},
				err: errors.New("error saving acme authz: force"),
			}
		},
		"ok": func(t *testing.T) test {
			updAz := &acme.Authorization{
				ID:         azID,
				AccountID:  dbaz.AccountID,
				Status:     acme.StatusValid,
				Identifier: dbaz.Identifier,
				Challenges: []*acme.Challenge{
					{ID: "foo"},
					{ID: "bar"},
				},
				Token:     dbaz.Token,
				Wildcard:  dbaz.Wildcard,
				ExpiresAt: dbaz.ExpiresAt,
				Error:     acme.NewError(acme.ErrorMalformedType, "malformed"),
			}
			return test{
				az: updAz,
				db: &db.MockSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, authzTable)
						assert.Equals(t, string(key), azID)

						return b, nil
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, authzTable)
						assert.Equals(t, old, b)

						dbOld := new(dbAuthz)
						assert.FatalError(t, json.Unmarshal(old, dbOld))
						assert.Equals(t, dbaz, dbOld)

						dbNew := new(dbAuthz)
						assert.FatalError(t, json.Unmarshal(nu, dbNew))
						assert.Equals(t, dbNew.ID, dbaz.ID)
						assert.Equals(t, dbNew.AccountID, dbaz.AccountID)
						assert.Equals(t, dbNew.Identifier, dbaz.Identifier)
						assert.Equals(t, dbNew.Status, acme.StatusValid)
						assert.Equals(t, dbNew.Token, dbaz.Token)
						assert.Equals(t, dbNew.ChallengeIDs, dbaz.ChallengeIDs)
						assert.Equals(t, dbNew.Wildcard, dbaz.Wildcard)
						assert.Equals(t, dbNew.CreatedAt, dbaz.CreatedAt)
						assert.Equals(t, dbNew.ExpiresAt, dbaz.ExpiresAt)
						assert.Equals(t, dbNew.Error.Error(), acme.NewError(acme.ErrorMalformedType, "malformed").Error())
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
			if err := db.UpdateAuthorization(context.Background(), tc.az); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, tc.az.ID, dbaz.ID)
					assert.Equals(t, tc.az.AccountID, dbaz.AccountID)
					assert.Equals(t, tc.az.Identifier, dbaz.Identifier)
					assert.Equals(t, tc.az.Status, acme.StatusValid)
					assert.Equals(t, tc.az.Wildcard, dbaz.Wildcard)
					assert.Equals(t, tc.az.Token, dbaz.Token)
					assert.Equals(t, tc.az.ExpiresAt, dbaz.ExpiresAt)
					assert.Equals(t, tc.az.Challenges, []*acme.Challenge{
						{ID: "foo"},
						{ID: "bar"},
					})
					assert.Equals(t, tc.az.Error.Error(), acme.NewError(acme.ErrorMalformedType, "malformed").Error())
				}
			}
		})
	}
}
