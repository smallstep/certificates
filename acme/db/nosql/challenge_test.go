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

func TestDB_getDBChallenge(t *testing.T) {
	chID := "chID"
	type test struct {
		db      nosql.DB
		err     error
		acmeErr *acme.Error
		dbc     *dbChallenge
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/not-found": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, challengeTable)
						assert.Equals(t, string(key), chID)

						return nil, nosqldb.ErrNotFound
					},
				},
				acmeErr: acme.NewError(acme.ErrorMalformedType, "challenge chID not found"),
			}
		},
		"fail/db.Get-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, challengeTable)
						assert.Equals(t, string(key), chID)

						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading acme challenge chID: force"),
			}
		},
		"fail/unmarshal-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, challengeTable)
						assert.Equals(t, string(key), chID)

						return []byte("foo"), nil
					},
				},
				err: errors.New("error unmarshaling dbChallenge"),
			}
		},
		"ok": func(t *testing.T) test {
			dbc := &dbChallenge{
				ID:          chID,
				AccountID:   "accountID",
				Type:        "dns-01",
				Status:      acme.StatusPending,
				Token:       "token",
				Value:       "test.ca.smallstep.com",
				CreatedAt:   clock.Now(),
				ValidatedAt: "foobar",
				Error:       acme.NewErrorISE("The server experienced an internal error"),
			}
			b, err := json.Marshal(dbc)
			assert.FatalError(t, err)
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, challengeTable)
						assert.Equals(t, string(key), chID)

						return b, nil
					},
				},
				dbc: dbc,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{db: tc.db}
			if ch, err := d.getDBChallenge(context.Background(), chID); err != nil {
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
				assert.Equals(t, ch.ID, tc.dbc.ID)
				assert.Equals(t, ch.AccountID, tc.dbc.AccountID)
				assert.Equals(t, ch.Type, tc.dbc.Type)
				assert.Equals(t, ch.Status, tc.dbc.Status)
				assert.Equals(t, ch.Token, tc.dbc.Token)
				assert.Equals(t, ch.Value, tc.dbc.Value)
				assert.Equals(t, ch.ValidatedAt, tc.dbc.ValidatedAt)
				assert.Equals(t, ch.Error.Error(), tc.dbc.Error.Error())
			}
		})
	}
}

func TestDB_CreateChallenge(t *testing.T) {
	type test struct {
		db  nosql.DB
		ch  *acme.Challenge
		err error
		_id *string
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/cmpAndSwap-error": func(t *testing.T) test {
			ch := &acme.Challenge{
				AccountID: "accountID",
				Type:      "dns-01",
				Status:    acme.StatusPending,
				Token:     "token",
				Value:     "test.ca.smallstep.com",
			}
			return test{
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, challengeTable)
						assert.Equals(t, string(key), ch.ID)
						assert.Equals(t, old, nil)

						dbc := new(dbChallenge)
						assert.FatalError(t, json.Unmarshal(nu, dbc))
						assert.Equals(t, dbc.ID, string(key))
						assert.Equals(t, dbc.AccountID, ch.AccountID)
						assert.Equals(t, dbc.Type, ch.Type)
						assert.Equals(t, dbc.Status, ch.Status)
						assert.Equals(t, dbc.Token, ch.Token)
						assert.Equals(t, dbc.Value, ch.Value)
						assert.True(t, clock.Now().Add(-time.Minute).Before(dbc.CreatedAt))
						assert.True(t, clock.Now().Add(time.Minute).After(dbc.CreatedAt))
						return nil, false, errors.New("force")
					},
				},
				ch:  ch,
				err: errors.New("error saving acme challenge: force"),
			}
		},
		"ok": func(t *testing.T) test {
			var (
				id    string
				idPtr = &id
				ch    = &acme.Challenge{
					AccountID: "accountID",
					Type:      "dns-01",
					Status:    acme.StatusPending,
					Token:     "token",
					Value:     "test.ca.smallstep.com",
				}
			)

			return test{
				ch: ch,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						*idPtr = string(key)
						assert.Equals(t, bucket, challengeTable)
						assert.Equals(t, string(key), ch.ID)
						assert.Equals(t, old, nil)

						dbc := new(dbChallenge)
						assert.FatalError(t, json.Unmarshal(nu, dbc))
						assert.Equals(t, dbc.ID, string(key))
						assert.Equals(t, dbc.AccountID, ch.AccountID)
						assert.Equals(t, dbc.Type, ch.Type)
						assert.Equals(t, dbc.Status, ch.Status)
						assert.Equals(t, dbc.Token, ch.Token)
						assert.Equals(t, dbc.Value, ch.Value)
						assert.True(t, clock.Now().Add(-time.Minute).Before(dbc.CreatedAt))
						assert.True(t, clock.Now().Add(time.Minute).After(dbc.CreatedAt))
						return nil, true, nil
					},
				},
				_id: idPtr,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{db: tc.db}
			if err := d.CreateChallenge(context.Background(), tc.ch); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, tc.ch.ID, *tc._id)
				}
			}
		})
	}
}

func TestDB_GetChallenge(t *testing.T) {
	chID := "chID"
	azID := "azID"
	type test struct {
		db      nosql.DB
		err     error
		acmeErr *acme.Error
		dbc     *dbChallenge
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/db.Get-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, challengeTable)
						assert.Equals(t, string(key), chID)

						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading acme challenge chID: force"),
			}
		},
		"fail/forward-acme-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, challengeTable)
						assert.Equals(t, string(key), chID)

						return nil, nosqldb.ErrNotFound
					},
				},
				acmeErr: acme.NewError(acme.ErrorMalformedType, "challenge chID not found"),
			}
		},
		"ok": func(t *testing.T) test {
			dbc := &dbChallenge{
				ID:          chID,
				AccountID:   "accountID",
				Type:        "dns-01",
				Status:      acme.StatusPending,
				Token:       "token",
				Value:       "test.ca.smallstep.com",
				CreatedAt:   clock.Now(),
				ValidatedAt: "foobar",
				Error:       acme.NewErrorISE("The server experienced an internal error"),
			}
			b, err := json.Marshal(dbc)
			assert.FatalError(t, err)
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, challengeTable)
						assert.Equals(t, string(key), chID)

						return b, nil
					},
				},
				dbc: dbc,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{db: tc.db}
			if ch, err := d.GetChallenge(context.Background(), chID, azID); err != nil {
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
				assert.Equals(t, ch.ID, tc.dbc.ID)
				assert.Equals(t, ch.AccountID, tc.dbc.AccountID)
				assert.Equals(t, ch.Type, tc.dbc.Type)
				assert.Equals(t, ch.Status, tc.dbc.Status)
				assert.Equals(t, ch.Token, tc.dbc.Token)
				assert.Equals(t, ch.Value, tc.dbc.Value)
				assert.Equals(t, ch.ValidatedAt, tc.dbc.ValidatedAt)
				assert.Equals(t, ch.Error.Error(), tc.dbc.Error.Error())
			}
		})
	}
}

func TestDB_UpdateChallenge(t *testing.T) {
	chID := "chID"
	dbc := &dbChallenge{
		ID:        chID,
		AccountID: "accountID",
		Type:      "dns-01",
		Status:    acme.StatusPending,
		Token:     "token",
		Value:     "test.ca.smallstep.com",
		CreatedAt: clock.Now(),
	}
	b, err := json.Marshal(dbc)
	assert.FatalError(t, err)
	type test struct {
		db  nosql.DB
		ch  *acme.Challenge
		err error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/db.Get-error": func(t *testing.T) test {
			return test{
				ch: &acme.Challenge{
					ID: chID,
				},
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, challengeTable)
						assert.Equals(t, string(key), chID)

						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading acme challenge chID: force"),
			}
		},
		"fail/db.CmpAndSwap-error": func(t *testing.T) test {
			updCh := &acme.Challenge{
				ID:          chID,
				Status:      acme.StatusValid,
				ValidatedAt: "foobar",
				Error:       acme.NewError(acme.ErrorMalformedType, "The request message was malformed"),
			}
			return test{
				ch: updCh,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, challengeTable)
						assert.Equals(t, string(key), chID)

						return b, nil
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, challengeTable)
						assert.Equals(t, old, b)

						dbOld := new(dbChallenge)
						assert.FatalError(t, json.Unmarshal(old, dbOld))
						assert.Equals(t, dbc, dbOld)

						dbNew := new(dbChallenge)
						assert.FatalError(t, json.Unmarshal(nu, dbNew))
						assert.Equals(t, dbNew.ID, dbc.ID)
						assert.Equals(t, dbNew.AccountID, dbc.AccountID)
						assert.Equals(t, dbNew.Type, dbc.Type)
						assert.Equals(t, dbNew.Status, updCh.Status)
						assert.Equals(t, dbNew.Token, dbc.Token)
						assert.Equals(t, dbNew.Value, dbc.Value)
						assert.Equals(t, dbNew.Error.Error(), updCh.Error.Error())
						assert.Equals(t, dbNew.CreatedAt, dbc.CreatedAt)
						assert.Equals(t, dbNew.ValidatedAt, updCh.ValidatedAt)
						return nil, false, errors.New("force")
					},
				},
				err: errors.New("error saving acme challenge: force"),
			}
		},
		"ok": func(t *testing.T) test {
			updCh := &acme.Challenge{
				ID:          dbc.ID,
				AccountID:   dbc.AccountID,
				Type:        dbc.Type,
				Token:       dbc.Token,
				Value:       dbc.Value,
				Status:      acme.StatusValid,
				ValidatedAt: "foobar",
				Error:       acme.NewError(acme.ErrorMalformedType, "malformed"),
			}
			return test{
				ch: updCh,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, challengeTable)
						assert.Equals(t, string(key), chID)

						return b, nil
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, challengeTable)
						assert.Equals(t, old, b)

						dbOld := new(dbChallenge)
						assert.FatalError(t, json.Unmarshal(old, dbOld))
						assert.Equals(t, dbc, dbOld)

						dbNew := new(dbChallenge)
						assert.FatalError(t, json.Unmarshal(nu, dbNew))
						assert.Equals(t, dbNew.ID, dbc.ID)
						assert.Equals(t, dbNew.AccountID, dbc.AccountID)
						assert.Equals(t, dbNew.Type, dbc.Type)
						assert.Equals(t, dbNew.Token, dbc.Token)
						assert.Equals(t, dbNew.Value, dbc.Value)
						assert.Equals(t, dbNew.CreatedAt, dbc.CreatedAt)
						assert.Equals(t, dbNew.Status, acme.StatusValid)
						assert.Equals(t, dbNew.ValidatedAt, "foobar")
						assert.Equals(t, dbNew.Error.Error(), acme.NewError(acme.ErrorMalformedType, "The request message was malformed").Error())
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
			if err := d.UpdateChallenge(context.Background(), tc.ch); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, tc.ch.ID, dbc.ID)
					assert.Equals(t, tc.ch.AccountID, dbc.AccountID)
					assert.Equals(t, tc.ch.Type, dbc.Type)
					assert.Equals(t, tc.ch.Token, dbc.Token)
					assert.Equals(t, tc.ch.Value, dbc.Value)
					assert.Equals(t, tc.ch.ValidatedAt, "foobar")
					assert.Equals(t, tc.ch.Status, acme.StatusValid)
					assert.Equals(t, tc.ch.Error.Error(), acme.NewError(acme.ErrorMalformedType, "malformed").Error())
				}
			}
		})
	}
}
