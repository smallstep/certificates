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

func TestDB_CreateNonce(t *testing.T) {
	type test struct {
		db    nosql.DB
		nonce *acme.Nonce
		err   error
		_id   *string
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/cmpAndSwap-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, nonceTable)
						assert.Equals(t, old, nil)

						dbn := new(dbNonce)
						assert.FatalError(t, json.Unmarshal(nu, dbn))
						assert.Equals(t, dbn.ID, string(key))
						assert.True(t, clock.Now().Add(-time.Minute).Before(dbn.CreatedAt))
						assert.True(t, clock.Now().Add(time.Minute).After(dbn.CreatedAt))
						return nil, false, errors.New("force")
					},
				},
				err: errors.New("error saving acme nonce: force"),
			}
		},
		"ok": func(t *testing.T) test {
			var (
				id    string
				idPtr = &id
			)

			return test{
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						*idPtr = string(key)
						assert.Equals(t, bucket, nonceTable)
						assert.Equals(t, old, nil)

						dbn := new(dbNonce)
						assert.FatalError(t, json.Unmarshal(nu, dbn))
						assert.Equals(t, dbn.ID, string(key))
						assert.True(t, clock.Now().Add(-time.Minute).Before(dbn.CreatedAt))
						assert.True(t, clock.Now().Add(time.Minute).After(dbn.CreatedAt))
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
			db := DB{db: tc.db}
			if n, err := db.CreateNonce(context.Background()); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, string(n), *tc._id)
				}
			}
		})
	}
}

func TestDB_DeleteNonce(t *testing.T) {

	nonceID := "nonceID"
	type test struct {
		db  nosql.DB
		err error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/not-found": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, nonceTable)
						assert.Equals(t, string(key), nonceID)

						return nil, nosqldb.ErrNotFound
					},
				},
				err: errors.New("nonce nonceID not found"),
			}
		},
		"fail/db.Get-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, nonceTable)
						assert.Equals(t, string(key), nonceID)

						return nil, errors.Errorf("force")
					},
				},
				err: errors.New("error loading nonce nonceID: force"),
			}
		},
		"fail/unmarshal-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, nonceTable)
						assert.Equals(t, string(key), nonceID)

						a := []string{"foo", "bar", "baz"}
						b, err := json.Marshal(a)
						assert.FatalError(t, err)

						return b, nil
					},
				},
				err: errors.New("error unmarshaling nonce nonceID"),
			}
		},
		"fail/already-used": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, nonceTable)
						assert.Equals(t, string(key), nonceID)

						nonce := dbNonce{
							ID:        nonceID,
							CreatedAt: clock.Now().Add(-5 * time.Minute),
							DeletedAt: clock.Now(),
						}
						b, err := json.Marshal(nonce)
						assert.FatalError(t, err)

						return b, nil
					},
				},
				err: acme.NewError(acme.ErrorBadNonceType, "nonce already deleted"),
			}
		},
		"ok": func(t *testing.T) test {
			nonce := dbNonce{
				ID:        nonceID,
				CreatedAt: clock.Now().Add(-5 * time.Minute),
			}
			b, err := json.Marshal(nonce)
			assert.FatalError(t, err)
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, nonceTable)
						assert.Equals(t, string(key), nonceID)

						return b, nil
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, nonceTable)
						assert.Equals(t, old, b)

						dbo := new(dbNonce)
						assert.FatalError(t, json.Unmarshal(old, dbo))
						assert.Equals(t, dbo.ID, string(key))
						assert.True(t, clock.Now().Add(-6*time.Minute).Before(dbo.CreatedAt))
						assert.True(t, clock.Now().Add(-4*time.Minute).After(dbo.CreatedAt))
						assert.True(t, dbo.DeletedAt.IsZero())

						dbn := new(dbNonce)
						assert.FatalError(t, json.Unmarshal(nu, dbn))
						assert.Equals(t, dbn.ID, string(key))
						assert.True(t, clock.Now().Add(-6*time.Minute).Before(dbn.CreatedAt))
						assert.True(t, clock.Now().Add(-4*time.Minute).After(dbn.CreatedAt))
						assert.True(t, clock.Now().Add(-time.Minute).Before(dbn.DeletedAt))
						assert.True(t, clock.Now().Add(time.Minute).After(dbn.DeletedAt))
						return nil, true, nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			db := DB{db: tc.db}
			if err := db.DeleteNonce(context.Background(), acme.Nonce(nonceID)); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}
