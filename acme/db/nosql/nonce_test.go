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
	"github.com/smallstep/nosql/database"
)

func TestDB_CreateNonce(t *testing.T) {
	type test struct {
		db  nosql.DB
		err error
		_id *string
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
			d := DB{db: tc.db}
			if n, err := d.CreateNonce(context.Background()); err != nil {
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
		db      nosql.DB
		err     error
		acmeErr *acme.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/not-found": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MUpdate: func(tx *database.Tx) error {
						assert.Equals(t, tx.Operations[0].Bucket, nonceTable)
						assert.Equals(t, tx.Operations[0].Key, []byte(nonceID))
						assert.Equals(t, tx.Operations[0].Cmd, database.Get)

						assert.Equals(t, tx.Operations[1].Bucket, nonceTable)
						assert.Equals(t, tx.Operations[1].Key, []byte(nonceID))
						assert.Equals(t, tx.Operations[1].Cmd, database.Delete)
						return database.ErrNotFound
					},
				},
				acmeErr: acme.NewError(acme.ErrorBadNonceType, "nonce %s not found", nonceID),
			}
		},
		"fail/db.Update-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MUpdate: func(tx *database.Tx) error {
						assert.Equals(t, tx.Operations[0].Bucket, nonceTable)
						assert.Equals(t, tx.Operations[0].Key, []byte(nonceID))
						assert.Equals(t, tx.Operations[0].Cmd, database.Get)

						assert.Equals(t, tx.Operations[1].Bucket, nonceTable)
						assert.Equals(t, tx.Operations[1].Key, []byte(nonceID))
						assert.Equals(t, tx.Operations[1].Cmd, database.Delete)
						return errors.New("force")
					},
				},
				err: errors.New("error deleting nonce nonceID: force"),
			}
		},
		"ok": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MUpdate: func(tx *database.Tx) error {
						assert.Equals(t, tx.Operations[0].Bucket, nonceTable)
						assert.Equals(t, tx.Operations[0].Key, []byte(nonceID))
						assert.Equals(t, tx.Operations[0].Cmd, database.Get)

						assert.Equals(t, tx.Operations[1].Bucket, nonceTable)
						assert.Equals(t, tx.Operations[1].Key, []byte(nonceID))
						assert.Equals(t, tx.Operations[1].Cmd, database.Delete)
						return nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{db: tc.db}
			if err := d.DeleteNonce(context.Background(), acme.Nonce(nonceID)); err != nil {
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
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}
