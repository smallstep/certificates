package acme

import (
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/nosql"
	"github.com/smallstep/nosql/database"
)

func TestNewNonce(t *testing.T) {
	type test struct {
		db  nosql.DB
		err *Error
		id  *string
	}
	tests := map[string]func(t *testing.T) test{
		"fail/cmpAndSwap-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, nonceTable)
						assert.Equals(t, old, nil)
						return nil, false, errors.New("force")
					},
				},
				err: ServerInternalErr(errors.Errorf("error storing nonce: force")),
			}
		},
		"fail/cmpAndSwap-false": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, nonceTable)
						assert.Equals(t, old, nil)
						return nil, false, nil
					},
				},
				err: ServerInternalErr(errors.Errorf("error storing nonce; value has changed since last read")),
			}
		},
		"ok": func(t *testing.T) test {
			var _id string
			id := &_id
			return test{
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, nonceTable)
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
			if n, err := newNonce(tc.db); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, n.ID, *tc.id)

					assert.True(t, n.Created.Before(time.Now().Add(time.Minute)))
					assert.True(t, n.Created.After(time.Now().Add(-time.Minute)))
				}
			}
		})
	}
}

func TestUseNonce(t *testing.T) {
	type test struct {
		id  string
		db  nosql.DB
		err *Error
	}
	tests := map[string]func(t *testing.T) test{
		"fail/update-not-found": func(t *testing.T) test {
			id := "foo"
			return test{
				db: &db.MockNoSQLDB{
					MUpdate: func(tx *database.Tx) error {
						assert.Equals(t, tx.Operations[0].Bucket, nonceTable)
						assert.Equals(t, tx.Operations[0].Key, []byte(id))
						assert.Equals(t, tx.Operations[0].Cmd, database.Get)

						assert.Equals(t, tx.Operations[1].Bucket, nonceTable)
						assert.Equals(t, tx.Operations[1].Key, []byte(id))
						assert.Equals(t, tx.Operations[1].Cmd, database.Delete)
						return database.ErrNotFound
					},
				},
				id:  id,
				err: BadNonceErr(nil),
			}
		},
		"fail/update-error": func(t *testing.T) test {
			id := "foo"
			return test{
				db: &db.MockNoSQLDB{
					MUpdate: func(tx *database.Tx) error {
						assert.Equals(t, tx.Operations[0].Bucket, nonceTable)
						assert.Equals(t, tx.Operations[0].Key, []byte(id))
						assert.Equals(t, tx.Operations[0].Cmd, database.Get)

						assert.Equals(t, tx.Operations[1].Bucket, nonceTable)
						assert.Equals(t, tx.Operations[1].Key, []byte(id))
						assert.Equals(t, tx.Operations[1].Cmd, database.Delete)
						return errors.New("force")
					},
				},
				id:  id,
				err: ServerInternalErr(errors.Errorf("error deleting nonce %s: force", id)),
			}
		},
		"ok": func(t *testing.T) test {
			id := "foo"
			return test{
				db: &db.MockNoSQLDB{
					MUpdate: func(tx *database.Tx) error {
						assert.Equals(t, tx.Operations[0].Bucket, nonceTable)
						assert.Equals(t, tx.Operations[0].Key, []byte(id))
						assert.Equals(t, tx.Operations[0].Cmd, database.Get)

						assert.Equals(t, tx.Operations[1].Bucket, nonceTable)
						assert.Equals(t, tx.Operations[1].Key, []byte(id))
						assert.Equals(t, tx.Operations[1].Cmd, database.Delete)

						return nil
					},
				},
				id: id,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if err := useNonce(tc.db, tc.id); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			}
		})
	}
}
