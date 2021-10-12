package nosql

import (
	"context"
	"testing"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/nosql"
)

func TestNew(t *testing.T) {
	type test struct {
		db  nosql.DB
		err error
	}
	var tests = map[string]test{
		"fail/db.CreateTable-error": {
			db: &db.MockNoSQLDB{
				MCreateTable: func(bucket []byte) error {
					assert.Equals(t, string(bucket), string(accountTable))
					return errors.New("force")
				},
			},
			err: errors.Errorf("error creating table %s: force", string(accountTable)),
		},
		"ok": {
			db: &db.MockNoSQLDB{
				MCreateTable: func(bucket []byte) error {
					return nil
				},
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := New(tc.db); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

type errorThrower string

func (et errorThrower) MarshalJSON() ([]byte, error) {
	return nil, errors.New("force")
}

func TestDB_save(t *testing.T) {
	type test struct {
		db  nosql.DB
		nu  interface{}
		old interface{}
		err error
	}
	var tests = map[string]test{
		"fail/error-marshaling-new": {
			nu:  errorThrower("foo"),
			err: errors.New("error marshaling acme type: challenge"),
		},
		"fail/error-marshaling-old": {
			nu:  "new",
			old: errorThrower("foo"),
			err: errors.New("error marshaling acme type: challenge"),
		},
		"fail/db.CmpAndSwap-error": {
			nu:  "new",
			old: "old",
			db: &db.MockNoSQLDB{
				MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
					assert.Equals(t, bucket, challengeTable)
					assert.Equals(t, string(key), "id")
					assert.Equals(t, string(old), "\"old\"")
					assert.Equals(t, string(nu), "\"new\"")
					return nil, false, errors.New("force")
				},
			},
			err: errors.New("error saving acme challenge: force"),
		},
		"fail/db.CmpAndSwap-false-marshaling-old": {
			nu:  "new",
			old: "old",
			db: &db.MockNoSQLDB{
				MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
					assert.Equals(t, bucket, challengeTable)
					assert.Equals(t, string(key), "id")
					assert.Equals(t, string(old), "\"old\"")
					assert.Equals(t, string(nu), "\"new\"")
					return nil, false, nil
				},
			},
			err: errors.New("error saving acme challenge; changed since last read"),
		},
		"ok": {
			nu:  "new",
			old: "old",
			db: &db.MockNoSQLDB{
				MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
					assert.Equals(t, bucket, challengeTable)
					assert.Equals(t, string(key), "id")
					assert.Equals(t, string(old), "\"old\"")
					assert.Equals(t, string(nu), "\"new\"")
					return nu, true, nil
				},
			},
		},
		"ok/nils": {
			nu:  nil,
			old: nil,
			db: &db.MockNoSQLDB{
				MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
					assert.Equals(t, bucket, challengeTable)
					assert.Equals(t, string(key), "id")
					assert.Equals(t, old, nil)
					assert.Equals(t, nu, nil)
					return nu, true, nil
				},
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			d := &DB{db: tc.db}
			if err := d.save(context.Background(), "id", tc.nu, tc.old, "challenge", challengeTable); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}
