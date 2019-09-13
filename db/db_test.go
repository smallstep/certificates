package db

import (
	"errors"
	"testing"

	"github.com/smallstep/assert"
	"github.com/smallstep/nosql/database"
)

func TestIsRevoked(t *testing.T) {
	tests := map[string]struct {
		key       string
		db        *DB
		isRevoked bool
		err       error
	}{
		"false/nil db": {
			key: "sn",
		},
		"false/ErrNotFound": {
			key: "sn",
			db:  &DB{&MockNoSQLDB{Err: database.ErrNotFound, Ret1: nil}, true},
		},
		"error/checking bucket": {
			key: "sn",
			db:  &DB{&MockNoSQLDB{Err: errors.New("force"), Ret1: nil}, true},
			err: errors.New("error checking revocation bucket: force"),
		},
		"true": {
			key:       "sn",
			db:        &DB{&MockNoSQLDB{Ret1: []byte("value")}, true},
			isRevoked: true,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			isRevoked, err := tc.db.IsRevoked(tc.key)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, tc.err.Error(), err.Error())
				}
			} else {
				assert.Nil(t, tc.err)
				assert.Fatal(t, isRevoked == tc.isRevoked)
			}
		})
	}
}

func TestRevoke(t *testing.T) {
	tests := map[string]struct {
		rci *RevokedCertificateInfo
		db  *DB
		err error
	}{
		"error/force isRevoked": {
			rci: &RevokedCertificateInfo{Serial: "sn"},
			db: &DB{&MockNoSQLDB{
				MCmpAndSwap: func(bucket, sn, old, newval []byte) ([]byte, bool, error) {
					return nil, false, errors.New("force")
				},
			}, true},
			err: errors.New("error AuthDB CmpAndSwap: force"),
		},
		"error/was already revoked": {
			rci: &RevokedCertificateInfo{Serial: "sn"},
			db: &DB{&MockNoSQLDB{
				MCmpAndSwap: func(bucket, sn, old, newval []byte) ([]byte, bool, error) {
					return []byte("foo"), false, nil
				},
			}, true},
			err: ErrAlreadyExists,
		},
		"ok": {
			rci: &RevokedCertificateInfo{Serial: "sn"},
			db: &DB{&MockNoSQLDB{
				MCmpAndSwap: func(bucket, sn, old, newval []byte) ([]byte, bool, error) {
					return []byte("foo"), true, nil
				},
			}, true},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if err := tc.db.Revoke(tc.rci); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, tc.err.Error(), err.Error())
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

func TestUseToken(t *testing.T) {
	type result struct {
		err error
		ok  bool
	}
	tests := map[string]struct {
		id, tok string
		db      *DB
		want    result
	}{
		"fail/force-CmpAndSwap-error": {
			id:  "id",
			tok: "token",
			db: &DB{&MockNoSQLDB{
				MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
					return nil, false, errors.New("force")
				},
			}, true},
			want: result{
				ok:  false,
				err: errors.New("error storing used token used_ott/id"),
			},
		},
		"fail/CmpAndSwap-already-exists": {
			id:  "id",
			tok: "token",
			db: &DB{&MockNoSQLDB{
				MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
					return []byte("foo"), false, nil
				},
			}, true},
			want: result{
				ok: false,
			},
		},
		"ok/cmpAndSwap-success": {
			id:  "id",
			tok: "token",
			db: &DB{&MockNoSQLDB{
				MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
					return []byte("bar"), true, nil
				},
			}, true},
			want: result{
				ok: true,
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			ok, err := tc.db.UseToken(tc.id, tc.tok)
			if err != nil {
				if assert.NotNil(t, tc.want.err) {
					assert.HasPrefix(t, err.Error(), tc.want.err.Error())
				}
				assert.False(t, ok)
			} else if ok {
				assert.True(t, tc.want.ok)
			} else {
				assert.False(t, tc.want.ok)
			}
		})
	}
}
