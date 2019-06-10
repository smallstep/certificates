package db

import (
	"errors"
	"testing"

	"github.com/smallstep/assert"
	"github.com/smallstep/nosql/database"
)

type MockNoSQLDB struct {
	err         error
	ret1, ret2  interface{}
	get         func(bucket, key []byte) ([]byte, error)
	set         func(bucket, key, value []byte) error
	open        func(dataSourceName string, opt ...database.Option) error
	close       func() error
	createTable func(bucket []byte) error
	deleteTable func(bucket []byte) error
	del         func(bucket, key []byte) error
	list        func(bucket []byte) ([]*database.Entry, error)
	update      func(tx *database.Tx) error
	cmpAndSwap  func(bucket, key, old, newval []byte) ([]byte, bool, error)
}

func (m *MockNoSQLDB) CmpAndSwap(bucket, key, old, newval []byte) ([]byte, bool, error) {
	if m.cmpAndSwap != nil {
		return m.cmpAndSwap(bucket, key, old, newval)
	}
	if m.ret1 == nil {
		return nil, false, m.err
	}
	return m.ret1.([]byte), m.ret2.(bool), m.err
}

func (m *MockNoSQLDB) Get(bucket, key []byte) ([]byte, error) {
	if m.get != nil {
		return m.get(bucket, key)
	}
	if m.ret1 == nil {
		return nil, m.err
	}
	return m.ret1.([]byte), m.err
}

func (m *MockNoSQLDB) Set(bucket, key, value []byte) error {
	if m.set != nil {
		return m.set(bucket, key, value)
	}
	return m.err
}

func (m *MockNoSQLDB) Open(dataSourceName string, opt ...database.Option) error {
	if m.open != nil {
		return m.open(dataSourceName, opt...)
	}
	return m.err
}

func (m *MockNoSQLDB) Close() error {
	if m.close != nil {
		return m.close()
	}
	return m.err
}

func (m *MockNoSQLDB) CreateTable(bucket []byte) error {
	if m.createTable != nil {
		return m.createTable(bucket)
	}
	return m.err
}

func (m *MockNoSQLDB) DeleteTable(bucket []byte) error {
	if m.deleteTable != nil {
		return m.deleteTable(bucket)
	}
	return m.err
}

func (m *MockNoSQLDB) Del(bucket, key []byte) error {
	if m.del != nil {
		return m.del(bucket, key)
	}
	return m.err
}

func (m *MockNoSQLDB) List(bucket []byte) ([]*database.Entry, error) {
	if m.list != nil {
		return m.list(bucket)
	}
	return m.ret1.([]*database.Entry), m.err
}

func (m *MockNoSQLDB) Update(tx *database.Tx) error {
	if m.update != nil {
		return m.update(tx)
	}
	return m.err
}

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
			db:  &DB{&MockNoSQLDB{err: database.ErrNotFound, ret1: nil}, true},
		},
		"error/checking bucket": {
			key: "sn",
			db:  &DB{&MockNoSQLDB{err: errors.New("force"), ret1: nil}, true},
			err: errors.New("error checking revocation bucket: force"),
		},
		"true": {
			key:       "sn",
			db:        &DB{&MockNoSQLDB{ret1: []byte("value")}, true},
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
				get: func(bucket []byte, sn []byte) ([]byte, error) {
					return nil, errors.New("force IsRevoked")
				},
			}, true},
			err: errors.New("error checking revocation bucket: force IsRevoked"),
		},
		"error/was already revoked": {
			rci: &RevokedCertificateInfo{Serial: "sn"},
			db: &DB{&MockNoSQLDB{
				get: func(bucket []byte, sn []byte) ([]byte, error) {
					return nil, nil
				},
			}, true},
			err: ErrAlreadyExists,
		},
		"error/database set": {
			rci: &RevokedCertificateInfo{Serial: "sn"},
			db: &DB{&MockNoSQLDB{
				get: func(bucket []byte, sn []byte) ([]byte, error) {
					return nil, database.ErrNotFound
				},
				set: func(bucket []byte, key []byte, value []byte) error {
					return errors.New("force")
				},
			}, true},
			err: errors.New("database Set error: force"),
		},
		"ok": {
			rci: &RevokedCertificateInfo{Serial: "sn"},
			db: &DB{&MockNoSQLDB{
				get: func(bucket []byte, sn []byte) ([]byte, error) {
					return nil, database.ErrNotFound
				},
				set: func(bucket []byte, key []byte, value []byte) error {
					return nil
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
				cmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
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
				cmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
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
				cmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
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
