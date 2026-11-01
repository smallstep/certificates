package db

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smallstep/nosql/database"
)

func TestKeyFingerprint(t *testing.T) {
	// SHA-256 of "abc".
	assert.Equal(t, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", KeyFingerprint([]byte("abc")))
	assert.NotEqual(t, KeyFingerprint([]byte("a")), KeyFingerprint([]byte("b")))
}

func TestIsKeyRevoked(t *testing.T) {
	tests := map[string]struct {
		db        *DB
		isRevoked bool
		err       string
	}{
		"false/nil db": {},
		"false/ErrNotFound": {
			db: &DB{&MockNoSQLDB{Err: database.ErrNotFound}, true},
		},
		"error/checking bucket": {
			db:  &DB{&MockNoSQLDB{Err: errors.New("force")}, true},
			err: "error checking key revocation bucket: force",
		},
		"true": {
			db: &DB{&MockNoSQLDB{MGet: func(bucket, key []byte) ([]byte, error) {
				if !bytes.Equal(bucket, revokedKeysTable) || string(key) != "fp" {
					return nil, database.ErrNotFound
				}
				return []byte("{}"), nil
			}}, true},
			isRevoked: true,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			isRevoked, err := tc.db.IsKeyRevoked("fp")
			if tc.err != "" {
				assert.EqualError(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.isRevoked, isRevoked)
		})
	}
}

func TestRevokeKey(t *testing.T) {
	rci := &RevokedCertificateInfo{Serial: "sn", ReasonCode: 1}
	tests := map[string]struct {
		db  *DB
		err error
	}{
		"error/CmpAndSwap": {
			db: &DB{&MockNoSQLDB{MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
				return nil, false, errors.New("force")
			}}, true},
			err: errors.New("error AuthDB CmpAndSwap: force"),
		},
		"error/already revoked": {
			db: &DB{&MockNoSQLDB{MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
				return []byte("{}"), false, nil
			}}, true},
			err: ErrAlreadyExists,
		},
		"ok": {
			db: &DB{&MockNoSQLDB{MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
				assert.Equal(t, revokedKeysTable, bucket)
				assert.Equal(t, []byte("fp"), key)
				assert.Nil(t, old)
				var got RevokedCertificateInfo
				require.NoError(t, json.Unmarshal(newval, &got))
				assert.Equal(t, *rci, got)
				return newval, true, nil
			}}, true},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := tc.db.RevokeKey("fp", rci)
			if tc.err != nil {
				assert.EqualError(t, err, tc.err.Error())
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestNew_createsRevokedKeysTable(t *testing.T) {
	db, err := New(&Config{Type: "badgerv2", DataSource: t.TempDir()})
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Shutdown() })

	kdb, ok := db.(KeyRevocationDB)
	require.True(t, ok, "DB must implement KeyRevocationDB")

	isRevoked, err := kdb.IsKeyRevoked("fp")
	require.NoError(t, err)
	assert.False(t, isRevoked)

	require.NoError(t, kdb.RevokeKey("fp", &RevokedCertificateInfo{Serial: "1", ReasonCode: 1}))
	assert.ErrorIs(t, kdb.RevokeKey("fp", &RevokedCertificateInfo{Serial: "2", ReasonCode: 1}), ErrAlreadyExists)

	isRevoked, err = kdb.IsKeyRevoked("fp")
	require.NoError(t, err)
	assert.True(t, isRevoked)
}
