package nosql

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/smallstep/certificates/acme"
	certificatesdb "github.com/smallstep/certificates/db"
	"github.com/smallstep/nosql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDB_GetDpopToken(t *testing.T) {
	type test struct {
		db          *DB
		orderID     string
		expected    map[string]any
		expectedErr error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/acme-not-found": func(t *testing.T) test {
			dir := t.TempDir()
			db, err := nosql.New("badgerv2", dir)
			require.NoError(t, err)
			return test{
				db: &DB{
					db: db,
				},
				orderID: "orderID",
				expectedErr: &acme.Error{
					Type:   "urn:ietf:params:acme:error:malformed",
					Status: 400,
					Detail: "The request message was malformed",
					Err:    errors.New(`dpop token "orderID" not found`),
				},
			}
		},
		"fail/unmarshal-error": func(t *testing.T) test {
			dir := t.TempDir()
			db, err := nosql.New("badgerv2", dir)
			require.NoError(t, err)
			token := dbDpopToken{
				ID:        "orderID",
				Content:   []byte("{}"),
				CreatedAt: time.Now(),
			}
			b, err := json.Marshal(token)
			require.NoError(t, err)
			err = db.Set(wireDpopTokenTable, []byte("orderID"), b[1:]) // start at index 1; corrupt JSON data
			require.NoError(t, err)
			return test{
				db: &DB{
					db: db,
				},
				orderID:     "orderID",
				expectedErr: errors.New(`failed unmarshaling dpop token "orderID" into dbDpopToken: invalid character ':' after top-level value`),
			}
		},
		"fail/db.Get": func(t *testing.T) test {
			db := &certificatesdb.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equal(t, wireDpopTokenTable, bucket)
					assert.Equal(t, []byte("orderID"), key)
					return nil, errors.New("fail")
				},
			}
			return test{
				db: &DB{
					db: db,
				},
				orderID:     "orderID",
				expectedErr: errors.New(`failed loading dpop token "orderID": fail`),
			}
		},
		"ok": func(t *testing.T) test {
			dir := t.TempDir()
			db, err := nosql.New("badgerv2", dir)
			require.NoError(t, err)
			token := dbDpopToken{
				ID:        "orderID",
				Content:   []byte(`{"sub": "wireapp://guVX5xeFS3eTatmXBIyA4A!7a41cf5b79683410@wire.com"}`),
				CreatedAt: time.Now(),
			}
			b, err := json.Marshal(token)
			require.NoError(t, err)
			err = db.Set(wireDpopTokenTable, []byte("orderID"), b)
			require.NoError(t, err)
			return test{
				db: &DB{
					db: db,
				},
				orderID: "orderID",
				expected: map[string]any{
					"sub": "wireapp://guVX5xeFS3eTatmXBIyA4A!7a41cf5b79683410@wire.com",
				},
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			got, err := tc.db.GetDpopToken(context.Background(), tc.orderID)
			if tc.expectedErr != nil {
				assert.EqualError(t, err, tc.expectedErr.Error())
				ae := &acme.Error{}
				if errors.As(err, &ae) {
					ee := &acme.Error{}
					require.True(t, errors.As(tc.expectedErr, &ee))
					assert.Equal(t, ee.Detail, ae.Detail)
					assert.Equal(t, ee.Type, ae.Type)
					assert.Equal(t, ee.Status, ae.Status)
				}
				assert.Nil(t, got)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestDB_CreateDpopToken(t *testing.T) {
	type test struct {
		db          *DB
		orderID     string
		dpop        map[string]any
		expectedErr error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/db.Save": func(t *testing.T) test {
			db := &certificatesdb.MockNoSQLDB{
				MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
					assert.Equal(t, wireDpopTokenTable, bucket)
					assert.Equal(t, []byte("orderID"), key)
					return nil, false, errors.New("fail")
				},
			}
			return test{
				db: &DB{
					db: db,
				},
				orderID: "orderID",
				dpop: map[string]any{
					"sub": "wireapp://guVX5xeFS3eTatmXBIyA4A!7a41cf5b79683410@wire.com",
				},
				expectedErr: errors.New("failed saving dpop token: error saving acme dpop: fail"),
			}
		},
		"ok": func(t *testing.T) test {
			dir := t.TempDir()
			db, err := nosql.New("badgerv2", dir)
			require.NoError(t, err)
			return test{
				db: &DB{
					db: db,
				},
				orderID: "orderID",
				dpop: map[string]any{
					"sub": "wireapp://guVX5xeFS3eTatmXBIyA4A!7a41cf5b79683410@wire.com",
				},
			}
		},
		"ok/nil": func(t *testing.T) test {
			dir := t.TempDir()
			db, err := nosql.New("badgerv2", dir)
			require.NoError(t, err)
			return test{
				db: &DB{
					db: db,
				},
				orderID: "orderID",
				dpop:    nil,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			err := tc.db.CreateDpopToken(context.Background(), tc.orderID, tc.dpop)
			if tc.expectedErr != nil {
				assert.EqualError(t, err, tc.expectedErr.Error())
				return
			}

			assert.NoError(t, err)

			dpop, err := tc.db.getDBDpopToken(context.Background(), tc.orderID)
			require.NoError(t, err)

			assert.Equal(t, tc.orderID, dpop.ID)
			var m map[string]any
			err = json.Unmarshal(dpop.Content, &m)
			require.NoError(t, err)

			assert.Equal(t, tc.dpop, m)
		})
	}
}

func TestDB_GetOidcToken(t *testing.T) {
	type test struct {
		db          *DB
		orderID     string
		expected    map[string]any
		expectedErr error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/acme-not-found": func(t *testing.T) test {
			dir := t.TempDir()
			db, err := nosql.New("badgerv2", dir)
			require.NoError(t, err)
			return test{
				db: &DB{
					db: db,
				},
				orderID: "orderID",
				expectedErr: &acme.Error{
					Type:   "urn:ietf:params:acme:error:malformed",
					Status: 400,
					Detail: "The request message was malformed",
					Err:    errors.New(`oidc token "orderID" not found`),
				},
			}
		},
		"fail/unmarshal-error": func(t *testing.T) test {
			dir := t.TempDir()
			db, err := nosql.New("badgerv2", dir)
			require.NoError(t, err)
			token := dbOidcToken{
				ID:        "orderID",
				Content:   []byte("{}"),
				CreatedAt: time.Now(),
			}
			b, err := json.Marshal(token)
			require.NoError(t, err)
			err = db.Set(wireOidcTokenTable, []byte("orderID"), b[1:]) // start at index 1; corrupt JSON data
			require.NoError(t, err)
			return test{
				db: &DB{
					db: db,
				},
				orderID:     "orderID",
				expectedErr: errors.New(`failed unmarshaling oidc token "orderID" into dbOidcToken: invalid character ':' after top-level value`),
			}
		},
		"fail/db.Get": func(t *testing.T) test {
			db := &certificatesdb.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equal(t, wireOidcTokenTable, bucket)
					assert.Equal(t, []byte("orderID"), key)
					return nil, errors.New("fail")
				},
			}
			return test{
				db: &DB{
					db: db,
				},
				orderID:     "orderID",
				expectedErr: errors.New(`failed loading oidc token "orderID": fail`),
			}
		},
		"ok": func(t *testing.T) test {
			dir := t.TempDir()
			db, err := nosql.New("badgerv2", dir)
			require.NoError(t, err)
			token := dbOidcToken{
				ID:        "orderID",
				Content:   []byte(`{"name": "Alice Smith", "preferred_username": "@alice.smith"}`),
				CreatedAt: time.Now(),
			}
			b, err := json.Marshal(token)
			require.NoError(t, err)
			err = db.Set(wireOidcTokenTable, []byte("orderID"), b)
			require.NoError(t, err)
			return test{
				db: &DB{
					db: db,
				},
				orderID: "orderID",
				expected: map[string]any{
					"name":               "Alice Smith",
					"preferred_username": "@alice.smith",
				},
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			got, err := tc.db.GetOidcToken(context.Background(), tc.orderID)
			if tc.expectedErr != nil {
				assert.EqualError(t, err, tc.expectedErr.Error())
				ae := &acme.Error{}
				if errors.As(err, &ae) {
					ee := &acme.Error{}
					require.True(t, errors.As(tc.expectedErr, &ee))
					assert.Equal(t, ee.Detail, ae.Detail)
					assert.Equal(t, ee.Type, ae.Type)
					assert.Equal(t, ee.Status, ae.Status)
				}
				assert.Nil(t, got)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestDB_CreateOidcToken(t *testing.T) {
	type test struct {
		db          *DB
		orderID     string
		oidc        map[string]any
		expectedErr error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/db.Save": func(t *testing.T) test {
			db := &certificatesdb.MockNoSQLDB{
				MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
					assert.Equal(t, wireOidcTokenTable, bucket)
					assert.Equal(t, []byte("orderID"), key)
					return nil, false, errors.New("fail")
				},
			}
			return test{
				db: &DB{
					db: db,
				},
				orderID: "orderID",
				oidc: map[string]any{
					"name":               "Alice Smith",
					"preferred_username": "@alice.smith",
				},
				expectedErr: errors.New("failed saving oidc token: error saving acme oidc: fail"),
			}
		},
		"ok": func(t *testing.T) test {
			dir := t.TempDir()
			db, err := nosql.New("badgerv2", dir)
			require.NoError(t, err)
			return test{
				db: &DB{
					db: db,
				},
				orderID: "orderID",
				oidc: map[string]any{
					"name":               "Alice Smith",
					"preferred_username": "@alice.smith",
				},
			}
		},
		"ok/nil": func(t *testing.T) test {
			dir := t.TempDir()
			db, err := nosql.New("badgerv2", dir)
			require.NoError(t, err)
			return test{
				db: &DB{
					db: db,
				},
				orderID: "orderID",
				oidc:    nil,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			err := tc.db.CreateOidcToken(context.Background(), tc.orderID, tc.oidc)
			if tc.expectedErr != nil {
				assert.EqualError(t, err, tc.expectedErr.Error())
				return
			}

			assert.NoError(t, err)

			oidc, err := tc.db.getDBOidcToken(context.Background(), tc.orderID)
			require.NoError(t, err)

			assert.Equal(t, tc.orderID, oidc.ID)
			var m map[string]any
			err = json.Unmarshal(oidc.Content, &m)
			require.NoError(t, err)

			assert.Equal(t, tc.oidc, m)
		})
	}
}
