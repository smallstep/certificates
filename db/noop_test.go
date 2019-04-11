package db

import (
	"testing"

	"github.com/smallstep/assert"
)

func Test_noop(t *testing.T) {
	db := new(NoopDB)

	_db, err := db.Init(&Config{})
	assert.FatalError(t, err)
	assert.Equals(t, db, _db)

	isRevoked, err := db.IsRevoked("foo")
	assert.False(t, isRevoked)
	assert.Nil(t, err)

	assert.Equals(t, db.Revoke(&RevokedCertificateInfo{}), ErrNotImplemented)
}
