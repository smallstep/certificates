package db

import (
	"testing"

	"github.com/smallstep/assert"
)

func TestSimpleDB(t *testing.T) {
	db, err := newSimpleDB(nil)
	assert.FatalError(t, err)

	// Revoke
	assert.Equals(t, ErrNotImplemented, db.Revoke(nil))

	// IsRevoked -- verify noop
	isRevoked, err := db.IsRevoked("foo")
	assert.False(t, isRevoked)
	assert.Nil(t, err)

	// StoreCertificate
	assert.Equals(t, ErrNotImplemented, db.StoreCertificate(nil))

	// UseToken
	ok, err := db.UseToken("foo", "bar")
	assert.True(t, ok)
	assert.Nil(t, err)
	ok, err = db.UseToken("foo", "cat")
	assert.False(t, ok)
	assert.Nil(t, err)

	// Shutdown -- verify noop
	assert.FatalError(t, db.Shutdown())
	ok, err = db.UseToken("foo", "cat")
	assert.False(t, ok)
	assert.Nil(t, err)
}
