package acme

import (
	"context"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
)

func TestAuthorization_UpdateStatus(t *testing.T) {
	type test struct {
		az  *Authorization
		err *Error
		db  DB
	}
	tests := map[string]func(t *testing.T) test{
		"ok/already-invalid": func(t *testing.T) test {
			az := &Authorization{
				Status: StatusInvalid,
			}
			return test{
				az: az,
			}
		},
		"ok/already-valid": func(t *testing.T) test {
			az := &Authorization{
				Status: StatusInvalid,
			}
			return test{
				az: az,
			}
		},
		"fail/error-unexpected-status": func(t *testing.T) test {
			az := &Authorization{
				Status: "foo",
			}
			return test{
				az:  az,
				err: NewErrorISE("unrecognized authorization status: %s", az.Status),
			}
		},
		"ok/expired": func(t *testing.T) test {
			now := clock.Now()
			az := &Authorization{
				ID:        "azID",
				AccountID: "accID",
				Status:    StatusPending,
				ExpiresAt: now.Add(-5 * time.Minute),
			}
			return test{
				az: az,
				db: &MockDB{
					MockUpdateAuthorization: func(ctx context.Context, updaz *Authorization) error {
						assert.Equals(t, updaz.ID, az.ID)
						assert.Equals(t, updaz.AccountID, az.AccountID)
						assert.Equals(t, updaz.Status, StatusInvalid)
						assert.Equals(t, updaz.ExpiresAt, az.ExpiresAt)
						return nil
					},
				},
			}
		},
		"fail/db.UpdateAuthorization-error": func(t *testing.T) test {
			now := clock.Now()
			az := &Authorization{
				ID:        "azID",
				AccountID: "accID",
				Status:    StatusPending,
				ExpiresAt: now.Add(-5 * time.Minute),
			}
			return test{
				az: az,
				db: &MockDB{
					MockUpdateAuthorization: func(ctx context.Context, updaz *Authorization) error {
						assert.Equals(t, updaz.ID, az.ID)
						assert.Equals(t, updaz.AccountID, az.AccountID)
						assert.Equals(t, updaz.Status, StatusInvalid)
						assert.Equals(t, updaz.ExpiresAt, az.ExpiresAt)
						return errors.New("force")
					},
				},
				err: NewErrorISE("error updating authorization: force"),
			}
		},
		"ok/no-valid-challenges": func(t *testing.T) test {
			now := clock.Now()
			az := &Authorization{
				ID:        "azID",
				AccountID: "accID",
				Status:    StatusPending,
				ExpiresAt: now.Add(5 * time.Minute),
				Challenges: []*Challenge{
					{Status: StatusPending}, {Status: StatusPending}, {Status: StatusPending},
				},
			}
			return test{
				az: az,
			}
		},
		"ok/valid": func(t *testing.T) test {
			now := clock.Now()
			az := &Authorization{
				ID:        "azID",
				AccountID: "accID",
				Status:    StatusPending,
				ExpiresAt: now.Add(5 * time.Minute),
				Challenges: []*Challenge{
					{Status: StatusPending}, {Status: StatusPending}, {Status: StatusValid},
				},
			}
			return test{
				az: az,
				db: &MockDB{
					MockUpdateAuthorization: func(ctx context.Context, updaz *Authorization) error {
						assert.Equals(t, updaz.ID, az.ID)
						assert.Equals(t, updaz.AccountID, az.AccountID)
						assert.Equals(t, updaz.Status, StatusValid)
						assert.Equals(t, updaz.ExpiresAt, az.ExpiresAt)
						assert.Equals(t, updaz.Error, nil)
						return nil
					},
				},
			}
		},
		"ok/invalid-challenge": func(t *testing.T) test {
			now := clock.Now()
			chErr := NewError(ErrorConnectionType, "force")
			az := &Authorization{
				ID:        "azID",
				AccountID: "accID",
				Status:    StatusPending,
				ExpiresAt: now.Add(5 * time.Minute),
				Challenges: []*Challenge{
					{Status: StatusPending}, {Status: StatusInvalid, Error: chErr}, {Status: StatusPending},
				},
			}
			return test{
				az: az,
				db: &MockDB{
					MockUpdateAuthorization: func(ctx context.Context, updaz *Authorization) error {
						assert.Equals(t, updaz.ID, az.ID)
						assert.Equals(t, updaz.Status, StatusInvalid)
						assert.Equals(t, updaz.Error, chErr)
						return nil
					},
				},
			}
		},
		"ok/valid-wins-over-invalid": func(t *testing.T) test {
			now := clock.Now()
			az := &Authorization{
				ID:        "azID",
				AccountID: "accID",
				Status:    StatusPending,
				ExpiresAt: now.Add(5 * time.Minute),
				Challenges: []*Challenge{
					{Status: StatusInvalid, Error: NewError(ErrorConnectionType, "force")}, {Status: StatusValid},
				},
			}
			return test{
				az: az,
				db: &MockDB{
					MockUpdateAuthorization: func(ctx context.Context, updaz *Authorization) error {
						assert.Equals(t, updaz.Status, StatusValid)
						assert.Equals(t, updaz.Error, nil)
						return nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if err := tc.az.UpdateStatus(context.Background(), tc.db); err != nil {
				if assert.NotNil(t, tc.err) {
					var k *Error
					if errors.As(err, &k) {
						assert.Equals(t, k.Type, tc.err.Type)
						assert.Equals(t, k.Detail, tc.err.Detail)
						assert.Equals(t, k.Status, tc.err.Status)
						assert.Equals(t, k.Err.Error(), tc.err.Err.Error())
						assert.Equals(t, k.Detail, tc.err.Detail)
					} else {
						assert.FatalError(t, errors.New("unexpected error type"))
					}
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})

	}
}

func TestAuthorizationInvalidAfterFailedChallenge(t *testing.T) {
	chErr := NewError(ErrorConnectionType, "no such host")
	az := &Authorization{
		ID:        "azID",
		Status:    StatusPending,
		ExpiresAt: clock.Now().Add(time.Hour),
		Challenges: []*Challenge{
			{Type: HTTP01, Status: StatusInvalid, Error: chErr},
			{Type: DNS01, Status: StatusPending},
		},
	}
	updated := false
	db := &MockDB{
		MockUpdateAuthorization: func(context.Context, *Authorization) error {
			updated = true
			return nil
		},
	}

	assert.FatalError(t, az.UpdateStatus(context.Background(), db))
	assert.True(t, updated, "authorization must be persisted")
	assert.Equals(t, az.Status, StatusInvalid)
	assert.Equals(t, az.Error, chErr)
}
