package nosql

import (
	"context"
	"encoding/json"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/nosql"
)

// dbAuthz is the base authz type that others build from.
type dbAuthz struct {
	ID           string          `json:"id"`
	AccountID    string          `json:"accountID"`
	Identifier   acme.Identifier `json:"identifier"`
	Status       acme.Status     `json:"status"`
	Token        string          `json:"token"`
	ChallengeIDs []string        `json:"challengeIDs"`
	Wildcard     bool            `json:"wildcard"`
	CreatedAt    time.Time       `json:"createdAt"`
	ExpiresAt    time.Time       `json:"expiresAt"`
	Error        *acme.Error     `json:"error"`
}

func (ba *dbAuthz) clone() *dbAuthz {
	u := *ba
	return &u
}

// getDBAuthz retrieves and unmarshals a database representation of the
// ACME Authorization type.
func (db *DB) getDBAuthz(ctx context.Context, id string) (*dbAuthz, error) {
	data, err := db.db.Get(authzTable, []byte(id))
	if nosql.IsErrNotFound(err) {
		return nil, acme.NewError(acme.ErrorMalformedType, "authz %s not found", id)
	} else if err != nil {
		return nil, errors.Wrapf(err, "error loading authz %s", id)
	}

	var dbaz dbAuthz
	if err = json.Unmarshal(data, &dbaz); err != nil {
		return nil, errors.Wrapf(err, "error unmarshaling authz %s into dbAuthz", id)
	}
	return &dbaz, nil
}

// GetAuthorization retrieves and unmarshals an ACME authz type from the database.
// Implements acme.DB GetAuthorization interface.
func (db *DB) GetAuthorization(ctx context.Context, id string) (*acme.Authorization, error) {
	dbaz, err := db.getDBAuthz(ctx, id)
	if err != nil {
		return nil, err
	}
	var chs = make([]*acme.Challenge, len(dbaz.ChallengeIDs))
	for i, chID := range dbaz.ChallengeIDs {
		chs[i], err = db.GetChallenge(ctx, chID, id)
		if err != nil {
			return nil, err
		}
	}
	return &acme.Authorization{
		ID:         dbaz.ID,
		AccountID:  dbaz.AccountID,
		Identifier: dbaz.Identifier,
		Status:     dbaz.Status,
		Challenges: chs,
		Wildcard:   dbaz.Wildcard,
		ExpiresAt:  dbaz.ExpiresAt,
		Token:      dbaz.Token,
		Error:      dbaz.Error,
	}, nil
}

// CreateAuthorization creates an entry in the database for the Authorization.
// Implements the acme.DB.CreateAuthorization interface.
func (db *DB) CreateAuthorization(ctx context.Context, az *acme.Authorization) error {
	var err error
	az.ID, err = randID()
	if err != nil {
		return err
	}

	chIDs := make([]string, len(az.Challenges))
	for i, ch := range az.Challenges {
		chIDs[i] = ch.ID
	}

	now := clock.Now()
	dbaz := &dbAuthz{
		ID:           az.ID,
		AccountID:    az.AccountID,
		Status:       az.Status,
		CreatedAt:    now,
		ExpiresAt:    az.ExpiresAt,
		Identifier:   az.Identifier,
		ChallengeIDs: chIDs,
		Token:        az.Token,
		Wildcard:     az.Wildcard,
	}

	return db.save(ctx, az.ID, dbaz, nil, "authz", authzTable)
}

// UpdateAuthorization saves an updated ACME Authorization to the database.
func (db *DB) UpdateAuthorization(ctx context.Context, az *acme.Authorization) error {
	old, err := db.getDBAuthz(ctx, az.ID)
	if err != nil {
		return err
	}

	nu := old.clone()

	nu.Status = az.Status
	nu.Error = az.Error
	return db.save(ctx, old.ID, nu, old, "authz", authzTable)
}

// GetAuthorizationsByAccountID retrieves and unmarshals ACME authz types from the database.
func (db *DB) GetAuthorizationsByAccountID(ctx context.Context, accountID string) ([]*acme.Authorization, error) {
	entries, err := db.db.List(authzTable)
	if err != nil {
		return nil, errors.Wrapf(err, "error listing authz")
	}
	authzs := []*acme.Authorization{}
	for _, entry := range entries {
		dbaz := new(dbAuthz)
		if err = json.Unmarshal(entry.Value, dbaz); err != nil {
			return nil, errors.Wrapf(err, "error unmarshaling dbAuthz key '%s' into dbAuthz struct", string(entry.Key))
		}
		// Filter out all dbAuthzs that don't belong to the accountID. This
		// could be made more efficient with additional data structures mapping the
		// Account ID to authorizations. Not trivial to do, though.
		if dbaz.AccountID != accountID {
			continue
		}
		authzs = append(authzs, &acme.Authorization{
			ID:         dbaz.ID,
			AccountID:  dbaz.AccountID,
			Identifier: dbaz.Identifier,
			Status:     dbaz.Status,
			Challenges: nil, // challenges not required for current use case
			Wildcard:   dbaz.Wildcard,
			ExpiresAt:  dbaz.ExpiresAt,
			Token:      dbaz.Token,
			Error:      dbaz.Error,
		})
	}

	return authzs, nil
}
