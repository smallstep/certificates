package nosql

import (
	"context"
	"encoding/json"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/nosql"
)

var defaultExpiryDuration = time.Hour * 24

// dbAuthz is the base authz type that others build from.
type dbAuthz struct {
	ID         string          `json:"id"`
	AccountID  string          `json:"accountID"`
	Identifier acme.Identifier `json:"identifier"`
	Status     acme.Status     `json:"status"`
	ExpiresAt  time.Time       `json:"expiresAt"`
	Challenges []string        `json:"challenges"`
	Wildcard   bool            `json:"wildcard"`
	CreatedAt  time.Time       `json:"createdAt"`
	Error      *acme.Error     `json:"error"`
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
		return nil, errors.Wrapf(err, "authz %s not found", id)
	} else if err != nil {
		return nil, errors.Wrapf(err, "error loading authz %s", id)
	}

	var dbaz dbAuthz
	if err = json.Unmarshal(data, &dbaz); err != nil {
		return nil, errors.Wrap(err, "error unmarshaling authz type into dbAuthz")
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
	var chs = make([]*acme.Challenge, len(dbaz.Challenges))
	for i, chID := range dbaz.Challenges {
		chs[i], err = db.GetChallenge(ctx, chID, id)
		if err != nil {
			return nil, err
		}
	}
	return &acme.Authorization{
		Identifier: dbaz.Identifier,
		Status:     dbaz.Status,
		Challenges: chs,
		Wildcard:   dbaz.Wildcard,
		ExpiresAt:  dbaz.ExpiresAt,
		ID:         dbaz.ID,
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
		ID:         az.ID,
		AccountID:  az.AccountID,
		Status:     acme.StatusPending,
		CreatedAt:  now,
		ExpiresAt:  now.Add(defaultExpiryDuration),
		Identifier: az.Identifier,
		Challenges: chIDs,
		Wildcard:   az.Wildcard,
	}

	return db.save(ctx, az.ID, dbaz, nil, "authz", authzTable)
}

// UpdateAuthorization saves an updated ACME Authorization to the database.
func (db *DB) UpdateAuthorization(ctx context.Context, az *acme.Authorization) error {
	if len(az.ID) == 0 {
		return errors.New("id cannot be empty")
	}
	old, err := db.getDBAuthz(ctx, az.ID)
	if err != nil {
		return err
	}

	nu := old.clone()

	nu.Status = az.Status
	return db.save(ctx, old.ID, nu, old, "authz", authzTable)
}
