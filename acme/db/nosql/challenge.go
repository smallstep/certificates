package nosql

import (
	"context"
	"encoding/json"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/nosql"
)

// dbChallenge is the base Challenge type that others build from.
type dbChallenge struct {
	ID        string      `json:"id"`
	AccountID string      `json:"accountID"`
	AuthzID   string      `json:"authzID"`
	Type      string      `json:"type"`
	Status    acme.Status `json:"status"`
	Token     string      `json:"token"`
	Value     string      `json:"value"`
	Validated string      `json:"validated"`
	Created   time.Time   `json:"created"`
	Error     *acme.Error `json:"error"`
}

func (dbc *dbChallenge) clone() *dbChallenge {
	u := *dbc
	return &u
}

func (db *DB) getDBChallenge(ctx context.Context, id string) (*dbChallenge, error) {
	data, err := db.db.Get(challengeTable, []byte(id))
	if nosql.IsErrNotFound(err) {
		return nil, errors.Wrapf(err, "challenge %s not found", id)
	} else if err != nil {
		return nil, errors.Wrapf(err, "error loading challenge %s", id)
	}

	dbch := new(dbChallenge)
	if err := json.Unmarshal(data, dbch); err != nil {
		return nil, errors.Wrap(err, "error unmarshaling dbChallenge")
	}
	return dbch, nil
}

// CreateChallenge creates a new ACME challenge data structure in the database.
// Implements acme.DB.CreateChallenge interface.
func (db *DB) CreateChallenge(ctx context.Context, ch *acme.Challenge) error {
	var err error
	ch.ID, err = randID()
	if err != nil {
		return errors.Wrap(err, "error generating random id for ACME challenge")
	}

	dbch := &dbChallenge{
		ID:        ch.ID,
		AuthzID:   ch.AuthzID,
		AccountID: ch.AccountID,
		Value:     ch.Value,
		Status:    acme.StatusPending,
		Token:     ch.Token,
		Created:   clock.Now(),
		Type:      ch.Type,
	}

	return db.save(ctx, ch.ID, dbch, nil, "challenge", challengeTable)
}

// GetChallenge retrieves and unmarshals an ACME challenge type from the database.
// Implements the acme.DB GetChallenge interface.
func (db *DB) GetChallenge(ctx context.Context, id, authzID string) (*acme.Challenge, error) {
	dbch, err := db.getDBChallenge(ctx, id)
	if err != nil {
		return nil, err
	}

	ch := &acme.Challenge{
		Type:      dbch.Type,
		Status:    dbch.Status,
		Token:     dbch.Token,
		ID:        dbch.ID,
		AuthzID:   dbch.AuthzID,
		Error:     dbch.Error,
		Validated: dbch.Validated,
	}
	return ch, nil
}

// UpdateChallenge updates an ACME challenge type in the database.
func (db *DB) UpdateChallenge(ctx context.Context, ch *acme.Challenge) error {
	if len(ch.ID) == 0 {
		return errors.New("id cannot be empty")
	}
	old, err := db.getDBChallenge(ctx, ch.ID)
	if err != nil {
		return err
	}

	nu := old.clone()

	// These should be the only values chaning in an Update request.
	nu.Status = ch.Status
	nu.Error = ch.Error
	nu.Validated = ch.Validated

	return db.save(ctx, old.ID, nu, old, "challenge", challengeTable)
}
