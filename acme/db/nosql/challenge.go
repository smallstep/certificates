package nosql

import (
	"context"
	"encoding/json"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/nosql"
)

// ChallengeOptions is the type used to created a new Challenge.
type ChallengeOptions struct {
	AccountID  string
	AuthzID    string
	Identifier Identifier
}

// dbChallenge is the base Challenge type that others build from.
type dbChallenge struct {
	ID        string    `json:"id"`
	AccountID string    `json:"accountID"`
	AuthzID   string    `json:"authzID"`
	Type      string    `json:"type"`
	Status    string    `json:"status"`
	Token     string    `json:"token"`
	Value     string    `json:"value"`
	Validated time.Time `json:"validated"`
	Created   time.Time `json:"created"`
	Error     *AError   `json:"error"`
}

func (dbc *dbChallenge) clone() *dbChallenge {
	u := *bc
	return &u
}

func (db *DB) getDBChallenge(ctx context.Context, id string) (*dbChallenge, error) {
	data, err := db.db.Get(challengeTable, []byte(id))
	if nosql.IsErrNotFound(err) {
		return nil, MalformedErr(errors.Wrapf(err, "challenge %s not found", id))
	} else if err != nil {
		return nil, ServerInternalErr(errors.Wrapf(err, "error loading challenge %s", id))
	}

	dbch := new(baseChallenge)
	if err := json.Unmarshal(data, dbch); err != nil {
		return nil, ServerInternalErr(errors.Wrap(err, "error unmarshaling "+
			"challenge type into dbChallenge"))
	}
	return dbch
}

// CreateChallenge creates a new ACME challenge data structure in the database.
// Implements acme.DB.CreateChallenge interface.
func (db *DB) CreateChallenge(ctx context.context, ch *types.Challenge) error {
	if len(ch.AuthzID) == 0 {
		return ServerInternalError(errors.New("AuthzID cannot be empty"))
	}
	if len(ch.AccountID) == 0 {
		return ServerInternalError(errors.New("AccountID cannot be empty"))
	}
	if len(ch.Value) == 0 {
		return ServerInternalError(errors.New("AccountID cannot be empty"))
	}
	// TODO: verify that challenge type is set and is one of expected types.
	if len(ch.Type) == 0 {
		return ServerInternalError(errors.New("Type cannot be empty"))
	}

	ch.ID, err = randID()
	if err != nil {
		return nil, Wrap(err, "error generating random id for ACME challenge")
	}
	ch.Token, err = randID()
	if err != nil {
		return nil, Wrap(err, "error generating token for ACME challenge")
	}

	dbch := &dbChallenge{
		ID:        ch.ID,
		AuthzID:   ch.AuthzID,
		AccountID: ch.AccountID,
		Value:     ch.Value,
		Status:    types.StatusPending,
		Token:     ch.Token,
		Created:   clock.Now(),
		Type:      ch.Type,
	}

	return dbch.save(ctx, ch.ID, dbch, nil, "challenge", challengeTable)
}

// GetChallenge retrieves and unmarshals an ACME challenge type from the database.
// Implements the acme.DB GetChallenge interface.
func (db *DB) GetChallenge(ctx context.Context, id, authzID string) (*types.Challenge, error) {
	dbch, err := db.getDBChallenge(ctx, id)
	if err != nil {
		return err
	}

	ch := &Challenge{
		Type:    dbch.Type,
		Status:  dbch.Status,
		Token:   dbch.Token,
		URL:     dir.getLink(ctx, ChallengeLink, true, dbch.getID()),
		ID:      dbch.ID,
		AuthzID: dbch.AuthzID(),
		Error:   dbch.Error,
	}
	if !dbch.Validated.IsZero() {
		ac.Validated = dbch.Validated.Format(time.RFC3339)
	}
	return ch, nil
}

// UpdateChallenge updates an ACME challenge type in the database.
func (db *DB) UpdateChallenge(ctx context.Context, ch *types.Challenge) error {
	if len(ch.ID) == 0 {
		return ServerInternalErr(errors.New("id cannot be empty"))
	}
	old, err := db.getDBChallenge(ctx, ch.ID)
	if err != nil {
		return err
	}

	nu := old.clone()

	// These should be the only values chaning in an Update request.
	nu.Status = ch.Status
	nu.Error = ch.Error
	if nu.Status == types.StatusValid {
		nu.Validated = clock.Now()
	}

	return db.save(ctx, old.ID, nu, old, "challenge", challengeTable)
}
