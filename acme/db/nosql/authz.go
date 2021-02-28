package nosql

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/nosql"
)

var defaultExpiryDuration = time.Hour * 24

// dbAuthz is the base authz type that others build from.
type dbAuthz struct {
	ID         string      `json:"id"`
	AccountID  string      `json:"accountID"`
	Identifier *Identifier `json:"identifier"`
	Status     string      `json:"status"`
	Expires    time.Time   `json:"expires"`
	Challenges []string    `json:"challenges"`
	Wildcard   bool        `json:"wildcard"`
	Created    time.Time   `json:"created"`
	Error      *Error      `json:"error"`
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
		return nil, MalformedErr(errors.Wrapf(err, "authz %s not found", id))
	} else if err != nil {
		return nil, ServerInternalErr(errors.Wrapf(err, "error loading authz %s", id))
	}

	var dbaz dbAuthz
	if err = json.Unmarshal(data, &dbaz); err != nil {
		return nil, ServerInternalErr(errors.Wrap(err, "error unmarshaling authz type into dbAuthz"))
	}
	return &dbaz
}

// GetAuthorization retrieves and unmarshals an ACME authz type from the database.
// Implements acme.DB GetAuthorization interface.
func (db *DB) GetAuthorization(ctx context.Context, id string) (*types.Authorization, error) {
	dbaz, err := getDBAuthz(id)
	if err != nil {
		return nil, err
	}
	var chs = make([]*Challenge, len(ba.Challenges))
	for i, chID := range dbaz.Challenges {
		chs[i], err = db.GetChallenge(ctx, chID)
		if err != nil {
			return nil, err
		}
	}
	return &types.Authorization{
		Identifier: dbaz.Identifier,
		Status:     dbaz.Status,
		Challenges: chs,
		Wildcard:   dbaz.Wildcard,
		Expires:    dbaz.Expires.Format(time.RFC3339),
		ID:         dbaz.ID,
	}, nil
}

// CreateAuthorization creates an entry in the database for the Authorization.
// Implements the acme.DB.CreateAuthorization interface.
func (db *DB) CreateAuthorization(ctx context.Context, az *types.Authorization) error {
	if len(az.AccountID) == 0 {
		return ServerInternalErr(errors.New("account-id cannot be empty"))
	}
	if az.Identifier == nil {
		return ServerInternalErr(errors.New("identifier cannot be nil"))
	}
	az.ID, err = randID()
	if err != nil {
		return nil, err
	}

	now := clock.Now()
	dbaz := &dbAuthz{
		ID:         az.ID,
		AccountID:  az.AccountID,
		Status:     types.StatusPending,
		Created:    now,
		Expires:    now.Add(defaultExpiryDuration),
		Identifier: az.Identifier,
	}

	if strings.HasPrefix(az.Identifier.Value, "*.") {
		dbaz.Wildcard = true
		dbaz.Identifier = Identifier{
			Value: strings.TrimPrefix(identifier.Value, "*."),
			Type:  identifier.Type,
		}
	}

	chIDs := []string{}
	chTypes := []string{"dns-01"}
	// HTTP and TLS challenges can only be used for identifiers without wildcards.
	if !dbaz.Wildcard {
		chTypes = append(chTypes, []string{"http-01", "tls-alpn-01"}...)
	}

	for _, typ := range chTypes {
		ch, err := db.CreateChallenge(ctx, &types.Challenge{
			AccountID: az.AccountID,
			AuthzID:   az.ID,
			Value:     az.Identifier.Value,
			Type:      typ,
		})
		if err != nil {
			return nil, Wrapf(err, "error creating '%s' challenge", typ)
		}

		chIDs = append(chIDs, ch.ID)
	}
	dbaz.Challenges = chIDs

	return db.save(ctx, az.ID, dbaz, nil, "authz", authzTable)
}

// UpdateAuthorization saves an updated ACME Authorization to the database.
func (db *DB) UpdateAuthorization(ctx context.Context, az *types.Authorization) error {
	if len(az.ID) == 0 {
		return ServerInternalErr(errors.New("id cannot be empty"))
	}
	old, err := db.getDBAuthz(ctx, az.ID)
	if err != nil {
		return err
	}

	nu := old.clone()

	nu.Status = az.Status
	nu.Error = az.Error
	return db.save(ctx, old.ID, nu, old, "authz", authzTable)
}
