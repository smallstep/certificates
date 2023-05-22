package nosql

import (
	"context"
	"encoding/json"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/nosql"
)

type dbDpopToken struct {
	ID        string    `json:"id"`
	Content   []byte    `json:"content"`
	CreatedAt time.Time `json:"createdAt"`
}

// getDBDpopToken retrieves and unmarshals an DPoP type from the database.
func (db *DB) getDBDpopToken(ctx context.Context, orderId string) (*dbDpopToken, error) {
	b, err := db.db.Get(dpopTokenTable, []byte(orderId))
	if nosql.IsErrNotFound(err) {
		return nil, acme.NewError(acme.ErrorMalformedType, "dpop %s not found", orderId)
	} else if err != nil {
		return nil, errors.Wrapf(err, "error loading dpop %s", orderId)
	}

	d := new(dbDpopToken)
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, errors.Wrapf(err, "error unmarshaling dpop %s into dbDpopToken", orderId)
	}
	return d, nil
}

// GetDpopToken retrieves an DPoP from the database.
func (db *DB) GetDpopToken(ctx context.Context, orderId string) (map[string]interface{}, error) {
	dbDpop, err := db.getDBDpopToken(ctx, orderId)
	if err != nil {
		return nil, err
	}

	dpop := make(map[string]interface{})
	err = json.Unmarshal(dbDpop.Content, &dpop)

	return dpop, err
}

// CreateDpopToken creates DPoP resources and saves them to the DB.
func (db *DB) CreateDpopToken(ctx context.Context, orderId string, dpop map[string]interface{}) error {
	content, err := json.Marshal(dpop)
	if err != nil {
		return err
	}

	now := clock.Now()
	dbDpop := &dbDpopToken{
		ID:        orderId,
		Content:   content,
		CreatedAt: now,
	}
	if err := db.save(ctx, orderId, dbDpop, nil, "dpop", dpopTokenTable); err != nil {
		return err
	}
	return nil
}

type dbOidcToken struct {
	ID        string    `json:"id"`
	Content   []byte    `json:"content"`
	CreatedAt time.Time `json:"createdAt"`
}

// getDBOidcToken retrieves and unmarshals an OIDC id token type from the database.
func (db *DB) getDBOidcToken(ctx context.Context, orderId string) (*dbOidcToken, error) {
	b, err := db.db.Get(oidcTokenTable, []byte(orderId))
	if nosql.IsErrNotFound(err) {
		return nil, acme.NewError(acme.ErrorMalformedType, "oidc token %s not found", orderId)
	} else if err != nil {
		return nil, errors.Wrapf(err, "error loading oidc token %s", orderId)
	}
	o := new(dbOidcToken)
	if err := json.Unmarshal(b, &o); err != nil {
		return nil, errors.Wrapf(err, "error unmarshaling oidc token %s into dbOidcToken", orderId)
	}
	return o, nil
}

// GetOidcToken retrieves an oidc token from the database.
func (db *DB) GetOidcToken(ctx context.Context, orderId string) (map[string]interface{}, error) {
	dbOidc, err := db.getDBOidcToken(ctx, orderId)
	if err != nil {
		return nil, err
	}

	idToken := make(map[string]interface{})
	err = json.Unmarshal(dbOidc.Content, &idToken)

	return idToken, err
}

// CreateOidcToken creates oidc token resources and saves them to the DB.
func (db *DB) CreateOidcToken(ctx context.Context, orderId string, idToken map[string]interface{}) error {
	content, err := json.Marshal(idToken)
	if err != nil {
		return err
	}

	now := clock.Now()
	dbOidc := &dbOidcToken{
		ID:        orderId,
		Content:   content,
		CreatedAt: now,
	}
	if err := db.save(ctx, orderId, dbOidc, nil, "oidc", oidcTokenTable); err != nil {
		return err
	}
	return nil
}
