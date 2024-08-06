package nosql

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/nosql"
)

type dbDpopToken struct {
	ID        string    `json:"id"`
	Content   []byte    `json:"content"`
	CreatedAt time.Time `json:"createdAt"`
}

// getDBDpopToken retrieves and unmarshals an DPoP type from the database.
func (db *DB) getDBDpopToken(_ context.Context, orderID string) (*dbDpopToken, error) {
	b, err := db.db.Get(wireDpopTokenTable, []byte(orderID))
	if err != nil {
		if nosql.IsErrNotFound(err) {
			return nil, acme.NewError(acme.ErrorMalformedType, "dpop token %q not found", orderID)
		}
		return nil, fmt.Errorf("failed loading dpop token %q: %w", orderID, err)
	}

	d := new(dbDpopToken)
	if err := json.Unmarshal(b, d); err != nil {
		return nil, fmt.Errorf("failed unmarshaling dpop token %q into dbDpopToken: %w", orderID, err)
	}
	return d, nil
}

// GetDpopToken retrieves an DPoP from the database.
func (db *DB) GetDpopToken(ctx context.Context, orderID string) (map[string]any, error) {
	dbDpop, err := db.getDBDpopToken(ctx, orderID)
	if err != nil {
		return nil, err
	}

	dpop := make(map[string]any)
	err = json.Unmarshal(dbDpop.Content, &dpop)

	return dpop, err
}

// CreateDpopToken creates DPoP resources and saves them to the DB.
func (db *DB) CreateDpopToken(ctx context.Context, orderID string, dpop map[string]any) error {
	content, err := json.Marshal(dpop)
	if err != nil {
		return fmt.Errorf("failed marshaling dpop token: %w", err)
	}

	now := clock.Now()
	dbDpop := &dbDpopToken{
		ID:        orderID,
		Content:   content,
		CreatedAt: now,
	}
	if err := db.save(ctx, orderID, dbDpop, nil, "dpop", wireDpopTokenTable); err != nil {
		return fmt.Errorf("failed saving dpop token: %w", err)
	}
	return nil
}

type dbOidcToken struct {
	ID        string    `json:"id"`
	Content   []byte    `json:"content"`
	CreatedAt time.Time `json:"createdAt"`
}

// getDBOidcToken retrieves and unmarshals an OIDC id token type from the database.
func (db *DB) getDBOidcToken(_ context.Context, orderID string) (*dbOidcToken, error) {
	b, err := db.db.Get(wireOidcTokenTable, []byte(orderID))
	if err != nil {
		if nosql.IsErrNotFound(err) {
			return nil, acme.NewError(acme.ErrorMalformedType, "oidc token %q not found", orderID)
		}
		return nil, fmt.Errorf("failed loading oidc token %q: %w", orderID, err)
	}

	o := new(dbOidcToken)
	if err := json.Unmarshal(b, o); err != nil {
		return nil, fmt.Errorf("failed unmarshaling oidc token %q into dbOidcToken: %w", orderID, err)
	}
	return o, nil
}

// GetOidcToken retrieves an oidc token from the database.
func (db *DB) GetOidcToken(ctx context.Context, orderID string) (map[string]any, error) {
	dbOidc, err := db.getDBOidcToken(ctx, orderID)
	if err != nil {
		return nil, err
	}

	idToken := make(map[string]any)
	err = json.Unmarshal(dbOidc.Content, &idToken)

	return idToken, err
}

// CreateOidcToken creates oidc token resources and saves them to the DB.
func (db *DB) CreateOidcToken(ctx context.Context, orderID string, idToken map[string]any) error {
	content, err := json.Marshal(idToken)
	if err != nil {
		return fmt.Errorf("failed marshaling oidc token: %w", err)
	}

	now := clock.Now()
	dbOidc := &dbOidcToken{
		ID:        orderID,
		Content:   content,
		CreatedAt: now,
	}
	if err := db.save(ctx, orderID, dbOidc, nil, "oidc", wireOidcTokenTable); err != nil {
		return fmt.Errorf("failed saving oidc token: %w", err)
	}
	return nil
}
