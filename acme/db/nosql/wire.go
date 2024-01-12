package nosql

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/nosql"
	"go.step.sm/crypto/jose"
)

type dbDpopToken struct {
	ID        string            `json:"id"` // jti
	Issuer    string            `json:"iss"`
	Subject   string            `json:"sub"`
	Audience  jose.Audience     `json:"aud,omitempty"`
	Expiry    *jose.NumericDate `json:"exp,omitempty"`
	NotBefore *jose.NumericDate `json:"nbf,omitempty"`
	IssuedAt  *jose.NumericDate `json:"iat,omitempty"`
	Nonce     string            `json:"nonce"`
	Method    string            `json:"htm"`
	URL       string            `json:"htu"`
	Challenge string            `json:"chal"`
	Handle    string            `json:"handle"`
	Team      string            `json:"team"`
	CreatedAt time.Time         `json:"createdAt"`
}

// getDBDpopToken retrieves and unmarshals an DPoP type from the database.
func (db *DB) getDBDpopToken(_ context.Context, orderID string) (*dbDpopToken, error) {
	b, err := db.db.Get(wireDpopTokenTable, []byte(orderID))
	if nosql.IsErrNotFound(err) {
		return nil, acme.NewError(acme.ErrorMalformedType, "dpop %s not found", orderID)
	} else if err != nil {
		return nil, errors.Wrapf(err, "error loading dpop %s", orderID)
	}

	d := new(dbDpopToken)
	if err := json.Unmarshal(b, d); err != nil {
		return nil, errors.Wrapf(err, "error unmarshaling dpop %s into dbDpopToken", orderID)
	}
	return d, nil
}

// GetDpopToken retrieves a DPoP from the database.
func (db *DB) GetDpopToken(ctx context.Context, orderID string) (*acme.WireDpopToken, error) {
	dbDpop, err := db.getDBDpopToken(ctx, orderID)
	if err != nil {
		return nil, err
	}

	return &acme.WireDpopToken{
		Claims: jose.Claims{
			ID:        dbDpop.ID,
			Issuer:    dbDpop.Issuer,
			Subject:   dbDpop.Subject,
			Audience:  dbDpop.Audience,
			Expiry:    dbDpop.Expiry,
			NotBefore: dbDpop.NotBefore,
			IssuedAt:  dbDpop.IssuedAt,
		},
		Nonce:     dbDpop.Nonce,
		Method:    dbDpop.Method,
		URL:       dbDpop.URL,
		Challenge: dbDpop.Challenge,
		Handle:    dbDpop.Handle,
		Team:      dbDpop.Team,
	}, nil
}

// CreateDpopToken creates DPoP resources and saves them to the DB.
func (db *DB) CreateDpopToken(ctx context.Context, orderID string, dpop *acme.WireDpopToken) error {
	now := clock.Now()
	dbDpop := &dbDpopToken{
		ID:        dpop.ID,
		Issuer:    dpop.Issuer,
		Subject:   dpop.Subject,
		Audience:  dpop.Audience,
		Expiry:    dpop.Expiry,
		NotBefore: dpop.NotBefore,
		IssuedAt:  dpop.IssuedAt,
		Nonce:     dpop.Nonce,
		Method:    dpop.Method,
		URL:       dpop.URL,
		Challenge: dpop.Challenge,
		Handle:    dpop.Handle,
		Team:      dpop.Team,
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
	if nosql.IsErrNotFound(err) {
		return nil, acme.NewError(acme.ErrorMalformedType, "oidc token %s not found", orderID)
	} else if err != nil {
		return nil, errors.Wrapf(err, "error loading oidc token %s", orderID)
	}
	o := new(dbOidcToken)
	if err := json.Unmarshal(b, o); err != nil {
		return nil, errors.Wrapf(err, "error unmarshaling oidc token %s into dbOidcToken", orderID)
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
		return err
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
