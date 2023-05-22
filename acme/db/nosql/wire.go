package nosql

import (
	"context"
	"encoding/json"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/nosql"
)

type dbDpop struct {
	ID        string    `json:"id"`
	Content   []byte    `json:"content"`
	CreatedAt time.Time `json:"createdAt"`
}

// getDBDpop retrieves and unmarshals an DPoP type from the database.
func (db *DB) getDBDpop(ctx context.Context, orderId string) (*dbDpop, error) {
	b, err := db.db.Get(dpopTable, []byte(orderId))
	if nosql.IsErrNotFound(err) {
		return nil, acme.NewError(acme.ErrorMalformedType, "dpop %s not found", orderId)
	} else if err != nil {
		return nil, errors.Wrapf(err, "error loading dpop %s", orderId)
	}
	o := new(dbDpop)
	if err := json.Unmarshal(b, &o); err != nil {
		return nil, errors.Wrapf(err, "error unmarshaling dpop %s into dbDpop", orderId)
	}
	return o, nil
}

// GetDpop retrieves an DPoP from the database.
func (db *DB) GetDpop(ctx context.Context, orderId string) (map[string]interface{}, error) {
	dbDpop, err := db.getDBDpop(ctx, orderId)
	if err != nil {
		return nil, err
	}

	dpop := make(map[string]interface{})
	err = json.Unmarshal(dbDpop.Content, &dpop)

	return dpop, err
}

// CreateDpop creates DPoP resources and saves them to the DB.
func (db *DB) CreateDpop(ctx context.Context, orderId string, dpop map[string]interface{}) error {
	content, err := json.Marshal(dpop)
	if err != nil {
		return err
	}

	now := clock.Now()
	dbDpop := &dbDpop{
		ID:        orderId,
		Content:   content,
		CreatedAt: now,
	}
	if err := db.save(ctx, orderId, dbDpop, nil, "dpop", dpopTable); err != nil {
		return err
	}
	return nil
}
