package nosql

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/nosql"
)

// dbNonce contains nonce metadata used in the ACME protocol.
type dbNonce struct {
	ID        string
	CreatedAt time.Time
	DeletedAt time.Time
}

func (dbn *dbNonce) clone() *dbNonce {
	u := *dbn
	return &u
}

// CreateNonce creates, stores, and returns an ACME replay-nonce.
// Implements the acme.DB interface.
func (db *DB) CreateNonce(ctx context.Context) (acme.Nonce, error) {
	_id, err := randID()
	if err != nil {
		return "", err
	}

	id := base64.RawURLEncoding.EncodeToString([]byte(_id))
	n := &dbNonce{
		ID:        id,
		CreatedAt: clock.Now(),
	}
	if err = db.save(ctx, id, n, nil, "nonce", nonceTable); err != nil {
		return "", err
	}
	return acme.Nonce(id), nil
}

// DeleteNonce verifies that the nonce is valid (by checking if it exists),
// and if so, consumes the nonce resource by deleting it from the database.
func (db *DB) DeleteNonce(ctx context.Context, nonce acme.Nonce) error {
	id := string(nonce)
	b, err := db.db.Get(nonceTable, []byte(nonce))
	if nosql.IsErrNotFound(err) {
		return errors.Wrapf(err, "nonce %s not found", id)
	} else if err != nil {
		return errors.Wrapf(err, "error loading nonce %s", id)
	}

	dbn := new(dbNonce)
	if err := json.Unmarshal(b, dbn); err != nil {
		return errors.Wrapf(err, "error unmarshaling nonce %s", string(nonce))
	}
	if !dbn.DeletedAt.IsZero() {
		return acme.NewError(acme.ErrorBadNonceType, "nonce %s already deleted", id)
	}

	nu := dbn.clone()
	nu.DeletedAt = clock.Now()

	return db.save(ctx, id, nu, dbn, "nonce", nonceTable)
}
