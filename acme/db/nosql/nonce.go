package nosql

import (
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/pkg/errors"
	nosqlDB "github.com/smallstep/nosql"
	"github.com/smallstep/nosql/database"
)

// dbNonce contains nonce metadata used in the ACME protocol.
type dbNonce struct {
	ID      string
	Created time.Time
}

// CreateNonce creates, stores, and returns an ACME replay-nonce.
// Implements the acme.DB interface.
func (db *DB) CreateNonce() (Nonce, error) {
	_id, err := randID()
	if err != nil {
		return nil, err
	}

	id := base64.RawURLEncoding.EncodeToString([]byte(_id))
	n := &dbNonce{
		ID:      id,
		Created: clock.Now(),
	}
	b, err := json.Marshal(n)
	if err != nil {
		return nil, ServerInternalErr(errors.Wrap(err, "error marshaling nonce"))
	}
	if err = db.save(ctx, id, b, nil, "nonce", nonceTable); err != nil {
		return "", err
	}
	return Nonce(id), nil
}

// DeleteNonce verifies that the nonce is valid (by checking if it exists),
// and if so, consumes the nonce resource by deleting it from the database.
func (db *DB) DeleteNonce(nonce string) error {
	err := db.db.Update(&database.Tx{
		Operations: []*database.TxEntry{
			{
				Bucket: nonceTable,
				Key:    []byte(nonce),
				Cmd:    database.Get,
			},
			{
				Bucket: nonceTable,
				Key:    []byte(nonce),
				Cmd:    database.Delete,
			},
		},
	})

	switch {
	case nosqlDB.IsErrNotFound(err):
		return BadNonceErr(nil)
	case err != nil:
		return ServerInternalErr(errors.Wrapf(err, "error deleting nonce %s", nonce))
	default:
		return nil
	}
}
