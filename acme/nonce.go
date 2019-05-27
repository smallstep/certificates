package acme

import (
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/nosql"
	"github.com/smallstep/nosql/database"
)

// nonce contains nonce metadata used in the ACME protocol.
type nonce struct {
	ID      string
	Created time.Time
}

// newNonce creates, stores, and returns an ACME replay-nonce.
func newNonce(db nosql.DB) (*nonce, error) {
	_id, err := randID()
	if err != nil {
		return nil, err
	}

	id := base64.RawURLEncoding.EncodeToString([]byte(_id))
	n := &nonce{
		ID:      id,
		Created: clock.Now(),
	}
	b, err := json.Marshal(n)
	if err != nil {
		return nil, ServerInternalErr(errors.Wrap(err, "error marshaling nonce"))
	}
	_, swapped, err := db.CmpAndSwap(nonceTable, []byte(id), nil, b)
	switch {
	case err != nil:
		return nil, ServerInternalErr(errors.Wrap(err, "error storing nonce"))
	case !swapped:
		return nil, ServerInternalErr(errors.New("error storing nonce; " +
			"value has changed since last read"))
	default:
		return n, nil
	}
}

// useNonce verifies that the nonce is valid (by checking if it exists),
// and if so, consumes the nonce resource by deleting it from the database.
func useNonce(db nosql.DB, nonce string) error {
	err := db.Update(&database.Tx{
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
	case nosql.IsErrNotFound(err):
		return BadNonceErr(nil)
	case err != nil:
		return ServerInternalErr(errors.Wrapf(err, "error deleting nonce %s", nonce))
	default:
		return nil
	}
}
