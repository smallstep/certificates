package nosql

import (
	"context"
	"crypto/rand"
	"time"

	"github.com/smallstep/certificates/authority/admin/eak"
)

type dbExternalAccountKey struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	AccountID string    `json:"accountID,omitempty"`
	KeyBytes  []byte    `json:"key,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
	BoundAt   time.Time `json:"boundAt"`
}

// CreateExternalAccountKey creates a new External Account Binding key
func (db *DB) CreateExternalAccountKey(ctx context.Context, name string) (*eak.ExternalAccountKey, error) {
	keyID, err := randID()
	if err != nil {
		return nil, err
	}

	random := make([]byte, 32)
	_, err = rand.Read(random)
	if err != nil {
		return nil, err
	}

	dbeak := &dbExternalAccountKey{
		ID:        keyID,
		Name:      name,
		KeyBytes:  random,
		CreatedAt: clock.Now(),
	}

	if err = db.save(ctx, keyID, dbeak, nil, "external_account_key", externalAccountKeyTable); err != nil {
		return nil, err
	}
	return &eak.ExternalAccountKey{
		ID:        dbeak.ID,
		Name:      dbeak.Name,
		AccountID: dbeak.AccountID,
		KeyBytes:  dbeak.KeyBytes,
		CreatedAt: dbeak.CreatedAt,
		BoundAt:   dbeak.BoundAt,
	}, nil
}
