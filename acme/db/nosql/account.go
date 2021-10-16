package nosql

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/acme"
	nosqlDB "github.com/smallstep/nosql"
	"go.step.sm/crypto/jose"
)

// dbAccount represents an ACME account.
type dbAccount struct {
	ID            string           `json:"id"`
	Key           *jose.JSONWebKey `json:"key"`
	Contact       []string         `json:"contact,omitempty"`
	Status        acme.Status      `json:"status"`
	CreatedAt     time.Time        `json:"createdAt"`
	DeactivatedAt time.Time        `json:"deactivatedAt"`
}

func (dba *dbAccount) clone() *dbAccount {
	nu := *dba
	return &nu
}

type dbExternalAccountKey struct {
	ID          string    `json:"id"`
	Provisioner string    `json:"provisioner"`
	Reference   string    `json:"reference"`
	AccountID   string    `json:"accountID,omitempty"`
	KeyBytes    []byte    `json:"key"`
	CreatedAt   time.Time `json:"createdAt"`
	BoundAt     time.Time `json:"boundAt"`
}

type dbExternalAccountKeyReference struct {
	Reference            string `json:"reference"`
	ExternalAccountKeyID string `json:"externalAccountKeyID"`
}

func (db *DB) getAccountIDByKeyID(ctx context.Context, kid string) (string, error) {
	id, err := db.db.Get(accountByKeyIDTable, []byte(kid))
	if err != nil {
		if nosqlDB.IsErrNotFound(err) {
			return "", acme.ErrNotFound
		}
		return "", errors.Wrapf(err, "error loading key-account index for key %s", kid)
	}
	return string(id), nil
}

// getDBAccount retrieves and unmarshals dbAccount.
func (db *DB) getDBAccount(ctx context.Context, id string) (*dbAccount, error) {
	data, err := db.db.Get(accountTable, []byte(id))
	if err != nil {
		if nosqlDB.IsErrNotFound(err) {
			return nil, acme.ErrNotFound
		}
		return nil, errors.Wrapf(err, "error loading account %s", id)
	}

	dbacc := new(dbAccount)
	if err = json.Unmarshal(data, dbacc); err != nil {
		return nil, errors.Wrapf(err, "error unmarshaling account %s into dbAccount", id)
	}
	return dbacc, nil
}

// getDBExternalAccountKey retrieves and unmarshals dbExternalAccountKey.
func (db *DB) getDBExternalAccountKey(ctx context.Context, id string) (*dbExternalAccountKey, error) {
	data, err := db.db.Get(externalAccountKeyTable, []byte(id))
	if err != nil {
		if nosqlDB.IsErrNotFound(err) {
			return nil, acme.ErrNotFound
		}
		return nil, errors.Wrapf(err, "error loading external account key %s", id)
	}

	dbeak := new(dbExternalAccountKey)
	if err = json.Unmarshal(data, dbeak); err != nil {
		return nil, errors.Wrapf(err, "error unmarshaling external account key %s into dbExternalAccountKey", id)
	}

	return dbeak, nil
}

// GetAccount retrieves an ACME account by ID.
func (db *DB) GetAccount(ctx context.Context, id string) (*acme.Account, error) {
	dbacc, err := db.getDBAccount(ctx, id)
	if err != nil {
		return nil, err
	}

	return &acme.Account{
		Status:  dbacc.Status,
		Contact: dbacc.Contact,
		Key:     dbacc.Key,
		ID:      dbacc.ID,
	}, nil
}

// GetAccountByKeyID retrieves an ACME account by KeyID (thumbprint of the Account Key -- JWK).
func (db *DB) GetAccountByKeyID(ctx context.Context, kid string) (*acme.Account, error) {
	id, err := db.getAccountIDByKeyID(ctx, kid)
	if err != nil {
		return nil, err
	}
	return db.GetAccount(ctx, id)
}

// CreateAccount imlements the AcmeDB.CreateAccount interface.
func (db *DB) CreateAccount(ctx context.Context, acc *acme.Account) error {
	var err error
	acc.ID, err = randID()
	if err != nil {
		return err
	}

	dba := &dbAccount{
		ID:        acc.ID,
		Key:       acc.Key,
		Contact:   acc.Contact,
		Status:    acc.Status,
		CreatedAt: clock.Now(),
	}

	kid, err := acme.KeyToID(dba.Key)
	if err != nil {
		return err
	}
	kidB := []byte(kid)

	// Set the jwkID -> acme account ID index
	_, swapped, err := db.db.CmpAndSwap(accountByKeyIDTable, kidB, nil, []byte(acc.ID))
	switch {
	case err != nil:
		return errors.Wrap(err, "error storing keyID to accountID index")
	case !swapped:
		return errors.Errorf("key-id to account-id index already exists")
	default:
		if err = db.save(ctx, acc.ID, dba, nil, "account", accountTable); err != nil {
			db.db.Del(accountByKeyIDTable, kidB)
			return err
		}
		return nil
	}
}

// UpdateAccount imlements the AcmeDB.UpdateAccount interface.
func (db *DB) UpdateAccount(ctx context.Context, acc *acme.Account) error {
	old, err := db.getDBAccount(ctx, acc.ID)
	if err != nil {
		return err
	}

	nu := old.clone()
	nu.Contact = acc.Contact
	nu.Status = acc.Status

	// If the status has changed to 'deactivated', then set deactivatedAt timestamp.
	if acc.Status == acme.StatusDeactivated && old.Status != acme.StatusDeactivated {
		nu.DeactivatedAt = clock.Now()
	}

	return db.save(ctx, old.ID, nu, old, "account", accountTable)
}

// CreateExternalAccountKey creates a new External Account Binding key with a name
func (db *DB) CreateExternalAccountKey(ctx context.Context, provisionerName, reference string) (*acme.ExternalAccountKey, error) {
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
		ID:          keyID,
		Provisioner: provisionerName,
		Reference:   reference,
		KeyBytes:    random,
		CreatedAt:   clock.Now(),
	}

	if err := db.save(ctx, keyID, dbeak, nil, "external_account_key", externalAccountKeyTable); err != nil {
		return nil, err
	}

	if dbeak.Reference != "" {
		dbExternalAccountKeyReference := &dbExternalAccountKeyReference{
			Reference:            dbeak.Reference,
			ExternalAccountKeyID: dbeak.ID,
		}
		if err := db.save(ctx, dbeak.Reference, dbExternalAccountKeyReference, nil, "external_account_key_reference", externalAccountKeysByReferenceTable); err != nil {
			return nil, err
		}
	}

	return &acme.ExternalAccountKey{
		ID:          dbeak.ID,
		Provisioner: dbeak.Provisioner,
		Reference:   dbeak.Reference,
		AccountID:   dbeak.AccountID,
		KeyBytes:    dbeak.KeyBytes,
		CreatedAt:   dbeak.CreatedAt,
		BoundAt:     dbeak.BoundAt,
	}, nil
}

// GetExternalAccountKey retrieves an External Account Binding key by KeyID
func (db *DB) GetExternalAccountKey(ctx context.Context, provisionerName, keyID string) (*acme.ExternalAccountKey, error) {
	dbeak, err := db.getDBExternalAccountKey(ctx, keyID)
	if err != nil {
		return nil, err
	}

	if dbeak.Provisioner != provisionerName {
		return nil, acme.NewError(acme.ErrorUnauthorizedType, "name of provisioner does not match provisioner for which the EAB key was created")
	}

	return &acme.ExternalAccountKey{
		ID:          dbeak.ID,
		Provisioner: dbeak.Provisioner,
		Reference:   dbeak.Reference,
		AccountID:   dbeak.AccountID,
		KeyBytes:    dbeak.KeyBytes,
		CreatedAt:   dbeak.CreatedAt,
		BoundAt:     dbeak.BoundAt,
	}, nil
}

func (db *DB) DeleteExternalAccountKey(ctx context.Context, provisionerName, keyID string) error {
	dbeak, err := db.getDBExternalAccountKey(ctx, keyID)
	if err != nil {
		return errors.Wrapf(err, "error loading ACME EAB Key with Key ID %s", keyID)
	}
	if dbeak.Provisioner != provisionerName {
		return errors.New("name of provisioner does not match provisioner for which the EAB key was created")
	}
	if dbeak.Reference != "" {
		err = db.db.Del(externalAccountKeysByReferenceTable, []byte(dbeak.Reference))
		if err != nil {
			return errors.Wrapf(err, "error deleting ACME EAB Key Reference with Key ID %s and reference %s", keyID, dbeak.Reference)
		}
	}
	err = db.db.Del(externalAccountKeyTable, []byte(keyID))
	if err != nil {
		return errors.Wrapf(err, "error deleting ACME EAB Key with Key ID %s", keyID)
	}
	return nil
}

// GetExternalAccountKeys retrieves all External Account Binding keys for a provisioner
func (db *DB) GetExternalAccountKeys(ctx context.Context, provisionerName string) ([]*acme.ExternalAccountKey, error) {
	entries, err := db.db.List(externalAccountKeyTable)
	if err != nil {
		return nil, err
	}

	keys := []*acme.ExternalAccountKey{}
	for _, entry := range entries {
		dbeak := new(dbExternalAccountKey)
		if err = json.Unmarshal(entry.Value, dbeak); err != nil {
			return nil, errors.Wrapf(err, "error unmarshaling external account key %s into ExternalAccountKey", string(entry.Key))
		}
		if dbeak.Provisioner != provisionerName {
			continue
		}
		keys = append(keys, &acme.ExternalAccountKey{
			ID:          dbeak.ID,
			KeyBytes:    dbeak.KeyBytes,
			Provisioner: dbeak.Provisioner,
			Reference:   dbeak.Reference,
			AccountID:   dbeak.AccountID,
			CreatedAt:   dbeak.CreatedAt,
			BoundAt:     dbeak.BoundAt,
		})
	}

	return keys, nil
}

// GetExternalAccountKeyByReference retrieves an External Account Binding key with unique reference
func (db *DB) GetExternalAccountKeyByReference(ctx context.Context, provisionerName, reference string) (*acme.ExternalAccountKey, error) {
	if reference == "" {
		return nil, nil
	}
	k, err := db.db.Get(externalAccountKeysByReferenceTable, []byte(reference))
	if nosqlDB.IsErrNotFound(err) {
		return nil, acme.ErrNotFound
	} else if err != nil {
		return nil, errors.Wrapf(err, "error loading ACME EAB key for reference %s", reference)
	}
	dbExternalAccountKeyReference := new(dbExternalAccountKeyReference)
	if err := json.Unmarshal(k, dbExternalAccountKeyReference); err != nil {
		return nil, errors.Wrapf(err, "error unmarshaling ACME EAB key for reference %s", reference)
	}
	return db.GetExternalAccountKey(ctx, provisionerName, dbExternalAccountKeyReference.ExternalAccountKeyID)
}

func (db *DB) UpdateExternalAccountKey(ctx context.Context, provisionerName string, eak *acme.ExternalAccountKey) error {
	old, err := db.getDBExternalAccountKey(ctx, eak.ID)
	if err != nil {
		return err
	}

	if old.Provisioner != provisionerName {
		return errors.New("name of provisioner does not match provisioner for which the EAB key was created")
	}

	nu := dbExternalAccountKey{
		ID:          eak.ID,
		Provisioner: eak.Provisioner,
		Reference:   eak.Reference,
		AccountID:   eak.AccountID,
		KeyBytes:    eak.KeyBytes,
		CreatedAt:   eak.CreatedAt,
		BoundAt:     eak.BoundAt,
	}

	return db.save(ctx, nu.ID, nu, old, "external_account_key", externalAccountKeyTable)
}
