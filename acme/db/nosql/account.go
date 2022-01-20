package nosql

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/acme"
	nosqlDB "github.com/smallstep/nosql"
	"go.step.sm/crypto/jose"
)

// Mutex for locking referencesByProvisioner index operations.
var referencesByProvisionerIndexMux sync.Mutex

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
	ID            string    `json:"id"`
	ProvisionerID string    `json:"provisionerID"`
	Reference     string    `json:"reference"`
	AccountID     string    `json:"accountID,omitempty"`
	KeyBytes      []byte    `json:"key"`
	CreatedAt     time.Time `json:"createdAt"`
	BoundAt       time.Time `json:"boundAt"`
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
func (db *DB) CreateExternalAccountKey(ctx context.Context, provisionerID, reference string) (*acme.ExternalAccountKey, error) {
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
		ID:            keyID,
		ProvisionerID: provisionerID,
		Reference:     reference,
		KeyBytes:      random,
		CreatedAt:     clock.Now(),
	}

	if err := db.save(ctx, keyID, dbeak, nil, "external_account_key", externalAccountKeyTable); err != nil {
		return nil, err
	}

	if err := db.addEAKID(ctx, provisionerID, dbeak.ID); err != nil {
		return nil, err
	}

	if dbeak.Reference != "" {
		dbExternalAccountKeyReference := &dbExternalAccountKeyReference{
			Reference:            dbeak.Reference,
			ExternalAccountKeyID: dbeak.ID,
		}
		if err := db.save(ctx, referenceKey(provisionerID, dbeak.Reference), dbExternalAccountKeyReference, nil, "external_account_key_reference", externalAccountKeysByReferenceTable); err != nil {
			return nil, err
		}
	}

	return &acme.ExternalAccountKey{
		ID:            dbeak.ID,
		ProvisionerID: dbeak.ProvisionerID,
		Reference:     dbeak.Reference,
		AccountID:     dbeak.AccountID,
		KeyBytes:      dbeak.KeyBytes,
		CreatedAt:     dbeak.CreatedAt,
		BoundAt:       dbeak.BoundAt,
	}, nil
}

// GetExternalAccountKey retrieves an External Account Binding key by KeyID
func (db *DB) GetExternalAccountKey(ctx context.Context, provisionerID, keyID string) (*acme.ExternalAccountKey, error) {
	dbeak, err := db.getDBExternalAccountKey(ctx, keyID)
	if err != nil {
		return nil, err
	}

	if dbeak.ProvisionerID != provisionerID {
		return nil, acme.NewError(acme.ErrorUnauthorizedType, "provisioner does not match provisioner for which the EAB key was created")
	}

	return &acme.ExternalAccountKey{
		ID:            dbeak.ID,
		ProvisionerID: dbeak.ProvisionerID,
		Reference:     dbeak.Reference,
		AccountID:     dbeak.AccountID,
		KeyBytes:      dbeak.KeyBytes,
		CreatedAt:     dbeak.CreatedAt,
		BoundAt:       dbeak.BoundAt,
	}, nil
}

func (db *DB) DeleteExternalAccountKey(ctx context.Context, provisionerID, keyID string) error {
	dbeak, err := db.getDBExternalAccountKey(ctx, keyID)
	if err != nil {
		return errors.Wrapf(err, "error loading ACME EAB Key with Key ID %s", keyID)
	}

	if dbeak.ProvisionerID != provisionerID {
		return errors.New("provisioner does not match provisioner for which the EAB key was created")
	}

	if dbeak.Reference != "" {
		if err := db.db.Del(externalAccountKeysByReferenceTable, []byte(referenceKey(provisionerID, dbeak.Reference))); err != nil {
			return errors.Wrapf(err, "error deleting ACME EAB Key reference with Key ID %s and reference %s", keyID, dbeak.Reference)
		}
	}
	if err := db.db.Del(externalAccountKeyTable, []byte(keyID)); err != nil {
		return errors.Wrapf(err, "error deleting ACME EAB Key with Key ID %s", keyID)
	}
	if err := db.deleteEAKID(ctx, provisionerID, keyID); err != nil {
		return errors.Wrapf(err, "error removing ACME EAB Key ID %s", keyID)
	}

	return nil
}

// GetExternalAccountKeys retrieves all External Account Binding keys for a provisioner
func (db *DB) GetExternalAccountKeys(ctx context.Context, provisionerID string) ([]*acme.ExternalAccountKey, error) {

	// TODO: mutex?

	var eakIDs []string
	r, err := db.db.Get(externalAccountKeysByProvisionerIDTable, []byte(provisionerID))
	if err != nil {
		if !nosqlDB.IsErrNotFound(err) {
			return nil, errors.Wrapf(err, "error loading ACME EAB Key IDs for provisioner %s", provisionerID)
		}
	} else {
		if err := json.Unmarshal(r, &eakIDs); err != nil {
			return nil, errors.Wrapf(err, "error unmarshaling ACME EAB Key IDs for provisioner %s", provisionerID)
		}
	}

	keys := []*acme.ExternalAccountKey{}
	for _, eakID := range eakIDs {
		if eakID == "" {
			continue // shouldn't happen; just in case
		}
		eak, err := db.getDBExternalAccountKey(ctx, eakID)
		if err != nil {
			if !nosqlDB.IsErrNotFound(err) {
				return nil, errors.Wrapf(err, "error retrieving ACME EAB Key for provisioner %s and keyID %s", provisionerID, eakID)
			}
		}
		keys = append(keys, &acme.ExternalAccountKey{
			ID:            eak.ID,
			KeyBytes:      eak.KeyBytes,
			ProvisionerID: eak.ProvisionerID,
			Reference:     eak.Reference,
			AccountID:     eak.AccountID,
			CreatedAt:     eak.CreatedAt,
			BoundAt:       eak.BoundAt,
		})
	}

	return keys, nil
}

// GetExternalAccountKeyByReference retrieves an External Account Binding key with unique reference
func (db *DB) GetExternalAccountKeyByReference(ctx context.Context, provisionerID, reference string) (*acme.ExternalAccountKey, error) {
	if reference == "" {
		return nil, nil
	}

	k, err := db.db.Get(externalAccountKeysByReferenceTable, []byte(referenceKey(provisionerID, reference)))
	if nosqlDB.IsErrNotFound(err) {
		return nil, acme.ErrNotFound
	} else if err != nil {
		return nil, errors.Wrapf(err, "error loading ACME EAB key for reference %s", reference)
	}
	dbExternalAccountKeyReference := new(dbExternalAccountKeyReference)
	if err := json.Unmarshal(k, dbExternalAccountKeyReference); err != nil {
		return nil, errors.Wrapf(err, "error unmarshaling ACME EAB key for reference %s", reference)
	}

	return db.GetExternalAccountKey(ctx, provisionerID, dbExternalAccountKeyReference.ExternalAccountKeyID)
}

func (db *DB) UpdateExternalAccountKey(ctx context.Context, provisionerID string, eak *acme.ExternalAccountKey) error {
	old, err := db.getDBExternalAccountKey(ctx, eak.ID)
	if err != nil {
		return err
	}

	if old.ProvisionerID != provisionerID {
		return errors.New("provisioner does not match provisioner for which the EAB key was created")
	}

	if old.ProvisionerID != eak.ProvisionerID {
		return errors.New("cannot change provisioner for an existing ACME EAB Key")
	}

	if old.Reference != eak.Reference {
		return errors.New("cannot change reference for an existing ACME EAB Key")
	}

	nu := dbExternalAccountKey{
		ID:            eak.ID,
		ProvisionerID: eak.ProvisionerID,
		Reference:     eak.Reference,
		AccountID:     eak.AccountID,
		KeyBytes:      eak.KeyBytes,
		CreatedAt:     eak.CreatedAt,
		BoundAt:       eak.BoundAt,
	}

	return db.save(ctx, nu.ID, nu, old, "external_account_key", externalAccountKeyTable)
}

func (db *DB) addEAKID(ctx context.Context, provisionerID, eakID string) error {
	referencesByProvisionerIndexMux.Lock()
	defer referencesByProvisionerIndexMux.Unlock()

	var eakIDs []string
	b, err := db.db.Get(externalAccountKeysByProvisionerIDTable, []byte(provisionerID))
	if err != nil {
		if !nosqlDB.IsErrNotFound(err) {
			return errors.Wrapf(err, "error loading eakIDs for provisioner %s", provisionerID)
		}
	} else {
		if err := json.Unmarshal(b, &eakIDs); err != nil {
			return errors.Wrapf(err, "error unmarshaling eakIDs for provisioner %s", provisionerID)
		}
	}

	var newEAKIDs []string
	newEAKIDs = append(newEAKIDs, eakIDs...)
	newEAKIDs = append(newEAKIDs, eakID)
	var (
		_old interface{} = eakIDs
		_new interface{} = newEAKIDs
	)

	if err = db.save(ctx, provisionerID, _new, _old, "externalAccountKeysByProvisionerID", externalAccountKeysByProvisionerIDTable); err != nil {
		return errors.Wrapf(err, "error saving eakIDs index for provisioner %s", provisionerID)
	}

	return nil
}

func (db *DB) deleteEAKID(ctx context.Context, provisionerID, eakID string) error {
	referencesByProvisionerIndexMux.Lock()
	defer referencesByProvisionerIndexMux.Unlock()

	var eakIDs []string
	b, err := db.db.Get(externalAccountKeysByProvisionerIDTable, []byte(provisionerID))
	if err != nil {
		if !nosqlDB.IsErrNotFound(err) {
			return errors.Wrapf(err, "error loading reference IDs for provisioner %s", provisionerID)
		}
	} else {
		if err := json.Unmarshal(b, &eakIDs); err != nil {
			return errors.Wrapf(err, "error unmarshaling eakIDs for provisioner %s", provisionerID)
		}
	}

	newEAKIDs := removeElement(eakIDs, eakID)
	var (
		_old interface{} = eakIDs
		_new interface{} = newEAKIDs
	)

	if err = db.save(ctx, provisionerID, _new, _old, "externalAccountKeysByProvisionerID", externalAccountKeysByProvisionerIDTable); err != nil {
		return errors.Wrapf(err, "error saving referenceIDs index for provisioner %s", provisionerID)
	}

	return nil
}

// referenceKey returns a unique key for a reference per provisioner
func referenceKey(provisionerID, reference string) string {
	return provisionerID + "." + reference
}

// sliceIndex finds the index of item in slice
func sliceIndex(slice []string, item string) int {
	for i := range slice {
		if slice[i] == item {
			return i
		}
	}
	return -1
}

// removeElement deletes the item if it exists in the
// slice. It returns a new slice, keeping the old one intact.
func removeElement(slice []string, item string) []string {

	newSlice := make([]string, 0)
	index := sliceIndex(slice, item)
	if index < 0 {
		newSlice = append(newSlice, slice...)
		return newSlice
	}

	newSlice = append(newSlice, slice[:index]...)

	return append(newSlice, slice[index+1:]...)
}
