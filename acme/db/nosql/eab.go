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
)

// externalAccountKeyMutex for read/write locking of EAK operations.
var externalAccountKeyMutex sync.RWMutex

// referencesByProvisionerIndexMutex for locking referencesByProvisioner index operations.
var referencesByProvisionerIndexMutex sync.Mutex

type dbExternalAccountKey struct {
	ID            string    `json:"id"`
	ProvisionerID string    `json:"provisionerID"`
	Reference     string    `json:"reference"`
	AccountID     string    `json:"accountID,omitempty"`
	HmacKey       []byte    `json:"key"`
	CreatedAt     time.Time `json:"createdAt"`
	BoundAt       time.Time `json:"boundAt"`
}

type dbExternalAccountKeyReference struct {
	Reference            string `json:"reference"`
	ExternalAccountKeyID string `json:"externalAccountKeyID"`
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

// CreateExternalAccountKey creates a new External Account Binding key with a name
func (db *DB) CreateExternalAccountKey(ctx context.Context, provisionerID, reference string) (*acme.ExternalAccountKey, error) {
	externalAccountKeyMutex.Lock()
	defer externalAccountKeyMutex.Unlock()

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
		HmacKey:       random,
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
		if err := db.save(ctx, referenceKey(provisionerID, dbeak.Reference), dbExternalAccountKeyReference, nil, "external_account_key_reference", externalAccountKeyIDsByReferenceTable); err != nil {
			return nil, err
		}
	}

	return &acme.ExternalAccountKey{
		ID:            dbeak.ID,
		ProvisionerID: dbeak.ProvisionerID,
		Reference:     dbeak.Reference,
		AccountID:     dbeak.AccountID,
		HmacKey:       dbeak.HmacKey,
		CreatedAt:     dbeak.CreatedAt,
		BoundAt:       dbeak.BoundAt,
	}, nil
}

// GetExternalAccountKey retrieves an External Account Binding key by KeyID
func (db *DB) GetExternalAccountKey(ctx context.Context, provisionerID, keyID string) (*acme.ExternalAccountKey, error) {
	externalAccountKeyMutex.RLock()
	defer externalAccountKeyMutex.RUnlock()

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
		HmacKey:       dbeak.HmacKey,
		CreatedAt:     dbeak.CreatedAt,
		BoundAt:       dbeak.BoundAt,
	}, nil
}

func (db *DB) DeleteExternalAccountKey(ctx context.Context, provisionerID, keyID string) error {
	externalAccountKeyMutex.Lock()
	defer externalAccountKeyMutex.Unlock()

	dbeak, err := db.getDBExternalAccountKey(ctx, keyID)
	if err != nil {
		return errors.Wrapf(err, "error loading ACME EAB Key with Key ID %s", keyID)
	}

	if dbeak.ProvisionerID != provisionerID {
		return errors.New("provisioner does not match provisioner for which the EAB key was created")
	}

	if dbeak.Reference != "" {
		if err := db.db.Del(externalAccountKeyIDsByReferenceTable, []byte(referenceKey(provisionerID, dbeak.Reference))); err != nil {
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
func (db *DB) GetExternalAccountKeys(ctx context.Context, provisionerID, cursor string, limit int) ([]*acme.ExternalAccountKey, string, error) {
	externalAccountKeyMutex.RLock()
	defer externalAccountKeyMutex.RUnlock()

	// cursor and limit are ignored in open source, at least for now.

	var eakIDs []string
	r, err := db.db.Get(externalAccountKeyIDsByProvisionerIDTable, []byte(provisionerID))
	if err != nil {
		if !nosqlDB.IsErrNotFound(err) {
			return nil, "", errors.Wrapf(err, "error loading ACME EAB Key IDs for provisioner %s", provisionerID)
		}
		// it may happen that no record is found; we'll continue with an empty slice
	} else {
		if err := json.Unmarshal(r, &eakIDs); err != nil {
			return nil, "", errors.Wrapf(err, "error unmarshaling ACME EAB Key IDs for provisioner %s", provisionerID)
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
				return nil, "", errors.Wrapf(err, "error retrieving ACME EAB Key for provisioner %s and keyID %s", provisionerID, eakID)
			}
		}
		keys = append(keys, &acme.ExternalAccountKey{
			ID:            eak.ID,
			HmacKey:       eak.HmacKey,
			ProvisionerID: eak.ProvisionerID,
			Reference:     eak.Reference,
			AccountID:     eak.AccountID,
			CreatedAt:     eak.CreatedAt,
			BoundAt:       eak.BoundAt,
		})
	}

	return keys, "", nil
}

// GetExternalAccountKeyByReference retrieves an External Account Binding key with unique reference
func (db *DB) GetExternalAccountKeyByReference(ctx context.Context, provisionerID, reference string) (*acme.ExternalAccountKey, error) {
	externalAccountKeyMutex.RLock()
	defer externalAccountKeyMutex.RUnlock()

	if reference == "" {
		//nolint:nilnil // legacy
		return nil, nil
	}

	k, err := db.db.Get(externalAccountKeyIDsByReferenceTable, []byte(referenceKey(provisionerID, reference)))
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

func (db *DB) GetExternalAccountKeyByAccountID(ctx context.Context, provisionerID, accountID string) (*acme.ExternalAccountKey, error) {
	//nolint:nilnil // legacy
	return nil, nil
}

func (db *DB) UpdateExternalAccountKey(ctx context.Context, provisionerID string, eak *acme.ExternalAccountKey) error {
	externalAccountKeyMutex.Lock()
	defer externalAccountKeyMutex.Unlock()

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
		HmacKey:       eak.HmacKey,
		CreatedAt:     eak.CreatedAt,
		BoundAt:       eak.BoundAt,
	}

	return db.save(ctx, nu.ID, nu, old, "external_account_key", externalAccountKeyTable)
}

func (db *DB) addEAKID(ctx context.Context, provisionerID, eakID string) error {
	referencesByProvisionerIndexMutex.Lock()
	defer referencesByProvisionerIndexMutex.Unlock()

	if eakID == "" {
		return errors.Errorf("can't add empty eakID for provisioner %s", provisionerID)
	}

	var eakIDs []string
	b, err := db.db.Get(externalAccountKeyIDsByProvisionerIDTable, []byte(provisionerID))
	if err != nil {
		if !nosqlDB.IsErrNotFound(err) {
			return errors.Wrapf(err, "error loading eakIDs for provisioner %s", provisionerID)
		}
		// it may happen that no record is found; we'll continue with an empty slice
	} else {
		if err := json.Unmarshal(b, &eakIDs); err != nil {
			return errors.Wrapf(err, "error unmarshaling eakIDs for provisioner %s", provisionerID)
		}
	}

	for _, id := range eakIDs {
		if id == eakID {
			// return an error when a duplicate ID is found
			return errors.Errorf("eakID %s already exists for provisioner %s", eakID, provisionerID)
		}
	}

	var newEAKIDs []string
	newEAKIDs = append(newEAKIDs, eakIDs...)
	newEAKIDs = append(newEAKIDs, eakID)

	var (
		_old interface{} = eakIDs
		_new interface{} = newEAKIDs
	)

	// ensure that the DB gets the expected value when the slice is empty; otherwise
	// it'll return with an error that indicates that the DBs view of the data is
	// different from the last read (i.e. _old is different from what the DB has).
	if len(eakIDs) == 0 {
		_old = nil
	}

	if err = db.save(ctx, provisionerID, _new, _old, "externalAccountKeyIDsByProvisionerID", externalAccountKeyIDsByProvisionerIDTable); err != nil {
		return errors.Wrapf(err, "error saving eakIDs index for provisioner %s", provisionerID)
	}

	return nil
}

func (db *DB) deleteEAKID(ctx context.Context, provisionerID, eakID string) error {
	referencesByProvisionerIndexMutex.Lock()
	defer referencesByProvisionerIndexMutex.Unlock()

	var eakIDs []string
	b, err := db.db.Get(externalAccountKeyIDsByProvisionerIDTable, []byte(provisionerID))
	if err != nil {
		if !nosqlDB.IsErrNotFound(err) {
			return errors.Wrapf(err, "error loading eakIDs for provisioner %s", provisionerID)
		}
		// it may happen that no record is found; we'll continue with an empty slice
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

	// ensure that the DB gets the expected value when the slice is empty; otherwise
	// it'll return with an error that indicates that the DBs view of the data is
	// different from the last read (i.e. _old is different from what the DB has).
	if len(eakIDs) == 0 {
		_old = nil
	}

	if err = db.save(ctx, provisionerID, _new, _old, "externalAccountKeyIDsByProvisionerID", externalAccountKeyIDsByProvisionerIDTable); err != nil {
		return errors.Wrapf(err, "error saving eakIDs index for provisioner %s", provisionerID)
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
