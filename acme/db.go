package acme

import (
	"context"

	"github.com/pkg/errors"
)

// ErrNotFound is an error that should be used by the acme.DB interface to
// indicate that an entity does not exist. For example, in the new-account
// endpoint, if GetAccountByKeyID returns ErrNotFound we will create the new
// account.
var ErrNotFound = errors.New("not found")

// DB is the DB interface expected by the step-ca ACME API.
type DB interface {
	CreateAccount(ctx context.Context, acc *Account) error
	GetAccount(ctx context.Context, id string) (*Account, error)
	GetAccountByKeyID(ctx context.Context, kid string) (*Account, error)
	UpdateAccount(ctx context.Context, acc *Account) error

	CreateExternalAccountKey(ctx context.Context, provisionerID, reference string) (*ExternalAccountKey, error)
	GetExternalAccountKey(ctx context.Context, provisionerID, keyID string) (*ExternalAccountKey, error)
	GetExternalAccountKeys(ctx context.Context, provisionerID, cursor string, limit int) ([]*ExternalAccountKey, string, error)
	GetExternalAccountKeyByReference(ctx context.Context, provisionerID, reference string) (*ExternalAccountKey, error)
	GetExternalAccountKeyByAccountID(ctx context.Context, provisionerID, accountID string) (*ExternalAccountKey, error)
	DeleteExternalAccountKey(ctx context.Context, provisionerID, keyID string) error
	UpdateExternalAccountKey(ctx context.Context, provisionerID string, eak *ExternalAccountKey) error

	CreateNonce(ctx context.Context) (Nonce, error)
	DeleteNonce(ctx context.Context, nonce Nonce) error

	CreateAuthorization(ctx context.Context, az *Authorization) error
	GetAuthorization(ctx context.Context, id string) (*Authorization, error)
	UpdateAuthorization(ctx context.Context, az *Authorization) error
	GetAuthorizationsByAccountID(ctx context.Context, accountID string) ([]*Authorization, error)

	CreateCertificate(ctx context.Context, cert *Certificate) error
	GetCertificate(ctx context.Context, id string) (*Certificate, error)
	GetCertificateBySerial(ctx context.Context, serial string) (*Certificate, error)

	CreateChallenge(ctx context.Context, ch *Challenge) error
	GetChallenge(ctx context.Context, id, authzID string) (*Challenge, error)
	UpdateChallenge(ctx context.Context, ch *Challenge) error

	CreateOrder(ctx context.Context, o *Order) error
	GetOrder(ctx context.Context, id string) (*Order, error)
	GetOrdersByAccountID(ctx context.Context, accountID string) ([]string, error)
	UpdateOrder(ctx context.Context, o *Order) error
}

type dbKey struct{}

// NewDatabaseContext adds the given acme database to the context.
func NewDatabaseContext(ctx context.Context, db DB) context.Context {
	return context.WithValue(ctx, dbKey{}, db)
}

// DatabaseFromContext returns the current acme database from the given context.
func DatabaseFromContext(ctx context.Context) (db DB, ok bool) {
	db, ok = ctx.Value(dbKey{}).(DB)
	return
}

// MustDatabaseFromContext returns the current database from the given context.
// It will panic if it's not in the context.
func MustDatabaseFromContext(ctx context.Context) DB {
	if db, ok := DatabaseFromContext(ctx); !ok {
		panic("acme database is not in the context")
	} else {
		return db
	}
}

// MockDB is an implementation of the DB interface that should only be used as
// a mock in tests.
type MockDB struct {
	MockCreateAccount     func(ctx context.Context, acc *Account) error
	MockGetAccount        func(ctx context.Context, id string) (*Account, error)
	MockGetAccountByKeyID func(ctx context.Context, kid string) (*Account, error)
	MockUpdateAccount     func(ctx context.Context, acc *Account) error

	MockCreateExternalAccountKey         func(ctx context.Context, provisionerID, reference string) (*ExternalAccountKey, error)
	MockGetExternalAccountKey            func(ctx context.Context, provisionerID, keyID string) (*ExternalAccountKey, error)
	MockGetExternalAccountKeys           func(ctx context.Context, provisionerID, cursor string, limit int) ([]*ExternalAccountKey, string, error)
	MockGetExternalAccountKeyByReference func(ctx context.Context, provisionerID, reference string) (*ExternalAccountKey, error)
	MockGetExternalAccountKeyByAccountID func(ctx context.Context, provisionerID, accountID string) (*ExternalAccountKey, error)
	MockDeleteExternalAccountKey         func(ctx context.Context, provisionerID, keyID string) error
	MockUpdateExternalAccountKey         func(ctx context.Context, provisionerID string, eak *ExternalAccountKey) error

	MockCreateNonce func(ctx context.Context) (Nonce, error)
	MockDeleteNonce func(ctx context.Context, nonce Nonce) error

	MockCreateAuthorization          func(ctx context.Context, az *Authorization) error
	MockGetAuthorization             func(ctx context.Context, id string) (*Authorization, error)
	MockUpdateAuthorization          func(ctx context.Context, az *Authorization) error
	MockGetAuthorizationsByAccountID func(ctx context.Context, accountID string) ([]*Authorization, error)

	MockCreateCertificate      func(ctx context.Context, cert *Certificate) error
	MockGetCertificate         func(ctx context.Context, id string) (*Certificate, error)
	MockGetCertificateBySerial func(ctx context.Context, serial string) (*Certificate, error)

	MockCreateChallenge func(ctx context.Context, ch *Challenge) error
	MockGetChallenge    func(ctx context.Context, id, authzID string) (*Challenge, error)
	MockUpdateChallenge func(ctx context.Context, ch *Challenge) error

	MockCreateOrder          func(ctx context.Context, o *Order) error
	MockGetOrder             func(ctx context.Context, id string) (*Order, error)
	MockGetOrdersByAccountID func(ctx context.Context, accountID string) ([]string, error)
	MockUpdateOrder          func(ctx context.Context, o *Order) error

	MockRet1  interface{}
	MockError error
}

// CreateAccount mock.
func (m *MockDB) CreateAccount(ctx context.Context, acc *Account) error {
	if m.MockCreateAccount != nil {
		return m.MockCreateAccount(ctx, acc)
	} else if m.MockError != nil {
		return m.MockError
	}
	return m.MockError
}

// GetAccount mock.
func (m *MockDB) GetAccount(ctx context.Context, id string) (*Account, error) {
	if m.MockGetAccount != nil {
		return m.MockGetAccount(ctx, id)
	} else if m.MockError != nil {
		return nil, m.MockError
	}
	return m.MockRet1.(*Account), m.MockError
}

// GetAccountByKeyID mock
func (m *MockDB) GetAccountByKeyID(ctx context.Context, kid string) (*Account, error) {
	if m.MockGetAccountByKeyID != nil {
		return m.MockGetAccountByKeyID(ctx, kid)
	} else if m.MockError != nil {
		return nil, m.MockError
	}
	return m.MockRet1.(*Account), m.MockError
}

// UpdateAccount mock
func (m *MockDB) UpdateAccount(ctx context.Context, acc *Account) error {
	if m.MockUpdateAccount != nil {
		return m.MockUpdateAccount(ctx, acc)
	} else if m.MockError != nil {
		return m.MockError
	}
	return m.MockError
}

// CreateExternalAccountKey mock
func (m *MockDB) CreateExternalAccountKey(ctx context.Context, provisionerID, reference string) (*ExternalAccountKey, error) {
	if m.MockCreateExternalAccountKey != nil {
		return m.MockCreateExternalAccountKey(ctx, provisionerID, reference)
	} else if m.MockError != nil {
		return nil, m.MockError
	}
	return m.MockRet1.(*ExternalAccountKey), m.MockError
}

// GetExternalAccountKey mock
func (m *MockDB) GetExternalAccountKey(ctx context.Context, provisionerID, keyID string) (*ExternalAccountKey, error) {
	if m.MockGetExternalAccountKey != nil {
		return m.MockGetExternalAccountKey(ctx, provisionerID, keyID)
	} else if m.MockError != nil {
		return nil, m.MockError
	}
	return m.MockRet1.(*ExternalAccountKey), m.MockError
}

// GetExternalAccountKeys mock
func (m *MockDB) GetExternalAccountKeys(ctx context.Context, provisionerID, cursor string, limit int) ([]*ExternalAccountKey, string, error) {
	if m.MockGetExternalAccountKeys != nil {
		return m.MockGetExternalAccountKeys(ctx, provisionerID, cursor, limit)
	} else if m.MockError != nil {
		return nil, "", m.MockError
	}
	return m.MockRet1.([]*ExternalAccountKey), "", m.MockError
}

// GetExternalAccountKeyByReference mock
func (m *MockDB) GetExternalAccountKeyByReference(ctx context.Context, provisionerID, reference string) (*ExternalAccountKey, error) {
	if m.MockGetExternalAccountKeyByReference != nil {
		return m.MockGetExternalAccountKeyByReference(ctx, provisionerID, reference)
	} else if m.MockError != nil {
		return nil, m.MockError
	}
	return m.MockRet1.(*ExternalAccountKey), m.MockError
}

// GetExternalAccountKeyByAccountID mock
func (m *MockDB) GetExternalAccountKeyByAccountID(ctx context.Context, provisionerID, accountID string) (*ExternalAccountKey, error) {
	if m.MockGetExternalAccountKeyByAccountID != nil {
		return m.MockGetExternalAccountKeyByAccountID(ctx, provisionerID, accountID)
	} else if m.MockError != nil {
		return nil, m.MockError
	}
	return m.MockRet1.(*ExternalAccountKey), m.MockError
}

// DeleteExternalAccountKey mock
func (m *MockDB) DeleteExternalAccountKey(ctx context.Context, provisionerID, keyID string) error {
	if m.MockDeleteExternalAccountKey != nil {
		return m.MockDeleteExternalAccountKey(ctx, provisionerID, keyID)
	} else if m.MockError != nil {
		return m.MockError
	}
	return m.MockError
}

// UpdateExternalAccountKey mock
func (m *MockDB) UpdateExternalAccountKey(ctx context.Context, provisionerID string, eak *ExternalAccountKey) error {
	if m.MockUpdateExternalAccountKey != nil {
		return m.MockUpdateExternalAccountKey(ctx, provisionerID, eak)
	} else if m.MockError != nil {
		return m.MockError
	}
	return m.MockError
}

// CreateNonce mock
func (m *MockDB) CreateNonce(ctx context.Context) (Nonce, error) {
	if m.MockCreateNonce != nil {
		return m.MockCreateNonce(ctx)
	} else if m.MockError != nil {
		return Nonce(""), m.MockError
	}
	return m.MockRet1.(Nonce), m.MockError
}

// DeleteNonce mock
func (m *MockDB) DeleteNonce(ctx context.Context, nonce Nonce) error {
	if m.MockDeleteNonce != nil {
		return m.MockDeleteNonce(ctx, nonce)
	} else if m.MockError != nil {
		return m.MockError
	}
	return m.MockError
}

// CreateAuthorization mock
func (m *MockDB) CreateAuthorization(ctx context.Context, az *Authorization) error {
	if m.MockCreateAuthorization != nil {
		return m.MockCreateAuthorization(ctx, az)
	} else if m.MockError != nil {
		return m.MockError
	}
	return m.MockError
}

// GetAuthorization mock
func (m *MockDB) GetAuthorization(ctx context.Context, id string) (*Authorization, error) {
	if m.MockGetAuthorization != nil {
		return m.MockGetAuthorization(ctx, id)
	} else if m.MockError != nil {
		return nil, m.MockError
	}
	return m.MockRet1.(*Authorization), m.MockError
}

// UpdateAuthorization mock
func (m *MockDB) UpdateAuthorization(ctx context.Context, az *Authorization) error {
	if m.MockUpdateAuthorization != nil {
		return m.MockUpdateAuthorization(ctx, az)
	} else if m.MockError != nil {
		return m.MockError
	}
	return m.MockError
}

// GetAuthorizationsByAccountID mock
func (m *MockDB) GetAuthorizationsByAccountID(ctx context.Context, accountID string) ([]*Authorization, error) {
	if m.MockGetAuthorizationsByAccountID != nil {
		return m.MockGetAuthorizationsByAccountID(ctx, accountID)
	} else if m.MockError != nil {
		return nil, m.MockError
	}
	return nil, m.MockError
}

// CreateCertificate mock
func (m *MockDB) CreateCertificate(ctx context.Context, cert *Certificate) error {
	if m.MockCreateCertificate != nil {
		return m.MockCreateCertificate(ctx, cert)
	} else if m.MockError != nil {
		return m.MockError
	}
	return m.MockError
}

// GetCertificate mock
func (m *MockDB) GetCertificate(ctx context.Context, id string) (*Certificate, error) {
	if m.MockGetCertificate != nil {
		return m.MockGetCertificate(ctx, id)
	} else if m.MockError != nil {
		return nil, m.MockError
	}
	return m.MockRet1.(*Certificate), m.MockError
}

// GetCertificateBySerial mock
func (m *MockDB) GetCertificateBySerial(ctx context.Context, serial string) (*Certificate, error) {
	if m.MockGetCertificateBySerial != nil {
		return m.MockGetCertificateBySerial(ctx, serial)
	} else if m.MockError != nil {
		return nil, m.MockError
	}
	return m.MockRet1.(*Certificate), m.MockError
}

// CreateChallenge mock
func (m *MockDB) CreateChallenge(ctx context.Context, ch *Challenge) error {
	if m.MockCreateChallenge != nil {
		return m.MockCreateChallenge(ctx, ch)
	} else if m.MockError != nil {
		return m.MockError
	}
	return m.MockError
}

// GetChallenge mock
func (m *MockDB) GetChallenge(ctx context.Context, chID, azID string) (*Challenge, error) {
	if m.MockGetChallenge != nil {
		return m.MockGetChallenge(ctx, chID, azID)
	} else if m.MockError != nil {
		return nil, m.MockError
	}
	return m.MockRet1.(*Challenge), m.MockError
}

// UpdateChallenge mock
func (m *MockDB) UpdateChallenge(ctx context.Context, ch *Challenge) error {
	if m.MockUpdateChallenge != nil {
		return m.MockUpdateChallenge(ctx, ch)
	} else if m.MockError != nil {
		return m.MockError
	}
	return m.MockError
}

// CreateOrder mock
func (m *MockDB) CreateOrder(ctx context.Context, o *Order) error {
	if m.MockCreateOrder != nil {
		return m.MockCreateOrder(ctx, o)
	} else if m.MockError != nil {
		return m.MockError
	}
	return m.MockError
}

// GetOrder mock
func (m *MockDB) GetOrder(ctx context.Context, id string) (*Order, error) {
	if m.MockGetOrder != nil {
		return m.MockGetOrder(ctx, id)
	} else if m.MockError != nil {
		return nil, m.MockError
	}
	return m.MockRet1.(*Order), m.MockError
}

// UpdateOrder mock
func (m *MockDB) UpdateOrder(ctx context.Context, o *Order) error {
	if m.MockUpdateOrder != nil {
		return m.MockUpdateOrder(ctx, o)
	} else if m.MockError != nil {
		return m.MockError
	}
	return m.MockError
}

// GetOrdersByAccountID mock
func (m *MockDB) GetOrdersByAccountID(ctx context.Context, accID string) ([]string, error) {
	if m.MockGetOrdersByAccountID != nil {
		return m.MockGetOrdersByAccountID(ctx, accID)
	} else if m.MockError != nil {
		return nil, m.MockError
	}
	return m.MockRet1.([]string), m.MockError
}
