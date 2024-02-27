package admin

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"
	"go.step.sm/linkedca"
)

const (
	// DefaultAuthorityID is the default AuthorityID. This will be the ID
	// of the first Authority created, as well as the default AuthorityID
	// if one is not specified in the configuration.
	DefaultAuthorityID = "00000000-0000-0000-0000-000000000000"
)

// ErrNotFound is an error that should be used by the authority.DB interface to
// indicate that an entity does not exist.
var ErrNotFound = errors.New("not found")

// UnmarshalProvisionerDetails unmarshals details type to the specific provisioner details.
func UnmarshalProvisionerDetails(typ linkedca.Provisioner_Type, data []byte) (*linkedca.ProvisionerDetails, error) {
	var v linkedca.ProvisionerDetails
	switch typ {
	case linkedca.Provisioner_JWK:
		v.Data = new(linkedca.ProvisionerDetails_JWK)
	case linkedca.Provisioner_OIDC:
		v.Data = new(linkedca.ProvisionerDetails_OIDC)
	case linkedca.Provisioner_GCP:
		v.Data = new(linkedca.ProvisionerDetails_GCP)
	case linkedca.Provisioner_AWS:
		v.Data = new(linkedca.ProvisionerDetails_AWS)
	case linkedca.Provisioner_AZURE:
		v.Data = new(linkedca.ProvisionerDetails_Azure)
	case linkedca.Provisioner_ACME:
		v.Data = new(linkedca.ProvisionerDetails_ACME)
	case linkedca.Provisioner_X5C:
		v.Data = new(linkedca.ProvisionerDetails_X5C)
	case linkedca.Provisioner_K8SSA:
		v.Data = new(linkedca.ProvisionerDetails_K8SSA)
	case linkedca.Provisioner_SSHPOP:
		v.Data = new(linkedca.ProvisionerDetails_SSHPOP)
	case linkedca.Provisioner_SCEP:
		v.Data = new(linkedca.ProvisionerDetails_SCEP)
	case linkedca.Provisioner_NEBULA:
		v.Data = new(linkedca.ProvisionerDetails_Nebula)
	default:
		return nil, fmt.Errorf("unsupported provisioner type %s", typ)
	}

	if err := json.Unmarshal(data, v.Data); err != nil {
		return nil, err
	}
	return &linkedca.ProvisionerDetails{Data: v.Data}, nil
}

// DB is the DB interface expected by the step-ca Admin API.
type DB interface {
	CreateProvisioner(ctx context.Context, prov *linkedca.Provisioner) error
	GetProvisioner(ctx context.Context, id string) (*linkedca.Provisioner, error)
	GetProvisioners(ctx context.Context) ([]*linkedca.Provisioner, error)
	UpdateProvisioner(ctx context.Context, prov *linkedca.Provisioner) error
	DeleteProvisioner(ctx context.Context, id string) error

	CreateAdmin(ctx context.Context, admin *linkedca.Admin) error
	GetAdmin(ctx context.Context, id string) (*linkedca.Admin, error)
	GetAdmins(ctx context.Context) ([]*linkedca.Admin, error)
	UpdateAdmin(ctx context.Context, admin *linkedca.Admin) error
	DeleteAdmin(ctx context.Context, id string) error

	CreateAuthorityPolicy(ctx context.Context, policy *linkedca.Policy) error
	GetAuthorityPolicy(ctx context.Context) (*linkedca.Policy, error)
	UpdateAuthorityPolicy(ctx context.Context, policy *linkedca.Policy) error
	DeleteAuthorityPolicy(ctx context.Context) error
}

type dbKey struct{}

// NewContext adds the given admin database to the context.
func NewContext(ctx context.Context, db DB) context.Context {
	return context.WithValue(ctx, dbKey{}, db)
}

// FromContext returns the current admin database from the given context.
func FromContext(ctx context.Context) (db DB, ok bool) {
	db, ok = ctx.Value(dbKey{}).(DB)
	return
}

// MustFromContext returns the current admin database from the given context. It
// will panic if it's not in the context.
func MustFromContext(ctx context.Context) DB {
	var (
		db DB
		ok bool
	)
	if db, ok = FromContext(ctx); !ok {
		panic("admin database is not in the context")
	}
	return db
}

// MockDB is an implementation of the DB interface that should only be used as
// a mock in tests.
type MockDB struct {
	MockCreateProvisioner func(ctx context.Context, prov *linkedca.Provisioner) error
	MockGetProvisioner    func(ctx context.Context, id string) (*linkedca.Provisioner, error)
	MockGetProvisioners   func(ctx context.Context) ([]*linkedca.Provisioner, error)
	MockUpdateProvisioner func(ctx context.Context, prov *linkedca.Provisioner) error
	MockDeleteProvisioner func(ctx context.Context, id string) error

	MockCreateAdmin func(ctx context.Context, adm *linkedca.Admin) error
	MockGetAdmin    func(ctx context.Context, id string) (*linkedca.Admin, error)
	MockGetAdmins   func(ctx context.Context) ([]*linkedca.Admin, error)
	MockUpdateAdmin func(ctx context.Context, adm *linkedca.Admin) error
	MockDeleteAdmin func(ctx context.Context, id string) error

	MockCreateAuthorityPolicy func(ctx context.Context, policy *linkedca.Policy) error
	MockGetAuthorityPolicy    func(ctx context.Context) (*linkedca.Policy, error)
	MockUpdateAuthorityPolicy func(ctx context.Context, policy *linkedca.Policy) error
	MockDeleteAuthorityPolicy func(ctx context.Context) error

	MockError error
	MockRet1  interface{}
}

// CreateProvisioner mock.
func (m *MockDB) CreateProvisioner(ctx context.Context, prov *linkedca.Provisioner) error {
	if m.MockCreateProvisioner != nil {
		return m.MockCreateProvisioner(ctx, prov)
	} else if m.MockError != nil {
		return m.MockError
	}
	return m.MockError
}

// GetProvisioner mock.
func (m *MockDB) GetProvisioner(ctx context.Context, id string) (*linkedca.Provisioner, error) {
	if m.MockGetProvisioner != nil {
		return m.MockGetProvisioner(ctx, id)
	} else if m.MockError != nil {
		return nil, m.MockError
	}
	return m.MockRet1.(*linkedca.Provisioner), m.MockError
}

// GetProvisioners mock
func (m *MockDB) GetProvisioners(ctx context.Context) ([]*linkedca.Provisioner, error) {
	if m.MockGetProvisioners != nil {
		return m.MockGetProvisioners(ctx)
	} else if m.MockError != nil {
		return nil, m.MockError
	}
	return m.MockRet1.([]*linkedca.Provisioner), m.MockError
}

// UpdateProvisioner mock
func (m *MockDB) UpdateProvisioner(ctx context.Context, prov *linkedca.Provisioner) error {
	if m.MockUpdateProvisioner != nil {
		return m.MockUpdateProvisioner(ctx, prov)
	}
	return m.MockError
}

// DeleteProvisioner mock
func (m *MockDB) DeleteProvisioner(ctx context.Context, id string) error {
	if m.MockDeleteProvisioner != nil {
		return m.MockDeleteProvisioner(ctx, id)
	}
	return m.MockError
}

// CreateAdmin mock
func (m *MockDB) CreateAdmin(ctx context.Context, admin *linkedca.Admin) error {
	if m.MockCreateAdmin != nil {
		return m.MockCreateAdmin(ctx, admin)
	}
	return m.MockError
}

// GetAdmin mock.
func (m *MockDB) GetAdmin(ctx context.Context, id string) (*linkedca.Admin, error) {
	if m.MockGetAdmin != nil {
		return m.MockGetAdmin(ctx, id)
	} else if m.MockError != nil {
		return nil, m.MockError
	}
	return m.MockRet1.(*linkedca.Admin), m.MockError
}

// GetAdmins mock
func (m *MockDB) GetAdmins(ctx context.Context) ([]*linkedca.Admin, error) {
	if m.MockGetAdmins != nil {
		return m.MockGetAdmins(ctx)
	} else if m.MockError != nil {
		return nil, m.MockError
	}
	return m.MockRet1.([]*linkedca.Admin), m.MockError
}

// UpdateAdmin mock
func (m *MockDB) UpdateAdmin(ctx context.Context, adm *linkedca.Admin) error {
	if m.MockUpdateAdmin != nil {
		return m.MockUpdateAdmin(ctx, adm)
	}
	return m.MockError
}

// DeleteAdmin mock
func (m *MockDB) DeleteAdmin(ctx context.Context, id string) error {
	if m.MockDeleteAdmin != nil {
		return m.MockDeleteAdmin(ctx, id)
	}
	return m.MockError
}

// CreateAuthorityPolicy mock
func (m *MockDB) CreateAuthorityPolicy(ctx context.Context, policy *linkedca.Policy) error {
	if m.MockCreateAuthorityPolicy != nil {
		return m.MockCreateAuthorityPolicy(ctx, policy)
	}
	return m.MockError
}

// GetAuthorityPolicy mock
func (m *MockDB) GetAuthorityPolicy(ctx context.Context) (*linkedca.Policy, error) {
	if m.MockGetAuthorityPolicy != nil {
		return m.MockGetAuthorityPolicy(ctx)
	}
	return m.MockRet1.(*linkedca.Policy), m.MockError
}

// UpdateAuthorityPolicy mock
func (m *MockDB) UpdateAuthorityPolicy(ctx context.Context, policy *linkedca.Policy) error {
	if m.MockUpdateAuthorityPolicy != nil {
		return m.MockUpdateAuthorityPolicy(ctx, policy)
	}
	return m.MockError
}

// DeleteAuthorityPolicy mock
func (m *MockDB) DeleteAuthorityPolicy(ctx context.Context) error {
	if m.MockDeleteAuthorityPolicy != nil {
		return m.MockDeleteAuthorityPolicy(ctx)
	}
	return m.MockError
}
