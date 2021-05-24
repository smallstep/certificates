package mgmt

import (
	"context"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/linkedca"
)

// ErrNotFound is an error that should be used by the authority.DB interface to
// indicate that an entity does not exist.
var ErrNotFound = errors.New("not found")

// DB is the DB interface expected by the step-ca ACME API.
type DB interface {
	CreateProvisioner(ctx context.Context, prov *linkedca.Provisioner) error
	GetProvisioner(ctx context.Context, id string) (*linkedca.Provisioner, error)
	GetProvisioners(ctx context.Context) ([]*linkedca.Provisioner, error)
	UpdateProvisioner(ctx context.Context, prov *linkedca.Provisioner) error

	CreateAdmin(ctx context.Context, admin *linkedca.Admin) error
	GetAdmin(ctx context.Context, id string) (*linkedca.Admin, error)
	GetAdmins(ctx context.Context) ([]*linkedca.Admin, error)
	UpdateAdmin(ctx context.Context, admin *linkedca.Admin) error
}

// MockDB is an implementation of the DB interface that should only be used as
// a mock in tests.
type MockDB struct {
	MockCreateProvisioner func(ctx context.Context, prov *linkedca.Provisioner) error
	MockGetProvisioner    func(ctx context.Context, id string) (*linkedca.Provisioner, error)
	MockGetProvisioners   func(ctx context.Context) ([]*linkedca.Provisioner, error)
	MockUpdateProvisioner func(ctx context.Context, prov *linkedca.Provisioner) error

	MockCreateAdmin func(ctx context.Context, adm *linkedca.Admin) error
	MockGetAdmin    func(ctx context.Context, id string) (*linkedca.Admin, error)
	MockGetAdmins   func(ctx context.Context) ([]*linkedca.Admin, error)
	MockUpdateAdmin func(ctx context.Context, adm *linkedca.Admin) error

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
