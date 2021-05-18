package mgmt

import (
	"context"

	"github.com/pkg/errors"
)

// ErrNotFound is an error that should be used by the authority.DB interface to
// indicate that an entity does not exist.
var ErrNotFound = errors.New("not found")

// DB is the DB interface expected by the step-ca ACME API.
type DB interface {
	CreateProvisioner(ctx context.Context, prov *Provisioner) error
	GetProvisioner(ctx context.Context, id string) (*Provisioner, error)
	GetProvisionerByName(ctx context.Context, name string) (*Provisioner, error)
	GetProvisioners(ctx context.Context) ([]*Provisioner, error)
	UpdateProvisioner(ctx context.Context, name string, prov *Provisioner) error

	CreateAdmin(ctx context.Context, admin *Admin) error
	GetAdmin(ctx context.Context, id string) (*Admin, error)
	GetAdmins(ctx context.Context) ([]*Admin, error)
	UpdateAdmin(ctx context.Context, admin *Admin) error

	CreateAuthConfig(ctx context.Context, ac *AuthConfig) error
	GetAuthConfig(ctx context.Context, id string) (*AuthConfig, error)
	UpdateAuthConfig(ctx context.Context, ac *AuthConfig) error
}

// MockDB is an implementation of the DB interface that should only be used as
// a mock in tests.
type MockDB struct {
	MockCreateProvisioner    func(ctx context.Context, prov *Provisioner) error
	MockGetProvisioner       func(ctx context.Context, id string) (*Provisioner, error)
	MockGetProvisionerByName func(ctx context.Context, name string) (*Provisioner, error)
	MockGetProvisioners      func(ctx context.Context) ([]*Provisioner, error)
	MockUpdateProvisioner    func(ctx context.Context, name string, prov *Provisioner) error

	MockCreateAdmin func(ctx context.Context, adm *Admin) error
	MockGetAdmin    func(ctx context.Context, id string) (*Admin, error)
	MockGetAdmins   func(ctx context.Context) ([]*Admin, error)
	MockUpdateAdmin func(ctx context.Context, adm *Admin) error

	MockCreateAuthConfig func(ctx context.Context, ac *AuthConfig) error
	MockGetAuthConfig    func(ctx context.Context, id string) (*AuthConfig, error)
	MockUpdateAuthConfig func(ctx context.Context, ac *AuthConfig) error

	MockError error
	MockRet1  interface{}
}

// CreateProvisioner mock.
func (m *MockDB) CreateProvisioner(ctx context.Context, prov *Provisioner) error {
	if m.MockCreateProvisioner != nil {
		return m.MockCreateProvisioner(ctx, prov)
	} else if m.MockError != nil {
		return m.MockError
	}
	return m.MockError
}

// GetProvisioner mock.
func (m *MockDB) GetProvisioner(ctx context.Context, id string) (*Provisioner, error) {
	if m.MockGetProvisioner != nil {
		return m.MockGetProvisioner(ctx, id)
	} else if m.MockError != nil {
		return nil, m.MockError
	}
	return m.MockRet1.(*Provisioner), m.MockError
}

// GetProvisionerByName mock.
func (m *MockDB) GetProvisionerByName(ctx context.Context, id string) (*Provisioner, error) {
	if m.MockGetProvisionerByName != nil {
		return m.MockGetProvisionerByName(ctx, id)
	} else if m.MockError != nil {
		return nil, m.MockError
	}
	return m.MockRet1.(*Provisioner), m.MockError
}

// GetProvisioners mock
func (m *MockDB) GetProvisioners(ctx context.Context) ([]*Provisioner, error) {
	if m.MockGetProvisioners != nil {
		return m.MockGetProvisioners(ctx)
	} else if m.MockError != nil {
		return nil, m.MockError
	}
	return m.MockRet1.([]*Provisioner), m.MockError
}

// UpdateProvisioner mock
func (m *MockDB) UpdateProvisioner(ctx context.Context, name string, prov *Provisioner) error {
	if m.MockUpdateProvisioner != nil {
		return m.MockUpdateProvisioner(ctx, name, prov)
	}
	return m.MockError
}

// CreateAdmin mock
func (m *MockDB) CreateAdmin(ctx context.Context, admin *Admin) error {
	if m.MockCreateAdmin != nil {
		return m.MockCreateAdmin(ctx, admin)
	}
	return m.MockError
}

// GetAdmin mock.
func (m *MockDB) GetAdmin(ctx context.Context, id string) (*Admin, error) {
	if m.MockGetAdmin != nil {
		return m.MockGetAdmin(ctx, id)
	} else if m.MockError != nil {
		return nil, m.MockError
	}
	return m.MockRet1.(*Admin), m.MockError
}

// GetAdmins mock
func (m *MockDB) GetAdmins(ctx context.Context) ([]*Admin, error) {
	if m.MockGetAdmins != nil {
		return m.MockGetAdmins(ctx)
	} else if m.MockError != nil {
		return nil, m.MockError
	}
	return m.MockRet1.([]*Admin), m.MockError
}

// UpdateAdmin mock
func (m *MockDB) UpdateAdmin(ctx context.Context, adm *Admin) error {
	if m.MockUpdateAdmin != nil {
		return m.MockUpdateAdmin(ctx, adm)
	}
	return m.MockError
}

// CreateAuthConfig mock
func (m *MockDB) CreateAuthConfig(ctx context.Context, admin *AuthConfig) error {
	if m.MockCreateAuthConfig != nil {
		return m.MockCreateAuthConfig(ctx, admin)
	}
	return m.MockError
}

// GetAuthConfig mock.
func (m *MockDB) GetAuthConfig(ctx context.Context, id string) (*AuthConfig, error) {
	if m.MockGetAuthConfig != nil {
		return m.MockGetAuthConfig(ctx, id)
	} else if m.MockError != nil {
		return nil, m.MockError
	}
	return m.MockRet1.(*AuthConfig), m.MockError
}

// UpdateAuthConfig mock
func (m *MockDB) UpdateAuthConfig(ctx context.Context, adm *AuthConfig) error {
	if m.MockUpdateAuthConfig != nil {
		return m.MockUpdateAuthConfig(ctx, adm)
	}
	return m.MockError
}
