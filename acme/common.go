package acme

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/smallstep/certificates/authority/provisioner"
)

// CertificateAuthority is the interface implemented by a CA authority.
type CertificateAuthority interface {
	Sign(cr *x509.CertificateRequest, opts provisioner.SignOptions, signOpts ...provisioner.SignOption) ([]*x509.Certificate, error)
	LoadProvisionerByName(string) (provisioner.Interface, error)
}

// Clock that returns time in UTC rounded to seconds.
type Clock struct{}

// Now returns the UTC time rounded to seconds.
func (c *Clock) Now() time.Time {
	return time.Now().UTC().Truncate(time.Second)
}

var clock Clock

// Provisioner is an interface that implements a subset of the provisioner.Interface --
// only those methods required by the ACME api/authority.
type Provisioner interface {
	AuthorizeSign(ctx context.Context, token string) ([]provisioner.SignOption, error)
	GetID() string
	GetName() string
	DefaultTLSCertDuration() time.Duration
	GetOptions() *provisioner.Options
}

// MockProvisioner for testing
type MockProvisioner struct {
	Mret1                   interface{}
	Merr                    error
	MgetID                  func() string
	MgetName                func() string
	MauthorizeSign          func(ctx context.Context, ott string) ([]provisioner.SignOption, error)
	MdefaultTLSCertDuration func() time.Duration
	MgetOptions             func() *provisioner.Options
}

// GetName mock
func (m *MockProvisioner) GetName() string {
	if m.MgetName != nil {
		return m.MgetName()
	}
	return m.Mret1.(string)
}

// AuthorizeSign mock
func (m *MockProvisioner) AuthorizeSign(ctx context.Context, ott string) ([]provisioner.SignOption, error) {
	if m.MauthorizeSign != nil {
		return m.MauthorizeSign(ctx, ott)
	}
	return m.Mret1.([]provisioner.SignOption), m.Merr
}

// DefaultTLSCertDuration mock
func (m *MockProvisioner) DefaultTLSCertDuration() time.Duration {
	if m.MdefaultTLSCertDuration != nil {
		return m.MdefaultTLSCertDuration()
	}
	return m.Mret1.(time.Duration)
}

// GetOptions mock
func (m *MockProvisioner) GetOptions() *provisioner.Options {
	if m.MgetOptions != nil {
		return m.MgetOptions()
	}
	return m.Mret1.(*provisioner.Options)
}

// GetID mock
func (m *MockProvisioner) GetID() string {
	if m.MgetID != nil {
		return m.MgetID()
	}
	return m.Mret1.(string)
}
