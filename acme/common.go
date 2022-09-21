package acme

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/provisioner"
)

// Clock that returns time in UTC rounded to seconds.
type Clock struct{}

// Now returns the UTC time rounded to seconds.
func (c *Clock) Now() time.Time {
	return time.Now().UTC().Truncate(time.Second)
}

var clock Clock

// CertificateAuthority is the interface implemented by a CA authority.
type CertificateAuthority interface {
	Sign(cr *x509.CertificateRequest, opts provisioner.SignOptions, signOpts ...provisioner.SignOption) ([]*x509.Certificate, error)
	AreSANsAllowed(ctx context.Context, sans []string) error
	IsRevoked(sn string) (bool, error)
	Revoke(context.Context, *authority.RevokeOptions) error
	LoadProvisionerByName(string) (provisioner.Interface, error)
}

// NewContext adds the given acme components to the context.
func NewContext(ctx context.Context, db DB, client Client, linker Linker, fn PrerequisitesChecker) context.Context {
	ctx = NewDatabaseContext(ctx, db)
	ctx = NewClientContext(ctx, client)
	ctx = NewLinkerContext(ctx, linker)
	// Prerequisite checker is optional.
	if fn != nil {
		ctx = NewPrerequisitesCheckerContext(ctx, fn)
	}
	return ctx
}

// PrerequisitesChecker is a function that checks if all prerequisites for
// serving ACME are met by the CA configuration.
type PrerequisitesChecker func(ctx context.Context) (bool, error)

// DefaultPrerequisitesChecker is the default PrerequisiteChecker and returns
// always true.
func DefaultPrerequisitesChecker(ctx context.Context) (bool, error) {
	return true, nil
}

type prerequisitesKey struct{}

// NewPrerequisitesCheckerContext adds the given PrerequisitesChecker to the
// context.
func NewPrerequisitesCheckerContext(ctx context.Context, fn PrerequisitesChecker) context.Context {
	return context.WithValue(ctx, prerequisitesKey{}, fn)
}

// PrerequisitesCheckerFromContext returns the PrerequisitesChecker in the
// context.
func PrerequisitesCheckerFromContext(ctx context.Context) (PrerequisitesChecker, bool) {
	fn, ok := ctx.Value(prerequisitesKey{}).(PrerequisitesChecker)
	return fn, ok && fn != nil
}

// Provisioner is an interface that implements a subset of the provisioner.Interface --
// only those methods required by the ACME api/authority.
type Provisioner interface {
	AuthorizeOrderIdentifier(ctx context.Context, identifier provisioner.ACMEIdentifier) error
	AuthorizeSign(ctx context.Context, token string) ([]provisioner.SignOption, error)
	AuthorizeRevoke(ctx context.Context, token string) error
	IsChallengeEnabled(ctx context.Context, challenge provisioner.ACMEChallenge) bool
	IsAttestationFormatEnabled(ctx context.Context, format provisioner.ACMEAttestationFormat) bool
	GetAttestationRoots() (*x509.CertPool, bool)
	GetID() string
	GetName() string
	DefaultTLSCertDuration() time.Duration
	GetOptions() *provisioner.Options
}

type provisionerKey struct{}

// NewProvisionerContext adds the given provisioner to the context.
func NewProvisionerContext(ctx context.Context, v Provisioner) context.Context {
	return context.WithValue(ctx, provisionerKey{}, v)
}

// ProvisionerFromContext returns the current provisioner from the given context.
func ProvisionerFromContext(ctx context.Context) (v Provisioner, ok bool) {
	v, ok = ctx.Value(provisionerKey{}).(Provisioner)
	return
}

// MustLinkerFromContext returns the current provisioner from the given context.
// It will panic if it's not in the context.
func MustProvisionerFromContext(ctx context.Context) Provisioner {
	if v, ok := ProvisionerFromContext(ctx); !ok {
		panic("acme provisioner is not the context")
	} else {
		return v
	}
}

// MockProvisioner for testing
type MockProvisioner struct {
	Mret1                     interface{}
	Merr                      error
	MgetID                    func() string
	MgetName                  func() string
	MauthorizeOrderIdentifier func(ctx context.Context, identifier provisioner.ACMEIdentifier) error
	MauthorizeSign            func(ctx context.Context, ott string) ([]provisioner.SignOption, error)
	MauthorizeRevoke          func(ctx context.Context, token string) error
	MisChallengeEnabled       func(ctx context.Context, challenge provisioner.ACMEChallenge) bool
	MisAttFormatEnabled       func(ctx context.Context, format provisioner.ACMEAttestationFormat) bool
	MgetAttestationRoots      func() (*x509.CertPool, bool)
	MdefaultTLSCertDuration   func() time.Duration
	MgetOptions               func() *provisioner.Options
}

// GetName mock
func (m *MockProvisioner) GetName() string {
	if m.MgetName != nil {
		return m.MgetName()
	}
	return m.Mret1.(string)
}

// AuthorizeOrderIdentifiers mock
func (m *MockProvisioner) AuthorizeOrderIdentifier(ctx context.Context, identifier provisioner.ACMEIdentifier) error {
	if m.MauthorizeOrderIdentifier != nil {
		return m.MauthorizeOrderIdentifier(ctx, identifier)
	}
	return m.Merr
}

// AuthorizeSign mock
func (m *MockProvisioner) AuthorizeSign(ctx context.Context, ott string) ([]provisioner.SignOption, error) {
	if m.MauthorizeSign != nil {
		return m.MauthorizeSign(ctx, ott)
	}
	return m.Mret1.([]provisioner.SignOption), m.Merr
}

// AuthorizeRevoke mock
func (m *MockProvisioner) AuthorizeRevoke(ctx context.Context, token string) error {
	if m.MauthorizeRevoke != nil {
		return m.MauthorizeRevoke(ctx, token)
	}
	return m.Merr
}

// IsChallengeEnabled mock
func (m *MockProvisioner) IsChallengeEnabled(ctx context.Context, challenge provisioner.ACMEChallenge) bool {
	if m.MisChallengeEnabled != nil {
		return m.MisChallengeEnabled(ctx, challenge)
	}
	return m.Merr == nil
}

// IsAttestationFormatEnabled mock
func (m *MockProvisioner) IsAttestationFormatEnabled(ctx context.Context, format provisioner.ACMEAttestationFormat) bool {
	if m.MisAttFormatEnabled != nil {
		return m.MisAttFormatEnabled(ctx, format)
	}
	return m.Merr == nil
}

func (m *MockProvisioner) GetAttestationRoots() (*x509.CertPool, bool) {
	if m.MgetAttestationRoots != nil {
		return m.MgetAttestationRoots()
	}
	return m.Mret1.(*x509.CertPool), m.Mret1 != nil
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
