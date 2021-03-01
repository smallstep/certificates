package acme

import (
	"context"
	"crypto/x509"
	"net/url"
	"time"

	"github.com/smallstep/certificates/authority/provisioner"
	"go.step.sm/crypto/jose"
)

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

// ContextKey is the key type for storing and searching for ACME request
// essentials in the context of a request.
type ContextKey string

const (
	// AccContextKey account key
	AccContextKey = ContextKey("acc")
	// BaseURLContextKey baseURL key
	BaseURLContextKey = ContextKey("baseURL")
	// JwsContextKey jws key
	JwsContextKey = ContextKey("jws")
	// JwkContextKey jwk key
	JwkContextKey = ContextKey("jwk")
	// PayloadContextKey payload key
	PayloadContextKey = ContextKey("payload")
	// ProvisionerContextKey provisioner key
	ProvisionerContextKey = ContextKey("provisioner")
)

// AccountFromContext searches the context for an ACME account. Returns the
// account or an error.
func AccountFromContext(ctx context.Context) (*Account, error) {
	val, ok := ctx.Value(AccContextKey).(*Account)
	if !ok || val == nil {
		return nil, NewError(ErrorServerInternalType, "account not in context")
	}
	return val, nil
}

// BaseURLFromContext returns the baseURL if one is stored in the context.
func BaseURLFromContext(ctx context.Context) *url.URL {
	val, ok := ctx.Value(BaseURLContextKey).(*url.URL)
	if !ok || val == nil {
		return nil
	}
	return val
}

// JwkFromContext searches the context for a JWK. Returns the JWK or an error.
func JwkFromContext(ctx context.Context) (*jose.JSONWebKey, error) {
	val, ok := ctx.Value(JwkContextKey).(*jose.JSONWebKey)
	if !ok || val == nil {
		return nil, NewError(ErrorServerInternalType, "jwk expected in request context")
	}
	return val, nil
}

// JwsFromContext searches the context for a JWS. Returns the JWS or an error.
func JwsFromContext(ctx context.Context) (*jose.JSONWebSignature, error) {
	val, ok := ctx.Value(JwsContextKey).(*jose.JSONWebSignature)
	if !ok || val == nil {
		return nil, NewError(ErrorServerInternalType, "jws expected in request context")
	}
	return val, nil
}

// ProvisionerFromContext searches the context for a provisioner. Returns the
// provisioner or an error.
func ProvisionerFromContext(ctx context.Context) (Provisioner, error) {
	val := ctx.Value(ProvisionerContextKey)
	if val == nil {
		return nil, NewError(ErrorServerInternalType, "provisioner expected in request context")
	}
	pval, ok := val.(Provisioner)
	if !ok || pval == nil {
		return nil, NewError(ErrorServerInternalType, "provisioner in context is not an ACME provisioner")
	}
	return pval, nil
}

// SignAuthority is the interface implemented by a CA authority.
type SignAuthority interface {
	Sign(cr *x509.CertificateRequest, opts provisioner.SignOptions, signOpts ...provisioner.SignOption) ([]*x509.Certificate, error)
	LoadProvisionerByID(string) (provisioner.Interface, error)
}

// Clock that returns time in UTC rounded to seconds.
type Clock int

// Now returns the UTC time rounded to seconds.
func (c *Clock) Now() time.Time {
	return time.Now().UTC().Round(time.Second)
}

var clock = new(Clock)
