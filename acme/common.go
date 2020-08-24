package acme

import (
	"context"
	"crypto/x509"
	"net/url"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/provisioner"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/randutil"
)

// Provisioner is an interface that implements a subset of the provisioner.Interface --
// only those methods required by the ACME api/authority.
type Provisioner interface {
	AuthorizeSign(ctx context.Context, token string) ([]provisioner.SignOption, error)
	GetName() string
	DefaultTLSCertDuration() time.Duration
	GetOptions() *provisioner.Options
}

// MockProvisioner for testing
type MockProvisioner struct {
	Mret1                   interface{}
	Merr                    error
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

func (m *MockProvisioner) GetOptions() *provisioner.Options {
	if m.MgetOptions != nil {
		return m.MgetOptions()
	}
	return m.Mret1.(*provisioner.Options)
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
		return nil, AccountDoesNotExistErr(nil)
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
		return nil, ServerInternalErr(errors.Errorf("jwk expected in request context"))
	}
	return val, nil
}

// JwsFromContext searches the context for a JWS. Returns the JWS or an error.
func JwsFromContext(ctx context.Context) (*jose.JSONWebSignature, error) {
	val, ok := ctx.Value(JwsContextKey).(*jose.JSONWebSignature)
	if !ok || val == nil {
		return nil, ServerInternalErr(errors.Errorf("jws expected in request context"))
	}
	return val, nil
}

// ProvisionerFromContext searches the context for a provisioner. Returns the
// provisioner or an error.
func ProvisionerFromContext(ctx context.Context) (Provisioner, error) {
	val := ctx.Value(ProvisionerContextKey)
	if val == nil {
		return nil, ServerInternalErr(errors.Errorf("provisioner expected in request context"))
	}
	pval, ok := val.(Provisioner)
	if !ok || pval == nil {
		return nil, ServerInternalErr(errors.Errorf("provisioner in context is not an ACME provisioner"))
	}
	return pval, nil
}

// SignAuthority is the interface implemented by a CA authority.
type SignAuthority interface {
	Sign(cr *x509.CertificateRequest, opts provisioner.SignOptions, signOpts ...provisioner.SignOption) ([]*x509.Certificate, error)
	LoadProvisionerByID(string) (provisioner.Interface, error)
}

// Identifier encodes the type that an order pertains to.
type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

var (
	// StatusValid -- valid
	StatusValid = "valid"
	// StatusInvalid -- invalid
	StatusInvalid = "invalid"
	// StatusPending -- pending; e.g. an Order that is not ready to be finalized.
	StatusPending = "pending"
	// StatusDeactivated -- deactivated; e.g. for an Account that is not longer valid.
	StatusDeactivated = "deactivated"
	// StatusReady -- ready; e.g. for an Order that is ready to be finalized.
	StatusReady = "ready"
	//statusExpired     = "expired"
	//statusActive      = "active"
	//statusProcessing  = "processing"
)

var idLen = 32

func randID() (val string, err error) {
	val, err = randutil.Alphanumeric(idLen)
	if err != nil {
		return "", ServerInternalErr(errors.Wrap(err, "error generating random alphanumeric ID"))
	}
	return val, nil
}

// Clock that returns time in UTC rounded to seconds.
type Clock int

// Now returns the UTC time rounded to seconds.
func (c *Clock) Now() time.Time {
	return time.Now().UTC().Round(time.Second)
}

var clock = new(Clock)
