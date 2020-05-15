package acme

import (
	"context"
	"crypto/x509"
	"net/url"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/cli/crypto/randutil"
	"github.com/smallstep/cli/jose"
)

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
func ProvisionerFromContext(ctx context.Context) (provisioner.Interface, error) {
	val, ok := ctx.Value(ProvisionerContextKey).(provisioner.Interface)
	if !ok || val == nil {
		return nil, ServerInternalErr(errors.Errorf("provisioner expected in request context"))
	}
	return val, nil
}

// SignAuthority is the interface implemented by a CA authority.
type SignAuthority interface {
	Sign(cr *x509.CertificateRequest, opts provisioner.Options, signOpts ...provisioner.SignOption) ([]*x509.Certificate, error)
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
