package est

import (
	"crypto/x509"
	"errors"
)

var (
	ErrAuthMethodDisabled      = errors.New("est authentication method disabled")
	ErrAuthMethodNotFound      = errors.New("no valid est authentication method found")
	ErrAuthMethodMisconfigured = errors.New("est authentication method misconfigured")
	ErrAuthDenied              = errors.New("est authentication denied")
)

type AuthMode string

type HTTPAuth struct{}

type EnrollmentIdentity string

type Operation string

type CSRAttributes struct{}

type PoPMode string

type Authentication struct {
	// Mode is "any" (default) or "all", requiring every enabled
	// method to succeed.
	Mode AuthMode `json:"mode,omitempty"`

	// ClientCertificate authenticates via the TLS client certificate
	// (RFC 7030 3.3.2).
	ClientCertificate *ClientCertificateAuth `json:"clientCertificate,omitempty"`

	// HTTP authenticates via HTTP Basic or Digest (RFC 7030 3.2.3).
	HTTP *HTTPAuth `json:"http,omitempty"`
}

type ClientCertificateAuth struct {
	// Roots is a PEM bundle of external trust anchors for initial
	// enrollment with an existing certificate (RFC 7030 2.2.1).
	Roots []byte `json:"roots,omitempty"`

	// AllowOwnCertificates accepts certificates issued by this CA,
	// required for re-enrollment (RFC 7030 4.2.2). Scope with
	// Provisioners; otherwise every leaf this CA has issued becomes
	// an EST enrollment credential.
	AllowOwnCertificates bool     `json:"allowOwnCertificates,omitempty"`
	Provisioners         []string `json:"provisioners,omitempty"`

	// Forwarded reads the client certificate from a header set by a
	// TLS-terminating proxy. Incompatible with ProofOfPossession.
	Forwarded *ForwardedClientCertificate `json:"forwarded,omitempty"`

	// EnrollmentIdentity is "unrestricted" (default) or "match",
	// requiring the CSR subject and SANs to equal the authenticating
	// certificate's. Always enforced for simplereenroll (4.2.2).
	EnrollmentIdentity EnrollmentIdentity `json:"enrollmentIdentity,omitempty"`
}

type ForwardedClientCertificate struct {
	Header         string   `json:"header"`
	Format         string   `json:"format,omitempty"`         // pem | der | url-encoded-pem | xfcc
	TrustedProxies []string `json:"trustedProxies,omitempty"` // CIDRs
}

type CACerts struct {
	ExcludeRoot         bool `json:"excludeRoot,omitempty"`
	ExcludeIntermediate bool `json:"excludeIntermediate,omitempty"`
	// Additional is a PEM bundle appended to /cacerts, e.g. Root CA
	// Key Update certificates (RFC 7030 4.1.3).
	Additional []byte `json:"additional,omitempty"`
}

// AuthRequest contains authentication material extracted from the request.
type AuthRequest struct {
	CSR                    *x509.CertificateRequest
	ClientCertificate      *x509.Certificate
	ClientCertificateChain []*x509.Certificate
	CARoots                []*x509.Certificate
	CAIntermediates        []*x509.Certificate
	AuthenticationHeader   string
	BasicAuthUsername      string
	BasicAuthPassword      string
	BearerToken            string
}

// HasBasicAuth reports whether any basic auth data is present.
func (r *AuthRequest) HasBasicAuth() bool {
	return r.BasicAuthUsername != "" || r.BasicAuthPassword != ""
}
