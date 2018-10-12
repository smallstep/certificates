package api

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"github.com/pkg/errors"
	"github.com/smallstep/ca-component/provisioner"
	"github.com/smallstep/cli/crypto/tlsutil"
	"github.com/smallstep/cli/crypto/x509util"
	"github.com/smallstep/cli/jose"
)

// Minimum and maximum validity of an end-entity (not root or intermediate) certificate.
// They will be overwritten with the values configured in the authority
var (
	minCertDuration = 5 * time.Minute
	maxCertDuration = 24 * time.Hour
)

// Claim interface is implemented by types used to validate specific claims in a
// certificate request.
// TODO(mariano): Rename?
type Claim interface {
	Valid(cr *x509.CertificateRequest) error
}

// SignOptions contains the options that can be passed to the Authority.Sign
// method.
type SignOptions struct {
	NotAfter  time.Time `json:"notAfter"`
	NotBefore time.Time `json:"notBefore"`
}

// Authority is the interface implemented by a CA authority.
type Authority interface {
	Authorize(ott string) ([]Claim, error)
	GetTLSOptions() *tlsutil.TLSOptions
	GetMinDuration() time.Duration
	GetMaxDuration() time.Duration
	Root(shasum string) (*x509.Certificate, error)
	Sign(cr *x509.CertificateRequest, opts SignOptions, claims ...Claim) (*x509.Certificate, *x509.Certificate, error)
	Renew(cert *x509.Certificate) (*x509.Certificate, *x509.Certificate, error)
	GetProvisioners() ([]*provisioner.Provisioner, error)
	GetEncryptedKey(kid string) (string, error)
}

// Certificate wraps a *x509.Certificate and adds the json.Marshaler interface.
type Certificate struct {
	*x509.Certificate
}

// NewCertificate is a helper method that returns a Certificate from a
// *x509.Certificate.
func NewCertificate(cr *x509.Certificate) Certificate {
	return Certificate{
		Certificate: cr,
	}
}

// MarshalJSON implements the json.Marshaler interface. The certificate is
// quoted string using the PEM encoding.
func (c Certificate) MarshalJSON() ([]byte, error) {
	if c.Certificate == nil {
		return []byte("null"), nil
	}
	block := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.Raw,
	})
	return json.Marshal(string(block))
}

// UnmarshalJSON implements the json.Unmarshaler interface. The certificate is
// expected to be a quoted string using the PEM encoding.
func (c *Certificate) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return errors.Wrap(err, "error decoding certificate")
	}
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return errors.New("error decoding certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.Wrap(err, "error decoding certificate")
	}
	c.Certificate = cert
	return nil
}

// CertificateRequest wraps a *x509.CertificateRequest and adds the
// json.Unmarshaler interface.
type CertificateRequest struct {
	*x509.CertificateRequest
}

// NewCertificateRequest is a helper method that returns a CertificateRequest
// from a *x509.CertificateRequest.
func NewCertificateRequest(cr *x509.CertificateRequest) CertificateRequest {
	return CertificateRequest{
		CertificateRequest: cr,
	}
}

// MarshalJSON implements the json.Marshaler interface. The certificate request
// is a quoted string using the PEM encoding.
func (c CertificateRequest) MarshalJSON() ([]byte, error) {
	if c.CertificateRequest == nil {
		return []byte("null"), nil
	}
	block := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: c.Raw,
	})
	return json.Marshal(string(block))
}

// UnmarshalJSON implements the json.Unmarshaler interface. The certificate
// request is expected to be a quoted string using the PEM encoding.
func (c *CertificateRequest) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return errors.Wrap(err, "error decoding csr")
	}
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return errors.New("error decoding csr")
	}
	cr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return errors.Wrap(err, "error decoding csr")
	}
	c.CertificateRequest = cr
	return nil
}

// Router defines a common router interface.
type Router interface {
	// MethodFunc adds routes for `pattern` that matches
	// the `method` HTTP method.
	MethodFunc(method, pattern string, h http.HandlerFunc)
}

// RouterHandler is the interface that a HTTP handler that manages multiple
// endpoints will implement.
type RouterHandler interface {
	Route(r Router)
}

// HealthResponse is the response object that returns the health of the server.
type HealthResponse struct {
	Status string `json:"status"`
}

// RootResponse is the response object that returns the PEM of a root certificate.
type RootResponse struct {
	RootPEM Certificate `json:"ca"`
}

// SignRequest is the request body for a certificate signature request.
type SignRequest struct {
	CsrPEM    CertificateRequest `json:"csr"`
	OTT       string             `json:"ott"`
	NotAfter  time.Time          `json:"notAfter"`
	NotBefore time.Time          `json:"notBefore"`
}

// ProvisionersResponse is the response object that returns the list of
// provisioners.
type ProvisionersResponse struct {
	Provisioners []*provisioner.Provisioner `json:"provisioners"`
}

// JWKSetByIssuerResponse is the response object that returns the map of
// provisioners.
type JWKSetByIssuerResponse struct {
	Map map[string]*jose.JSONWebKeySet `json:"map"`
}

// ProvisionerKeyResponse is the response object that returns the encryptoed key
// of a provisioner.
type ProvisionerKeyResponse struct {
	Key string `json:"key"`
}

// Validate checks the fields of the SignRequest and returns nil if they are ok
// or an error if something is wrong.
func (s *SignRequest) Validate() error {
	if s.CsrPEM.CertificateRequest == nil {
		return BadRequest(errors.New("missing csr"))
	}
	if err := s.CsrPEM.CertificateRequest.CheckSignature(); err != nil {
		return BadRequest(errors.Wrap(err, "invalid csr"))
	}
	if s.OTT == "" {
		return BadRequest(errors.New("missing ott"))
	}

	now := time.Now()
	if s.NotBefore.IsZero() {
		s.NotBefore = now
	}
	if s.NotAfter.IsZero() {
		s.NotAfter = now.Add(x509util.DefaultCertValidity)
	}

	if s.NotAfter.Before(now) {
		return BadRequest(errors.New("notAfter < now"))
	}
	if s.NotAfter.Before(s.NotBefore) {
		return BadRequest(errors.New("notAfter < notBefore"))
	}
	requestedDuration := s.NotAfter.Sub(s.NotBefore)
	if requestedDuration < minCertDuration {
		return BadRequest(errors.New("requested certificate validity duration is too short"))
	}
	if requestedDuration > maxCertDuration {
		return BadRequest(errors.New("requested certificate validity duration is too long"))
	}
	return nil
}

// SignResponse is the response object of the certificate signature request.
type SignResponse struct {
	ServerPEM  Certificate          `json:"crt"`
	CaPEM      Certificate          `json:"ca"`
	TLSOptions *tlsutil.TLSOptions  `json:"tlsOptions,omitempty"`
	TLS        *tls.ConnectionState `json:"-"`
}

// caHandler is the type used to implement the different CA HTTP endpoints.
type caHandler struct {
	Authority Authority
}

// New creates a new RouterHandler with the CA endpoints.
func New(authority Authority) RouterHandler {
	minCertDuration = authority.GetMinDuration()
	maxCertDuration = authority.GetMaxDuration()
	return &caHandler{
		Authority: authority,
	}
}

func (h *caHandler) Route(r Router) {
	r.MethodFunc("GET", "/health", h.Health)
	r.MethodFunc("GET", "/root/{sha}", h.Root)
	r.MethodFunc("POST", "/sign", h.Sign)
	r.MethodFunc("POST", "/renew", h.Renew)
	r.MethodFunc("GET", "/provisioners", h.Provisioners)
	r.MethodFunc("GET", "/provisioners/{kid}/encrypted-key", h.ProvisionerKey)
	r.MethodFunc("GET", "/provisioners/jwk-set-by-issuer", h.JWKSetByIssuer)
}

// Health is an HTTP handler that returns the status of the server.
func (h *caHandler) Health(w http.ResponseWriter, r *http.Request) {
	JSON(w, HealthResponse{Status: "ok"})
}

// Root is an HTTP handler that using the SHA256 from the URL, returns the root
// certificate for the given SHA256.
func (h *caHandler) Root(w http.ResponseWriter, r *http.Request) {
	sha := chi.URLParam(r, "sha")
	sum := strings.ToLower(strings.Replace(sha, "-", "", -1))
	// Load root certificate with the
	cert, err := h.Authority.Root(sum)
	if err != nil {
		WriteError(w, NotFound(errors.Wrapf(err, "%s was not found", r.RequestURI)))
		return
	}

	JSON(w, &RootResponse{RootPEM: Certificate{cert}})
}

// Sign is an HTTP handler that reads a certificate request and an
// one-time-token (ott) from the body and creates a new certificate with the
// information in the certificate request.
func (h *caHandler) Sign(w http.ResponseWriter, r *http.Request) {
	var body SignRequest
	if err := ReadJSON(r.Body, &body); err != nil {
		WriteError(w, BadRequest(errors.Wrap(err, "error reading request body")))
		return
	}
	if err := body.Validate(); err != nil {
		WriteError(w, err)
		return
	}

	claims, err := h.Authority.Authorize(body.OTT)
	if err != nil {
		WriteError(w, Unauthorized(err))
		return
	}

	opts := SignOptions{
		NotBefore: body.NotBefore,
		NotAfter:  body.NotAfter,
	}

	cert, root, err := h.Authority.Sign(body.CsrPEM.CertificateRequest, opts, claims...)
	if err != nil {
		WriteError(w, Forbidden(err))
		return
	}

	w.WriteHeader(http.StatusCreated)
	JSON(w, &SignResponse{
		ServerPEM:  Certificate{cert},
		CaPEM:      Certificate{root},
		TLSOptions: h.Authority.GetTLSOptions(),
	})
}

// Renew uses the information of certificate in the TLS connection to create a
// new one.
func (h *caHandler) Renew(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		WriteError(w, BadRequest(errors.New("missing peer certificate")))
		return
	}

	cert, root, err := h.Authority.Renew(r.TLS.PeerCertificates[0])
	if err != nil {
		WriteError(w, Forbidden(err))
		return
	}

	w.WriteHeader(http.StatusCreated)
	JSON(w, &SignResponse{
		ServerPEM:  Certificate{cert},
		CaPEM:      Certificate{root},
		TLSOptions: h.Authority.GetTLSOptions(),
	})
}

// Provisioners returns the list of provisioners configured in the authority.
func (h *caHandler) Provisioners(w http.ResponseWriter, r *http.Request) {
	p, err := h.Authority.GetProvisioners()
	if err != nil {
		WriteError(w, InternalServerError(err))
		return
	}
	JSON(w, &ProvisionersResponse{p})
}

// ProvisionerKey returns the encrypted key of a provisioner by it's key id.
func (h *caHandler) ProvisionerKey(w http.ResponseWriter, r *http.Request) {
	kid := chi.URLParam(r, "kid")
	key, err := h.Authority.GetEncryptedKey(kid)
	if err != nil {
		WriteError(w, NotFound(err))
		return
	}
	JSON(w, &ProvisionerKeyResponse{key})
}

func (h *caHandler) JWKSetByIssuer(w http.ResponseWriter, r *http.Request) {
	m := map[string]*jose.JSONWebKeySet{}
	ps, err := h.Authority.GetProvisioners()
	if err != nil {
		WriteError(w, InternalServerError(err))
		return
	}
	for _, p := range ps {
		ks, found := m[p.Issuer]
		if found {
			ks.Keys = append(ks.Keys, *p.Key)
		} else {
			ks = new(jose.JSONWebKeySet)
			ks.Keys = []jose.JSONWebKey{*p.Key}
			m[p.Issuer] = ks
		}
	}
	JSON(w, &JWKSetByIssuerResponse{m})
}
