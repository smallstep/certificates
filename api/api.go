package api

import (
	"context"
	"crypto"
	"crypto/dsa" //nolint:staticcheck // support legacy algorithms
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"github.com/pkg/errors"

	"github.com/smallstep/certificates/api/log"
	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/errs"
	"github.com/smallstep/certificates/logging"
)

// Authority is the interface implemented by a CA authority.
type Authority interface {
	SSHAuthority
	// context specifies the Authorize[Sign|Revoke|etc.] method.
	Authorize(ctx context.Context, ott string) ([]provisioner.SignOption, error)
	AuthorizeRenewToken(ctx context.Context, ott string) (*x509.Certificate, error)
	GetTLSOptions() *config.TLSOptions
	Root(shasum string) (*x509.Certificate, error)
	Sign(cr *x509.CertificateRequest, opts provisioner.SignOptions, signOpts ...provisioner.SignOption) ([]*x509.Certificate, error)
	Renew(peer *x509.Certificate) ([]*x509.Certificate, error)
	RenewContext(ctx context.Context, peer *x509.Certificate, pk crypto.PublicKey) ([]*x509.Certificate, error)
	Rekey(peer *x509.Certificate, pk crypto.PublicKey) ([]*x509.Certificate, error)
	LoadProvisionerByCertificate(*x509.Certificate) (provisioner.Interface, error)
	LoadProvisionerByName(string) (provisioner.Interface, error)
	GetProvisioners(cursor string, limit int) (provisioner.List, string, error)
	Revoke(context.Context, *authority.RevokeOptions) error
	GetEncryptedKey(kid string) (string, error)
	GetRoots() ([]*x509.Certificate, error)
	GetFederation() ([]*x509.Certificate, error)
	Version() authority.Version
	GetCertificateRevocationList() ([]byte, error)
}

// mustAuthority will be replaced on unit tests.
var mustAuthority = func(ctx context.Context) Authority {
	return authority.MustFromContext(ctx)
}

// TimeDuration is an alias of provisioner.TimeDuration
type TimeDuration = provisioner.TimeDuration

// NewTimeDuration returns a TimeDuration with the defined time.
func NewTimeDuration(t time.Time) TimeDuration {
	return provisioner.NewTimeDuration(t)
}

// ParseTimeDuration returns a new TimeDuration parsing the RFC 3339 time or
// time.Duration string.
func ParseTimeDuration(s string) (TimeDuration, error) {
	return provisioner.ParseTimeDuration(s)
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

// reset sets the inner x509.CertificateRequest to nil
func (c *Certificate) reset() {
	if c != nil {
		c.Certificate = nil
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

	// Make sure the inner x509.Certificate is nil
	if s == "null" || s == "" {
		c.reset()
		return nil
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

// reset sets the inner x509.CertificateRequest to nil
func (c *CertificateRequest) reset() {
	if c != nil {
		c.CertificateRequest = nil
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

	// Make sure the inner x509.CertificateRequest is nil
	if s == "null" || s == "" {
		c.reset()
		return nil
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

// VersionResponse is the response object that returns the version of the
// server.
type VersionResponse struct {
	Version                     string `json:"version"`
	RequireClientAuthentication bool   `json:"requireClientAuthentication,omitempty"`
}

// HealthResponse is the response object that returns the health of the server.
type HealthResponse struct {
	Status string `json:"status"`
}

// RootResponse is the response object that returns the PEM of a root certificate.
type RootResponse struct {
	RootPEM Certificate `json:"ca"`
}

// ProvisionersResponse is the response object that returns the list of
// provisioners.
type ProvisionersResponse struct {
	Provisioners provisioner.List `json:"provisioners"`
	NextCursor   string           `json:"nextCursor"`
}

// ProvisionerKeyResponse is the response object that returns the encrypted key
// of a provisioner.
type ProvisionerKeyResponse struct {
	Key string `json:"key"`
}

// RootsResponse is the response object of the roots request.
type RootsResponse struct {
	Certificates []Certificate `json:"crts"`
}

// FederationResponse is the response object of the federation request.
type FederationResponse struct {
	Certificates []Certificate `json:"crts"`
}

// caHandler is the type used to implement the different CA HTTP endpoints.
type caHandler struct {
	Authority Authority
}

// Route configures the http request router.
func (h *caHandler) Route(r Router) {
	Route(r)
}

// New creates a new RouterHandler with the CA endpoints.
//
// Deprecated: Use api.Route(r Router)
func New(auth Authority) RouterHandler {
	return &caHandler{}
}

func Route(r Router) {
	r.MethodFunc("GET", "/version", Version)
	r.MethodFunc("GET", "/health", Health)
	r.MethodFunc("GET", "/root/{sha}", Root)
	r.MethodFunc("POST", "/sign", Sign)
	r.MethodFunc("POST", "/renew", Renew)
	r.MethodFunc("POST", "/rekey", Rekey)
	r.MethodFunc("POST", "/revoke", Revoke)
	r.MethodFunc("GET", "/crl", CRL)
	r.MethodFunc("GET", "/provisioners", Provisioners)
	r.MethodFunc("GET", "/provisioners/{kid}/encrypted-key", ProvisionerKey)
	r.MethodFunc("GET", "/roots", Roots)
	r.MethodFunc("GET", "/roots.pem", RootsPEM)
	r.MethodFunc("GET", "/federation", Federation)
	// SSH CA
	r.MethodFunc("POST", "/ssh/sign", SSHSign)
	r.MethodFunc("POST", "/ssh/renew", SSHRenew)
	r.MethodFunc("POST", "/ssh/revoke", SSHRevoke)
	r.MethodFunc("POST", "/ssh/rekey", SSHRekey)
	r.MethodFunc("GET", "/ssh/roots", SSHRoots)
	r.MethodFunc("GET", "/ssh/federation", SSHFederation)
	r.MethodFunc("POST", "/ssh/config", SSHConfig)
	r.MethodFunc("POST", "/ssh/config/{type}", SSHConfig)
	r.MethodFunc("POST", "/ssh/check-host", SSHCheckHost)
	r.MethodFunc("GET", "/ssh/hosts", SSHGetHosts)
	r.MethodFunc("POST", "/ssh/bastion", SSHBastion)

	// For compatibility with old code:
	r.MethodFunc("POST", "/re-sign", Renew)
	r.MethodFunc("POST", "/sign-ssh", SSHSign)
	r.MethodFunc("GET", "/ssh/get-hosts", SSHGetHosts)
}

// Version is an HTTP handler that returns the version of the server.
func Version(w http.ResponseWriter, r *http.Request) {
	v := mustAuthority(r.Context()).Version()
	render.JSON(w, VersionResponse{
		Version:                     v.Version,
		RequireClientAuthentication: v.RequireClientAuthentication,
	})
}

// Health is an HTTP handler that returns the status of the server.
func Health(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, HealthResponse{Status: "ok"})
}

// Root is an HTTP handler that using the SHA256 from the URL, returns the root
// certificate for the given SHA256.
func Root(w http.ResponseWriter, r *http.Request) {
	sha := chi.URLParam(r, "sha")
	sum := strings.ToLower(strings.ReplaceAll(sha, "-", ""))
	// Load root certificate with the
	cert, err := mustAuthority(r.Context()).Root(sum)
	if err != nil {
		render.Error(w, errs.Wrapf(http.StatusNotFound, err, "%s was not found", r.RequestURI))
		return
	}

	render.JSON(w, &RootResponse{RootPEM: Certificate{cert}})
}

func certChainToPEM(certChain []*x509.Certificate) []Certificate {
	certChainPEM := make([]Certificate, 0, len(certChain))
	for _, c := range certChain {
		certChainPEM = append(certChainPEM, Certificate{c})
	}
	return certChainPEM
}

// Provisioners returns the list of provisioners configured in the authority.
func Provisioners(w http.ResponseWriter, r *http.Request) {
	cursor, limit, err := ParseCursor(r)
	if err != nil {
		render.Error(w, err)
		return
	}

	p, next, err := mustAuthority(r.Context()).GetProvisioners(cursor, limit)
	if err != nil {
		render.Error(w, errs.InternalServerErr(err))
		return
	}

	render.JSON(w, &ProvisionersResponse{
		Provisioners: p,
		NextCursor:   next,
	})
}

// ProvisionerKey returns the encrypted key of a provisioner by it's key id.
func ProvisionerKey(w http.ResponseWriter, r *http.Request) {
	kid := chi.URLParam(r, "kid")
	key, err := mustAuthority(r.Context()).GetEncryptedKey(kid)
	if err != nil {
		render.Error(w, errs.NotFoundErr(err))
		return
	}

	render.JSON(w, &ProvisionerKeyResponse{key})
}

// Roots returns all the root certificates for the CA.
func Roots(w http.ResponseWriter, r *http.Request) {
	roots, err := mustAuthority(r.Context()).GetRoots()
	if err != nil {
		render.Error(w, errs.ForbiddenErr(err, "error getting roots"))
		return
	}

	certs := make([]Certificate, len(roots))
	for i := range roots {
		certs[i] = Certificate{roots[i]}
	}

	render.JSONStatus(w, &RootsResponse{
		Certificates: certs,
	}, http.StatusCreated)
}

// RootsPEM returns all the root certificates for the CA in PEM format.
func RootsPEM(w http.ResponseWriter, r *http.Request) {
	roots, err := mustAuthority(r.Context()).GetRoots()
	if err != nil {
		render.Error(w, errs.InternalServerErr(err))
		return
	}

	w.Header().Set("Content-Type", "application/x-pem-file")

	for _, root := range roots {
		block := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: root.Raw,
		})

		if _, err := w.Write(block); err != nil {
			log.Error(w, err)
			return
		}
	}
}

// Federation returns all the public certificates in the federation.
func Federation(w http.ResponseWriter, r *http.Request) {
	federated, err := mustAuthority(r.Context()).GetFederation()
	if err != nil {
		render.Error(w, errs.ForbiddenErr(err, "error getting federated roots"))
		return
	}

	certs := make([]Certificate, len(federated))
	for i := range federated {
		certs[i] = Certificate{federated[i]}
	}

	render.JSONStatus(w, &FederationResponse{
		Certificates: certs,
	}, http.StatusCreated)
}

var oidStepProvisioner = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64, 1}

type stepProvisioner struct {
	Type         int
	Name         []byte
	CredentialID []byte
}

func logOtt(w http.ResponseWriter, token string) {
	if rl, ok := w.(logging.ResponseLogger); ok {
		rl.WithFields(map[string]interface{}{
			"ott": token,
		})
	}
}

// LogCertificate add certificate fields to the log message.
func LogCertificate(w http.ResponseWriter, cert *x509.Certificate) {
	if rl, ok := w.(logging.ResponseLogger); ok {
		m := map[string]interface{}{
			"serial":      cert.SerialNumber.String(),
			"subject":     cert.Subject.CommonName,
			"issuer":      cert.Issuer.CommonName,
			"valid-from":  cert.NotBefore.Format(time.RFC3339),
			"valid-to":    cert.NotAfter.Format(time.RFC3339),
			"public-key":  fmtPublicKey(cert),
			"certificate": base64.StdEncoding.EncodeToString(cert.Raw),
		}
		for _, ext := range cert.Extensions {
			if !ext.Id.Equal(oidStepProvisioner) {
				continue
			}
			val := &stepProvisioner{}
			rest, err := asn1.Unmarshal(ext.Value, val)
			if err != nil || len(rest) > 0 {
				break
			}
			if len(val.CredentialID) > 0 {
				m["provisioner"] = fmt.Sprintf("%s (%s)", val.Name, val.CredentialID)
			} else {
				m["provisioner"] = string(val.Name)
			}
			break
		}
		rl.WithFields(m)
	}
}

// ParseCursor parses the cursor and limit from the request query params.
func ParseCursor(r *http.Request) (cursor string, limit int, err error) {
	q := r.URL.Query()
	cursor = q.Get("cursor")
	if v := q.Get("limit"); len(v) > 0 {
		limit, err = strconv.Atoi(v)
		if err != nil {
			return "", 0, errs.BadRequestErr(err, "limit '%s' is not an integer", v)
		}
	}
	return
}

func fmtPublicKey(cert *x509.Certificate) string {
	var params string
	switch pk := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		params = pk.Curve.Params().Name
	case *rsa.PublicKey:
		params = strconv.Itoa(pk.Size() * 8)
	case ed25519.PublicKey:
		return cert.PublicKeyAlgorithm.String()
	case *dsa.PublicKey:
		params = strconv.Itoa(pk.Q.BitLen() * 8)
	default:
		params = "unknown"
	}
	return fmt.Sprintf("%s %s", cert.PublicKeyAlgorithm, params)
}
