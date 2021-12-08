package api

import (
	"context"
	"crypto"
	"crypto/dsa" //nolint
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
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/errs"
	"github.com/smallstep/certificates/logging"
	"github.com/smallstep/certificates/templates"
	"go.step.sm/linkedca"
	"golang.org/x/crypto/ssh"
)

// Authority is the interface implemented by a CA authority.
type Authority interface {
	SSHAuthority
	// context specifies the Authorize[Sign|Revoke|etc.] method.
	Authorize(ctx context.Context, ott string) ([]provisioner.SignOption, error)
	AuthorizeSign(ott string) ([]provisioner.SignOption, error)
	GetTLSOptions() *config.TLSOptions
	Root(shasum string) (*x509.Certificate, error)
	Sign(cr *x509.CertificateRequest, opts provisioner.SignOptions, signOpts ...provisioner.SignOption) ([]*x509.Certificate, error)
	Renew(peer *x509.Certificate) ([]*x509.Certificate, error)
	Rekey(peer *x509.Certificate, pk crypto.PublicKey) ([]*x509.Certificate, error)
	LoadProvisionerByCertificate(*x509.Certificate) (provisioner.Interface, error)
	LoadProvisionerByName(string) (provisioner.Interface, error)
	GetProvisioners(cursor string, limit int) (provisioner.List, string, error)
	Revoke(context.Context, *authority.RevokeOptions) error
	GetEncryptedKey(kid string) (string, error)
	GetRoots() (federation []*x509.Certificate, err error)
	GetFederation() ([]*x509.Certificate, error)
	Version() authority.Version
}

type LinkedAuthority interface { // TODO(hs): name is not great; it is related to LinkedCA, though
	Authority
	IsAdminAPIEnabled() bool
	LoadAdminByID(id string) (*linkedca.Admin, bool)
	GetAdmins(cursor string, limit int) ([]*linkedca.Admin, string, error)
	StoreAdmin(ctx context.Context, adm *linkedca.Admin, prov provisioner.Interface) error
	UpdateAdmin(ctx context.Context, id string, nu *linkedca.Admin) (*linkedca.Admin, error)
	RemoveAdmin(ctx context.Context, id string) error
	AuthorizeAdminToken(r *http.Request, token string) (*linkedca.Admin, error)
	StoreProvisioner(ctx context.Context, prov *linkedca.Provisioner) error
	LoadProvisionerByID(id string) (provisioner.Interface, error)
	UpdateProvisioner(ctx context.Context, nu *linkedca.Provisioner) error
	RemoveProvisioner(ctx context.Context, id string) error
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

// New creates a new RouterHandler with the CA endpoints.
func New(auth Authority) RouterHandler {
	return &caHandler{
		Authority: auth,
	}
}

func (h *caHandler) Route(r Router) {
	r.MethodFunc("GET", "/version", h.Version)
	r.MethodFunc("GET", "/health", h.Health)
	r.MethodFunc("GET", "/root/{sha}", h.Root)
	r.MethodFunc("POST", "/sign", h.Sign)
	r.MethodFunc("POST", "/renew", h.Renew)
	r.MethodFunc("POST", "/rekey", h.Rekey)
	r.MethodFunc("POST", "/revoke", h.Revoke)
	r.MethodFunc("GET", "/provisioners", h.Provisioners)
	r.MethodFunc("GET", "/provisioners/{kid}/encrypted-key", h.ProvisionerKey)
	r.MethodFunc("GET", "/roots", h.Roots)
	r.MethodFunc("GET", "/federation", h.Federation)
	// SSH CA
	r.MethodFunc("POST", "/ssh/sign", h.SSHSign)
	r.MethodFunc("POST", "/ssh/renew", h.SSHRenew)
	r.MethodFunc("POST", "/ssh/revoke", h.SSHRevoke)
	r.MethodFunc("POST", "/ssh/rekey", h.SSHRekey)
	r.MethodFunc("GET", "/ssh/roots", h.SSHRoots)
	r.MethodFunc("GET", "/ssh/federation", h.SSHFederation)
	r.MethodFunc("POST", "/ssh/config", h.SSHConfig)
	r.MethodFunc("POST", "/ssh/config/{type}", h.SSHConfig)
	r.MethodFunc("POST", "/ssh/check-host", h.SSHCheckHost)
	r.MethodFunc("GET", "/ssh/hosts", h.SSHGetHosts)
	r.MethodFunc("POST", "/ssh/bastion", h.SSHBastion)

	// For compatibility with old code:
	r.MethodFunc("POST", "/re-sign", h.Renew)
	r.MethodFunc("POST", "/sign-ssh", h.SSHSign)
	r.MethodFunc("GET", "/ssh/get-hosts", h.SSHGetHosts)
}

// Version is an HTTP handler that returns the version of the server.
func (h *caHandler) Version(w http.ResponseWriter, r *http.Request) {
	v := h.Authority.Version()
	JSON(w, VersionResponse{
		Version:                     v.Version,
		RequireClientAuthentication: v.RequireClientAuthentication,
	})
}

// Health is an HTTP handler that returns the status of the server.
func (h *caHandler) Health(w http.ResponseWriter, r *http.Request) {
	JSON(w, HealthResponse{Status: "ok"})
}

// Root is an HTTP handler that using the SHA256 from the URL, returns the root
// certificate for the given SHA256.
func (h *caHandler) Root(w http.ResponseWriter, r *http.Request) {
	sha := chi.URLParam(r, "sha")
	sum := strings.ToLower(strings.ReplaceAll(sha, "-", ""))
	// Load root certificate with the
	cert, err := h.Authority.Root(sum)
	if err != nil {
		WriteError(w, errs.Wrapf(http.StatusNotFound, err, "%s was not found", r.RequestURI))
		return
	}

	JSON(w, &RootResponse{RootPEM: Certificate{cert}})
}

func certChainToPEM(certChain []*x509.Certificate) []Certificate {
	certChainPEM := make([]Certificate, 0, len(certChain))
	for _, c := range certChain {
		certChainPEM = append(certChainPEM, Certificate{c})
	}
	return certChainPEM
}

// Provisioners returns the list of provisioners configured in the authority.
func (h *caHandler) Provisioners(w http.ResponseWriter, r *http.Request) {
	cursor, limit, err := ParseCursor(r)
	if err != nil {
		WriteError(w, err)
		return
	}

	p, next, err := h.Authority.GetProvisioners(cursor, limit)
	if err != nil {
		WriteError(w, errs.InternalServerErr(err))
		return
	}
	JSON(w, &ProvisionersResponse{
		Provisioners: p,
		NextCursor:   next,
	})
}

// ProvisionerKey returns the encrypted key of a provisioner by it's key id.
func (h *caHandler) ProvisionerKey(w http.ResponseWriter, r *http.Request) {
	kid := chi.URLParam(r, "kid")
	key, err := h.Authority.GetEncryptedKey(kid)
	if err != nil {
		WriteError(w, errs.NotFoundErr(err))
		return
	}
	JSON(w, &ProvisionerKeyResponse{key})
}

// Roots returns all the root certificates for the CA.
func (h *caHandler) Roots(w http.ResponseWriter, r *http.Request) {
	roots, err := h.Authority.GetRoots()
	if err != nil {
		WriteError(w, errs.ForbiddenErr(err))
		return
	}

	certs := make([]Certificate, len(roots))
	for i := range roots {
		certs[i] = Certificate{roots[i]}
	}

	JSONStatus(w, &RootsResponse{
		Certificates: certs,
	}, http.StatusCreated)
}

// Federation returns all the public certificates in the federation.
func (h *caHandler) Federation(w http.ResponseWriter, r *http.Request) {
	federated, err := h.Authority.GetFederation()
	if err != nil {
		WriteError(w, errs.ForbiddenErr(err))
		return
	}

	certs := make([]Certificate, len(federated))
	for i := range federated {
		certs[i] = Certificate{federated[i]}
	}

	JSONStatus(w, &FederationResponse{
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

type MockAuthority struct {
	ret1, ret2                   interface{}
	err                          error
	authorizeSign                func(ott string) ([]provisioner.SignOption, error)
	getTLSOptions                func() *authority.TLSOptions
	root                         func(shasum string) (*x509.Certificate, error)
	sign                         func(cr *x509.CertificateRequest, opts provisioner.SignOptions, signOpts ...provisioner.SignOption) ([]*x509.Certificate, error)
	renew                        func(cert *x509.Certificate) ([]*x509.Certificate, error)
	rekey                        func(oldCert *x509.Certificate, pk crypto.PublicKey) ([]*x509.Certificate, error)
	loadProvisionerByCertificate func(cert *x509.Certificate) (provisioner.Interface, error)
	MockLoadProvisionerByName    func(name string) (provisioner.Interface, error)
	getProvisioners              func(nextCursor string, limit int) (provisioner.List, string, error)
	revoke                       func(context.Context, *authority.RevokeOptions) error
	getEncryptedKey              func(kid string) (string, error)
	getRoots                     func() ([]*x509.Certificate, error)
	getFederation                func() ([]*x509.Certificate, error)
	signSSH                      func(ctx context.Context, key ssh.PublicKey, opts provisioner.SignSSHOptions, signOpts ...provisioner.SignOption) (*ssh.Certificate, error)
	signSSHAddUser               func(ctx context.Context, key ssh.PublicKey, cert *ssh.Certificate) (*ssh.Certificate, error)
	renewSSH                     func(ctx context.Context, cert *ssh.Certificate) (*ssh.Certificate, error)
	rekeySSH                     func(ctx context.Context, cert *ssh.Certificate, key ssh.PublicKey, signOpts ...provisioner.SignOption) (*ssh.Certificate, error)
	getSSHHosts                  func(ctx context.Context, cert *x509.Certificate) ([]authority.Host, error)
	getSSHRoots                  func(ctx context.Context) (*authority.SSHKeys, error)
	getSSHFederation             func(ctx context.Context) (*authority.SSHKeys, error)
	getSSHConfig                 func(ctx context.Context, typ string, data map[string]string) ([]templates.Output, error)
	checkSSHHost                 func(ctx context.Context, principal, token string) (bool, error)
	getSSHBastion                func(ctx context.Context, user string, hostname string) (*authority.Bastion, error)
	version                      func() authority.Version

	MockRet1, MockRet2      interface{} // TODO: refactor the ret1/ret2 into those two
	MockErr                 error
	MockIsAdminAPIEnabled   func() bool
	MockLoadAdminByID       func(id string) (*linkedca.Admin, bool)
	MockGetAdmins           func(cursor string, limit int) ([]*linkedca.Admin, string, error)
	MockStoreAdmin          func(ctx context.Context, adm *linkedca.Admin, prov provisioner.Interface) error
	MockUpdateAdmin         func(ctx context.Context, id string, nu *linkedca.Admin) (*linkedca.Admin, error)
	MockRemoveAdmin         func(ctx context.Context, id string) error
	MockAuthorizeAdminToken func(r *http.Request, token string) (*linkedca.Admin, error)
	MockStoreProvisioner    func(ctx context.Context, prov *linkedca.Provisioner) error
	MockLoadProvisionerByID func(id string) (provisioner.Interface, error)
	MockUpdateProvisioner   func(ctx context.Context, nu *linkedca.Provisioner) error
	MockRemoveProvisioner   func(ctx context.Context, id string) error
}

// TODO: remove once Authorize is deprecated.
func (m *MockAuthority) Authorize(ctx context.Context, ott string) ([]provisioner.SignOption, error) {
	return m.AuthorizeSign(ott)
}

func (m *MockAuthority) AuthorizeSign(ott string) ([]provisioner.SignOption, error) {
	if m.authorizeSign != nil {
		return m.authorizeSign(ott)
	}
	return m.ret1.([]provisioner.SignOption), m.err
}

func (m *MockAuthority) GetTLSOptions() *authority.TLSOptions {
	if m.getTLSOptions != nil {
		return m.getTLSOptions()
	}
	return m.ret1.(*authority.TLSOptions)
}

func (m *MockAuthority) Root(shasum string) (*x509.Certificate, error) {
	if m.root != nil {
		return m.root(shasum)
	}
	return m.ret1.(*x509.Certificate), m.err
}

func (m *MockAuthority) Sign(cr *x509.CertificateRequest, opts provisioner.SignOptions, signOpts ...provisioner.SignOption) ([]*x509.Certificate, error) {
	if m.sign != nil {
		return m.sign(cr, opts, signOpts...)
	}
	return []*x509.Certificate{m.ret1.(*x509.Certificate), m.ret2.(*x509.Certificate)}, m.err
}

func (m *MockAuthority) Renew(cert *x509.Certificate) ([]*x509.Certificate, error) {
	if m.renew != nil {
		return m.renew(cert)
	}
	return []*x509.Certificate{m.ret1.(*x509.Certificate), m.ret2.(*x509.Certificate)}, m.err
}

func (m *MockAuthority) Rekey(oldcert *x509.Certificate, pk crypto.PublicKey) ([]*x509.Certificate, error) {
	if m.rekey != nil {
		return m.rekey(oldcert, pk)
	}
	return []*x509.Certificate{m.ret1.(*x509.Certificate), m.ret2.(*x509.Certificate)}, m.err
}

func (m *MockAuthority) GetProvisioners(nextCursor string, limit int) (provisioner.List, string, error) {
	if m.getProvisioners != nil {
		return m.getProvisioners(nextCursor, limit)
	}
	return m.ret1.(provisioner.List), m.ret2.(string), m.err
}

func (m *MockAuthority) LoadProvisionerByCertificate(cert *x509.Certificate) (provisioner.Interface, error) {
	if m.loadProvisionerByCertificate != nil {
		return m.loadProvisionerByCertificate(cert)
	}
	return m.ret1.(provisioner.Interface), m.err
}

func (m *MockAuthority) LoadProvisionerByName(name string) (provisioner.Interface, error) {
	if m.MockLoadProvisionerByName != nil {
		return m.MockLoadProvisionerByName(name)
	}
	return m.ret1.(provisioner.Interface), m.err
}

func (m *MockAuthority) Revoke(ctx context.Context, opts *authority.RevokeOptions) error {
	if m.revoke != nil {
		return m.revoke(ctx, opts)
	}
	return m.err
}

func (m *MockAuthority) GetEncryptedKey(kid string) (string, error) {
	if m.getEncryptedKey != nil {
		return m.getEncryptedKey(kid)
	}
	return m.ret1.(string), m.err
}

func (m *MockAuthority) GetRoots() ([]*x509.Certificate, error) {
	if m.getRoots != nil {
		return m.getRoots()
	}
	return m.ret1.([]*x509.Certificate), m.err
}

func (m *MockAuthority) GetFederation() ([]*x509.Certificate, error) {
	if m.getFederation != nil {
		return m.getFederation()
	}
	return m.ret1.([]*x509.Certificate), m.err
}

func (m *MockAuthority) SignSSH(ctx context.Context, key ssh.PublicKey, opts provisioner.SignSSHOptions, signOpts ...provisioner.SignOption) (*ssh.Certificate, error) {
	if m.signSSH != nil {
		return m.signSSH(ctx, key, opts, signOpts...)
	}
	return m.ret1.(*ssh.Certificate), m.err
}

func (m *MockAuthority) SignSSHAddUser(ctx context.Context, key ssh.PublicKey, cert *ssh.Certificate) (*ssh.Certificate, error) {
	if m.signSSHAddUser != nil {
		return m.signSSHAddUser(ctx, key, cert)
	}
	return m.ret1.(*ssh.Certificate), m.err
}

func (m *MockAuthority) RenewSSH(ctx context.Context, cert *ssh.Certificate) (*ssh.Certificate, error) {
	if m.renewSSH != nil {
		return m.renewSSH(ctx, cert)
	}
	return m.ret1.(*ssh.Certificate), m.err
}

func (m *MockAuthority) RekeySSH(ctx context.Context, cert *ssh.Certificate, key ssh.PublicKey, signOpts ...provisioner.SignOption) (*ssh.Certificate, error) {
	if m.rekeySSH != nil {
		return m.rekeySSH(ctx, cert, key, signOpts...)
	}
	return m.ret1.(*ssh.Certificate), m.err
}

func (m *MockAuthority) GetSSHHosts(ctx context.Context, cert *x509.Certificate) ([]authority.Host, error) {
	if m.getSSHHosts != nil {
		return m.getSSHHosts(ctx, cert)
	}
	return m.ret1.([]authority.Host), m.err
}

func (m *MockAuthority) GetSSHRoots(ctx context.Context) (*authority.SSHKeys, error) {
	if m.getSSHRoots != nil {
		return m.getSSHRoots(ctx)
	}
	return m.ret1.(*authority.SSHKeys), m.err
}

func (m *MockAuthority) GetSSHFederation(ctx context.Context) (*authority.SSHKeys, error) {
	if m.getSSHFederation != nil {
		return m.getSSHFederation(ctx)
	}
	return m.ret1.(*authority.SSHKeys), m.err
}

func (m *MockAuthority) GetSSHConfig(ctx context.Context, typ string, data map[string]string) ([]templates.Output, error) {
	if m.getSSHConfig != nil {
		return m.getSSHConfig(ctx, typ, data)
	}
	return m.ret1.([]templates.Output), m.err
}

func (m *MockAuthority) CheckSSHHost(ctx context.Context, principal, token string) (bool, error) {
	if m.checkSSHHost != nil {
		return m.checkSSHHost(ctx, principal, token)
	}
	return m.ret1.(bool), m.err
}

func (m *MockAuthority) GetSSHBastion(ctx context.Context, user, hostname string) (*authority.Bastion, error) {
	if m.getSSHBastion != nil {
		return m.getSSHBastion(ctx, user, hostname)
	}
	return m.ret1.(*authority.Bastion), m.err
}

func (m *MockAuthority) Version() authority.Version {
	if m.version != nil {
		return m.version()
	}
	return m.ret1.(authority.Version)
}

func (m *MockAuthority) IsAdminAPIEnabled() bool {
	if m.MockIsAdminAPIEnabled != nil {
		return m.MockIsAdminAPIEnabled()
	}
	return m.MockRet1.(bool)
}

func (m *MockAuthority) LoadAdminByID(id string) (*linkedca.Admin, bool) {
	if m.MockLoadAdminByID != nil {
		return m.MockLoadAdminByID(id)
	}
	return m.MockRet1.(*linkedca.Admin), m.MockRet2.(bool)
}

func (m *MockAuthority) GetAdmins(cursor string, limit int) ([]*linkedca.Admin, string, error) {
	if m.MockGetAdmins != nil {
		return m.MockGetAdmins(cursor, limit)
	}
	return m.MockRet1.([]*linkedca.Admin), m.MockRet2.(string), m.MockErr
}

func (m *MockAuthority) StoreAdmin(ctx context.Context, adm *linkedca.Admin, prov provisioner.Interface) error {
	if m.MockStoreAdmin != nil {
		return m.MockStoreAdmin(ctx, adm, prov)
	}
	return m.MockErr
}

func (m *MockAuthority) UpdateAdmin(ctx context.Context, id string, nu *linkedca.Admin) (*linkedca.Admin, error) {
	if m.MockUpdateAdmin != nil {
		return m.MockUpdateAdmin(ctx, id, nu)
	}
	return m.MockRet1.(*linkedca.Admin), m.MockErr
}

func (m *MockAuthority) RemoveAdmin(ctx context.Context, id string) error {
	if m.MockRemoveAdmin != nil {
		return m.MockRemoveAdmin(ctx, id)
	}
	return m.MockErr
}

func (m *MockAuthority) AuthorizeAdminToken(r *http.Request, token string) (*linkedca.Admin, error) {
	if m.MockAuthorizeAdminToken != nil {
		return m.MockAuthorizeAdminToken(r, token)
	}
	return m.MockRet1.(*linkedca.Admin), m.MockErr
}

func (m *MockAuthority) StoreProvisioner(ctx context.Context, prov *linkedca.Provisioner) error {
	if m.MockStoreProvisioner != nil {
		return m.MockStoreProvisioner(ctx, prov)
	}
	return m.MockErr
}

func (m *MockAuthority) LoadProvisionerByID(id string) (provisioner.Interface, error) {
	if m.MockLoadProvisionerByID != nil {
		return m.MockLoadProvisionerByID(id)
	}
	return m.MockRet1.(provisioner.Interface), m.MockErr
}

func (m *MockAuthority) UpdateProvisioner(ctx context.Context, nu *linkedca.Provisioner) error {
	if m.MockUpdateProvisioner != nil {
		return m.MockUpdateProvisioner(ctx, nu)
	}
	return m.MockErr
}

func (m *MockAuthority) RemoveProvisioner(ctx context.Context, id string) error {
	if m.MockRemoveProvisioner != nil {
		return m.MockRemoveProvisioner(ctx, id)
	}
	return m.MockErr
}
