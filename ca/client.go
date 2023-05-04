package ca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/ca/identity"
	"github.com/smallstep/certificates/errs"
	"go.step.sm/cli-utils/step"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/x509util"
	"golang.org/x/net/http2"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"gopkg.in/square/go-jose.v2/jwt"
)

// DisableIdentity is a global variable to disable the identity.
var DisableIdentity = false

// UserAgent will set the User-Agent header in the client requests.
var UserAgent = "step-http-client/1.0"

type uaClient struct {
	Client *http.Client
}

func newClient(transport http.RoundTripper) *uaClient {
	return &uaClient{
		Client: &http.Client{
			Transport: transport,
		},
	}
}

//nolint:gosec // used in bootstrap protocol
func newInsecureClient() *uaClient {
	return &uaClient{
		Client: &http.Client{
			Transport: getDefaultTransport(&tls.Config{InsecureSkipVerify: true}),
		},
	}
}

func (c *uaClient) GetTransport() http.RoundTripper {
	return c.Client.Transport
}

func (c *uaClient) SetTransport(tr http.RoundTripper) {
	c.Client.Transport = tr
}

func (c *uaClient) Get(u string) (*http.Response, error) {
	return c.GetWithContext(context.Background(), u)
}

func (c *uaClient) GetWithContext(ctx context.Context, u string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", u, http.NoBody)
	if err != nil {
		return nil, errors.Wrapf(err, "create GET %s request failed", u)
	}
	req.Header.Set("User-Agent", UserAgent)
	return c.Client.Do(req)
}

func (c *uaClient) Post(u, contentType string, body io.Reader) (*http.Response, error) {
	return c.PostWithContext(context.Background(), u, contentType, body)
}

func (c *uaClient) PostWithContext(ctx context.Context, u, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", u, body)
	if err != nil {
		return nil, errors.Wrapf(err, "create POST %s request failed", u)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", UserAgent)
	return c.Client.Do(req)
}

func (c *uaClient) Do(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", UserAgent)
	return c.Client.Do(req)
}

// RetryFunc defines the method used to retry a request. If it returns true, the
// request will be retried once.
type RetryFunc func(code int) bool

// ClientOption is the type of options passed to the Client constructor.
type ClientOption func(o *clientOptions) error

type clientOptions struct {
	transport            http.RoundTripper
	rootSHA256           string
	rootFilename         string
	rootBundle           []byte
	certificate          tls.Certificate
	getClientCertificate func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
	retryFunc            RetryFunc
	x5cJWK               *jose.JSONWebKey
	x5cCertFile          string
	x5cCertStrs          []string
	x5cCert              *x509.Certificate
	x5cSubject           string
}

func (o *clientOptions) apply(opts []ClientOption) (err error) {
	o.applyDefaultIdentity()
	for _, fn := range opts {
		if err = fn(o); err != nil {
			return
		}
	}
	return
}

// applyDefaultIdentity sets the options for the default identity if the
// identity file is present. The identity is enabled by default.
func (o *clientOptions) applyDefaultIdentity() {
	if DisableIdentity {
		return
	}

	// Do not load an identity if something fails
	i, err := identity.LoadDefaultIdentity()
	if err != nil {
		return
	}
	if err := i.Validate(); err != nil {
		return
	}
	crt, err := i.TLSCertificate()
	if err != nil {
		return
	}
	o.certificate = crt
	o.getClientCertificate = i.GetClientCertificateFunc()
}

// checkTransport checks if other ways to set up a transport have been provided.
// If they have it returns an error.
func (o *clientOptions) checkTransport() error {
	if o.transport != nil || o.rootFilename != "" || o.rootSHA256 != "" || o.rootBundle != nil {
		return errors.New("multiple transport methods have been configured")
	}
	return nil
}

// getTransport returns the transport configured in the clientOptions.
func (o *clientOptions) getTransport(endpoint string) (tr http.RoundTripper, err error) {
	if o.transport != nil {
		tr = o.transport
	}
	if o.rootFilename != "" {
		if tr, err = getTransportFromFile(o.rootFilename); err != nil {
			return nil, err
		}
	}
	if o.rootSHA256 != "" {
		if tr, err = getTransportFromSHA256(endpoint, o.rootSHA256); err != nil {
			return nil, err
		}
	}
	if o.rootBundle != nil {
		if tr, err = getTransportFromCABundle(o.rootBundle); err != nil {
			return nil, err
		}
	}
	// As the last option attempt to load the default root ca
	if tr == nil {
		rootFile := getRootCAPath()
		if _, err := os.Stat(rootFile); err == nil {
			if tr, err = getTransportFromFile(rootFile); err != nil {
				return nil, err
			}
		}
		if tr == nil {
			return nil, errors.New("a transport, a root cert, or a root sha256 must be used")
		}
	}

	// Add client certificate if available
	if o.certificate.Certificate != nil {
		switch tr := tr.(type) {
		case *http.Transport:
			if tr.TLSClientConfig == nil {
				tr.TLSClientConfig = &tls.Config{
					MinVersion: tls.VersionTLS12,
				}
			}
			if len(tr.TLSClientConfig.Certificates) == 0 && tr.TLSClientConfig.GetClientCertificate == nil {
				tr.TLSClientConfig.Certificates = []tls.Certificate{o.certificate}
				tr.TLSClientConfig.GetClientCertificate = o.getClientCertificate
			}
		case *http2.Transport:
			if tr.TLSClientConfig == nil {
				tr.TLSClientConfig = &tls.Config{
					MinVersion: tls.VersionTLS12,
				}
			}
			if len(tr.TLSClientConfig.Certificates) == 0 && tr.TLSClientConfig.GetClientCertificate == nil {
				tr.TLSClientConfig.Certificates = []tls.Certificate{o.certificate}
				tr.TLSClientConfig.GetClientCertificate = o.getClientCertificate
			}
		default:
			return nil, errors.Errorf("unsupported transport type %T", tr)
		}
	}

	return tr, nil
}

// WithTransport adds a custom transport to the Client. It will fail if a
// previous option to create the transport has been configured.
func WithTransport(tr http.RoundTripper) ClientOption {
	return func(o *clientOptions) error {
		if err := o.checkTransport(); err != nil {
			return err
		}
		o.transport = tr
		return nil
	}
}

// WithInsecure adds a insecure transport that bypasses TLS verification.
func WithInsecure() ClientOption {
	return func(o *clientOptions) error {
		o.transport = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				//nolint:gosec // insecure option
				InsecureSkipVerify: true,
			},
		}
		return nil
	}
}

// WithRootFile will create the transport using the given root certificate. It
// will fail if a previous option to create the transport has been configured.
func WithRootFile(filename string) ClientOption {
	return func(o *clientOptions) error {
		if err := o.checkTransport(); err != nil {
			return err
		}
		o.rootFilename = filename
		return nil
	}
}

// WithRootSHA256 will create the transport using an insecure client to retrieve
// the root certificate using its fingerprint. It will fail if a previous option
// to create the transport has been configured.
func WithRootSHA256(sum string) ClientOption {
	return func(o *clientOptions) error {
		if err := o.checkTransport(); err != nil {
			return err
		}
		o.rootSHA256 = sum
		return nil
	}
}

// WithCABundle will create the transport using the given root certificates. It
// will fail if a previous option to create the transport has been configured.
func WithCABundle(bundle []byte) ClientOption {
	return func(o *clientOptions) error {
		if err := o.checkTransport(); err != nil {
			return err
		}
		o.rootBundle = bundle
		return nil
	}
}

// WithCertificate will set the given certificate as the TLS client certificate
// in the client.
func WithCertificate(cert tls.Certificate) ClientOption {
	return func(o *clientOptions) error {
		o.certificate = cert
		return nil
	}
}

// WithAdminX5C will set the given file as the X5C certificate for use
// by the client.
func WithAdminX5C(certs []*x509.Certificate, key interface{}, passwordFile string) ClientOption {
	return func(o *clientOptions) error {
		// Get private key from given key file
		var (
			err  error
			opts []jose.Option
		)
		if passwordFile != "" {
			opts = append(opts, jose.WithPasswordFile(passwordFile))
		}
		blk, err := pemutil.Serialize(key)
		if err != nil {
			return errors.Wrap(err, "error serializing private key")
		}
		o.x5cJWK, err = jose.ParseKey(pem.EncodeToMemory(blk), opts...)
		if err != nil {
			return err
		}
		o.x5cCertStrs, err = jose.ValidateX5C(certs, o.x5cJWK.Key)
		if err != nil {
			return errors.Wrap(err, "error validating x5c certificate chain and key for use in x5c header")
		}

		o.x5cCert = certs[0]
		switch leaf := certs[0]; {
		case leaf.Subject.CommonName != "":
			o.x5cSubject = leaf.Subject.CommonName
		case len(leaf.DNSNames) > 0:
			o.x5cSubject = leaf.DNSNames[0]
		case len(leaf.EmailAddresses) > 0:
			o.x5cSubject = leaf.EmailAddresses[0]
		}

		return nil
	}
}

// WithRetryFunc defines a method used to retry a request.
func WithRetryFunc(fn RetryFunc) ClientOption {
	return func(o *clientOptions) error {
		o.retryFunc = fn
		return nil
	}
}

func getTransportFromFile(filename string) (http.RoundTripper, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading %s", filename)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.Errorf("error parsing %s: no certificates found", filename)
	}
	return getDefaultTransport(&tls.Config{
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		RootCAs:                  pool,
	}), nil
}

func getTransportFromSHA256(endpoint, sum string) (http.RoundTripper, error) {
	u, err := parseEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	client := &Client{endpoint: u}
	root, err := client.Root(sum)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(root.RootPEM.Certificate)
	return getDefaultTransport(&tls.Config{
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		RootCAs:                  pool,
	}), nil
}

func getTransportFromCABundle(bundle []byte) (http.RoundTripper, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(bundle) {
		return nil, errors.New("error parsing ca bundle: no certificates found")
	}
	return getDefaultTransport(&tls.Config{
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		RootCAs:                  pool,
	}), nil
}

// parseEndpoint parses and validates the given endpoint. It supports general
// URLs like https://ca.smallstep.com[:port][/path], and incomplete URLs like
// ca.smallstep.com[:port][/path].
func parseEndpoint(endpoint string) (*url.URL, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing endpoint '%s'", endpoint)
	}

	// URLs are generally parsed as:
	// [scheme:][//[userinfo@]host][/]path[?query][#fragment]
	// But URLs that do not start with a slash after the scheme are interpreted as
	// scheme:opaque[?query][#fragment]
	if u.Opaque == "" {
		if u.Scheme == "" {
			u.Scheme = "https"
		}
		if u.Host == "" {
			// endpoint looks like ca.smallstep.com or ca.smallstep.com/1.0/sign
			if u.Path != "" {
				parts := strings.SplitN(u.Path, "/", 2)
				u.Host = parts[0]
				if len(parts) == 2 {
					u.Path = parts[1]
				} else {
					u.Path = ""
				}
				return parseEndpoint(u.String())
			}
			return nil, errors.Errorf("error parsing endpoint: url '%s' is not valid", endpoint)
		}
		return u, nil
	}
	// scheme:opaque[?query][#fragment]
	// endpoint looks like ca.smallstep.com:443 or ca.smallstep.com:443/1.0/sign
	return parseEndpoint("https://" + endpoint)
}

// ProvisionerOption is the type of options passed to the Provisioner method.
type ProvisionerOption func(o *ProvisionerOptions) error

// ProvisionerOptions stores options for the provisioner CRUD API.
type ProvisionerOptions struct {
	Cursor string
	Limit  int
	ID     string
	Name   string
}

// Apply caches provisioner options on a struct for later use.
func (o *ProvisionerOptions) Apply(opts []ProvisionerOption) (err error) {
	for _, fn := range opts {
		if err = fn(o); err != nil {
			return
		}
	}
	return
}

func (o *ProvisionerOptions) rawQuery() string {
	v := url.Values{}
	if o.Cursor != "" {
		v.Set("cursor", o.Cursor)
	}
	if o.Limit > 0 {
		v.Set("limit", strconv.Itoa(o.Limit))
	}
	if o.ID != "" {
		v.Set("id", o.ID)
	}
	if o.Name != "" {
		v.Set("name", o.Name)
	}
	return v.Encode()
}

// WithProvisionerCursor will request the provisioners starting with the given cursor.
func WithProvisionerCursor(cursor string) ProvisionerOption {
	return func(o *ProvisionerOptions) error {
		o.Cursor = cursor
		return nil
	}
}

// WithProvisionerLimit will request the given number of provisioners.
func WithProvisionerLimit(limit int) ProvisionerOption {
	return func(o *ProvisionerOptions) error {
		o.Limit = limit
		return nil
	}
}

// WithProvisionerID will request the given provisioner.
func WithProvisionerID(id string) ProvisionerOption {
	return func(o *ProvisionerOptions) error {
		o.ID = id
		return nil
	}
}

// WithProvisionerName will request the given provisioner.
func WithProvisionerName(name string) ProvisionerOption {
	return func(o *ProvisionerOptions) error {
		o.Name = name
		return nil
	}
}

// Client implements an HTTP client for the CA server.
type Client struct {
	client    *uaClient
	endpoint  *url.URL
	retryFunc RetryFunc
	opts      []ClientOption
}

// NewClient creates a new Client with the given endpoint and options.
func NewClient(endpoint string, opts ...ClientOption) (*Client, error) {
	u, err := parseEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	// Retrieve transport from options.
	o := new(clientOptions)
	if err := o.apply(opts); err != nil {
		return nil, err
	}
	tr, err := o.getTransport(endpoint)
	if err != nil {
		return nil, err
	}

	return &Client{
		client:    newClient(tr),
		endpoint:  u,
		retryFunc: o.retryFunc,
		opts:      opts,
	}, nil
}

func (c *Client) retryOnError(r *http.Response) bool {
	if c.retryFunc != nil {
		if c.retryFunc(r.StatusCode) {
			o := new(clientOptions)
			if err := o.apply(c.opts); err != nil {
				return false
			}
			tr, err := o.getTransport(c.endpoint.String())
			if err != nil {
				return false
			}
			r.Body.Close()
			c.client.SetTransport(tr)
			return true
		}
	}
	return false
}

// GetCaURL returns the configured CA url.
func (c *Client) GetCaURL() string {
	return c.endpoint.String()
}

// GetRootCAs returns the RootCAs certificate pool from the configured
// transport.
func (c *Client) GetRootCAs() *x509.CertPool {
	switch t := c.client.GetTransport().(type) {
	case *http.Transport:
		if t.TLSClientConfig != nil {
			return t.TLSClientConfig.RootCAs
		}
		return nil
	case *http2.Transport:
		if t.TLSClientConfig != nil {
			return t.TLSClientConfig.RootCAs
		}
		return nil
	default:
		return nil
	}
}

// SetTransport updates the transport of the internal HTTP client.
func (c *Client) SetTransport(tr http.RoundTripper) {
	c.client.SetTransport(tr)
}

// Version performs the version request to the CA with an empty context and returns the
// api.VersionResponse struct.
func (c *Client) Version() (*api.VersionResponse, error) {
	return c.VersionWithContext(context.Background())
}

// VersionWithContext performs the version request to the CA with the provided context
// and returns the api.VersionResponse struct.
func (c *Client) VersionWithContext(ctx context.Context) (*api.VersionResponse, error) {
	var retried bool
	u := c.endpoint.ResolveReference(&url.URL{Path: "/version"})
retry:
	resp, err := c.client.GetWithContext(ctx, u.String())
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) { //nolint:contextcheck // deeply nested context; retry using the same context
			retried = true
			goto retry
		}
		return nil, readError(resp.Body)
	}
	var version api.VersionResponse
	if err := readJSON(resp.Body, &version); err != nil {
		return nil, errs.Wrapf(http.StatusInternalServerError, err, "client.Version; error reading %s", u)
	}
	return &version, nil
}

// Health performs the health request to the CA with an empty context
// and returns the api.HealthResponse struct.
func (c *Client) Health() (*api.HealthResponse, error) {
	return c.HealthWithContext(context.Background())
}

// HealthWithContext performs the health request to the CA with the provided context
// and returns the api.HealthResponse struct.
func (c *Client) HealthWithContext(ctx context.Context) (*api.HealthResponse, error) {
	var retried bool
	u := c.endpoint.ResolveReference(&url.URL{Path: "/health"})
retry:
	resp, err := c.client.GetWithContext(ctx, u.String())
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) { //nolint:contextcheck // deeply nested context; retry using the same context
			retried = true
			goto retry
		}
		return nil, readError(resp.Body)
	}
	var health api.HealthResponse
	if err := readJSON(resp.Body, &health); err != nil {
		return nil, errs.Wrapf(http.StatusInternalServerError, err, "client.Health; error reading %s", u)
	}
	return &health, nil
}

// Root performs the root request to the CA with an empty context and the provided
// SHA256 and returns the api.RootResponse struct. It uses an insecure client, but
// it checks the resulting root certificate with the given SHA256, returning an error
// if they do not match.
func (c *Client) Root(sha256Sum string) (*api.RootResponse, error) {
	return c.RootWithContext(context.Background(), sha256Sum)
}

// RootWithContext performs the root request to the CA with an empty context and the provided
// SHA256 and returns the api.RootResponse struct. It uses an insecure client, but
// it checks the resulting root certificate with the given SHA256, returning an error
// if they do not match.
func (c *Client) RootWithContext(ctx context.Context, sha256Sum string) (*api.RootResponse, error) {
	var retried bool
	sha256Sum = strings.ToLower(strings.ReplaceAll(sha256Sum, "-", ""))
	u := c.endpoint.ResolveReference(&url.URL{Path: "/root/" + sha256Sum})
retry:
	resp, err := newInsecureClient().GetWithContext(ctx, u.String())
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) { //nolint:contextcheck // deeply nested context; retry using the same context
			retried = true
			goto retry
		}
		return nil, readError(resp.Body)
	}
	var root api.RootResponse
	if err := readJSON(resp.Body, &root); err != nil {
		return nil, errs.Wrapf(http.StatusInternalServerError, err, "client.Root; error reading %s", u)
	}
	// verify the sha256
	sum := sha256.Sum256(root.RootPEM.Raw)
	if !strings.EqualFold(sha256Sum, strings.ToLower(hex.EncodeToString(sum[:]))) {
		return nil, errs.BadRequest("root certificate fingerprint does not match")
	}
	return &root, nil
}

// Sign performs the sign request to the CA with an empty context and returns
// the api.SignResponse struct.
func (c *Client) Sign(req *api.SignRequest) (*api.SignResponse, error) {
	return c.SignWithContext(context.Background(), req)
}

// SignWithContext performs the sign request to the CA with the provided context
// and returns the api.SignResponse struct.
func (c *Client) SignWithContext(ctx context.Context, req *api.SignRequest) (*api.SignResponse, error) {
	var retried bool
	body, err := json.Marshal(req)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "client.Sign; error marshaling request")
	}
	u := c.endpoint.ResolveReference(&url.URL{Path: "/sign"})
retry:
	resp, err := c.client.PostWithContext(ctx, u.String(), "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) { //nolint:contextcheck // deeply nested context; retry using the same context
			retried = true
			goto retry
		}
		return nil, readError(resp.Body)
	}
	var sign api.SignResponse
	if err := readJSON(resp.Body, &sign); err != nil {
		return nil, errs.Wrapf(http.StatusInternalServerError, err, "client.Sign; error reading %s", u)
	}
	// Add tls.ConnectionState:
	// We'll extract the root certificate from the verified chains
	sign.TLS = resp.TLS
	return &sign, nil
}

// Renew performs the renew request to the CA with an empty context and
// returns the api.SignResponse struct.
func (c *Client) Renew(tr http.RoundTripper) (*api.SignResponse, error) {
	return c.RenewWithContext(context.Background(), tr)
}

// RenewWithContext performs the renew request to the CA with the provided context
// and returns the api.SignResponse struct.
func (c *Client) RenewWithContext(ctx context.Context, tr http.RoundTripper) (*api.SignResponse, error) {
	var retried bool
	u := c.endpoint.ResolveReference(&url.URL{Path: "/renew"})
	client := &http.Client{Transport: tr}
retry:
	req, err := http.NewRequestWithContext(ctx, "POST", u.String(), http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) { //nolint:contextcheck // deeply nested context; retry using the same context
			retried = true
			goto retry
		}
		return nil, readError(resp.Body)
	}
	var sign api.SignResponse
	if err := readJSON(resp.Body, &sign); err != nil {
		return nil, errs.Wrapf(http.StatusInternalServerError, err, "client.Renew; error reading %s", u)
	}
	return &sign, nil
}

// RenewWithToken performs the renew request to the CA with the given
// authorization token and and empty context and returns the api.SignResponse struct.
// This method is generally used to renew an expired certificate.
func (c *Client) RenewWithToken(token string) (*api.SignResponse, error) {
	return c.RenewWithTokenAndContext(context.Background(), token)
}

// RenewWithTokenAndContext performs the renew request to the CA with the given
// authorization token and context and returns the api.SignResponse struct.
// This method is generally used to renew an expired certificate.
func (c *Client) RenewWithTokenAndContext(ctx context.Context, token string) (*api.SignResponse, error) {
	var retried bool
	u := c.endpoint.ResolveReference(&url.URL{Path: "/renew"})
	req, err := http.NewRequestWithContext(ctx, "POST", u.String(), http.NoBody)
	if err != nil {
		return nil, errors.Wrapf(err, "create POST %s request failed", u)
	}
	req.Header.Add("Authorization", "Bearer "+token)
retry:
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) { //nolint:contextcheck // deeply nested context; retry using the same context
			retried = true
			goto retry
		}
		return nil, readError(resp.Body)
	}
	var sign api.SignResponse
	if err := readJSON(resp.Body, &sign); err != nil {
		return nil, errs.Wrapf(http.StatusInternalServerError, err, "client.RenewWithToken; error reading %s", u)
	}
	return &sign, nil
}

// Rekey performs the rekey request to the CA with an empty context and
// returns the api.SignResponse struct.
func (c *Client) Rekey(req *api.RekeyRequest, tr http.RoundTripper) (*api.SignResponse, error) {
	return c.RekeyWithContext(context.Background(), req, tr)
}

// RekeyWithContext performs the rekey request to the CA with the provided context
// and returns the api.SignResponse struct.
func (c *Client) RekeyWithContext(ctx context.Context, req *api.RekeyRequest, tr http.RoundTripper) (*api.SignResponse, error) {
	var retried bool
	body, err := json.Marshal(req)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling request")
	}
	u := c.endpoint.ResolveReference(&url.URL{Path: "/rekey"})
	client := &http.Client{Transport: tr}
retry:
	httpReq, err := http.NewRequestWithContext(ctx, "POST", u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) { //nolint:contextcheck // deeply nested context; retry using the same context
			retried = true
			goto retry
		}
		return nil, readError(resp.Body)
	}
	var sign api.SignResponse
	if err := readJSON(resp.Body, &sign); err != nil {
		return nil, errs.Wrapf(http.StatusInternalServerError, err, "client.Rekey; error reading %s", u)
	}
	return &sign, nil
}

// Revoke performs the revoke request to the CA with an empty context and returns
// the api.RevokeResponse struct.
func (c *Client) Revoke(req *api.RevokeRequest, tr http.RoundTripper) (*api.RevokeResponse, error) {
	return c.RevokeWithContext(context.Background(), req, tr)
}

// RevokeWithContext performs the revoke request to the CA with the provided context and
// returns the api.RevokeResponse struct.
func (c *Client) RevokeWithContext(ctx context.Context, req *api.RevokeRequest, tr http.RoundTripper) (*api.RevokeResponse, error) {
	var retried bool
	body, err := json.Marshal(req)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling request")
	}
	var client *uaClient
retry:
	if tr != nil {
		client = newClient(tr)
	} else {
		client = c.client
	}

	u := c.endpoint.ResolveReference(&url.URL{Path: "/revoke"})
	resp, err := client.PostWithContext(ctx, u.String(), "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) { //nolint:contextcheck // deeply nested context; retry using the same context
			retried = true
			goto retry
		}
		return nil, readError(resp.Body)
	}
	var revoke api.RevokeResponse
	if err := readJSON(resp.Body, &revoke); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	return &revoke, nil
}

// Provisioners performs the provisioners request to the CA with an empty context
// and returns the api.ProvisionersResponse struct with a map of provisioners.
//
// ProvisionerOption WithProvisionerCursor and WithProvisionLimit can be used to
// paginate the provisioners.
func (c *Client) Provisioners(opts ...ProvisionerOption) (*api.ProvisionersResponse, error) {
	return c.ProvisionersWithContext(context.Background(), opts...)
}

// ProvisionersWithContext performs the provisioners request to the CA with the provided context
// and returns the api.ProvisionersResponse struct with a map of provisioners.
//
// ProvisionerOption WithProvisionerCursor and WithProvisionLimit can be used to
// paginate the provisioners.
func (c *Client) ProvisionersWithContext(ctx context.Context, opts ...ProvisionerOption) (*api.ProvisionersResponse, error) {
	var retried bool
	o := new(ProvisionerOptions)
	if err := o.Apply(opts); err != nil {
		return nil, err
	}
	u := c.endpoint.ResolveReference(&url.URL{
		Path:     "/provisioners",
		RawQuery: o.rawQuery(),
	})
retry:
	resp, err := c.client.GetWithContext(ctx, u.String())
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) { //nolint:contextcheck // deeply nested context; retry using the same context
			retried = true
			goto retry
		}
		return nil, readError(resp.Body)
	}
	var provisioners api.ProvisionersResponse
	if err := readJSON(resp.Body, &provisioners); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	return &provisioners, nil
}

// ProvisionerKey performs the request to the CA with an empty context to get
// the encrypted key for the given provisioner kid and returns the api.ProvisionerKeyResponse
// struct with the encrypted key.
func (c *Client) ProvisionerKey(kid string) (*api.ProvisionerKeyResponse, error) {
	return c.ProvisionerKeyWithContext(context.Background(), kid)
}

// ProvisionerKeyWithContext performs the request to the CA with the provided context to get
// the encrypted key for the given provisioner kid and returns the api.ProvisionerKeyResponse
// struct with the encrypted key.
func (c *Client) ProvisionerKeyWithContext(ctx context.Context, kid string) (*api.ProvisionerKeyResponse, error) {
	var retried bool
	u := c.endpoint.ResolveReference(&url.URL{Path: "/provisioners/" + kid + "/encrypted-key"})
retry:
	resp, err := c.client.GetWithContext(ctx, u.String())
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) { //nolint:contextcheck // deeply nested context; retry using the same context
			retried = true
			goto retry
		}
		return nil, readError(resp.Body)
	}
	var key api.ProvisionerKeyResponse
	if err := readJSON(resp.Body, &key); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	return &key, nil
}

// Roots performs the get roots request to the CA with an empty context
// and returns the api.RootsResponse struct.
func (c *Client) Roots() (*api.RootsResponse, error) {
	return c.RootsWithContext(context.Background())
}

// RootsWithContext performs the get roots request to the CA with the provided context
// and returns the api.RootsResponse struct.
func (c *Client) RootsWithContext(ctx context.Context) (*api.RootsResponse, error) {
	var retried bool
	u := c.endpoint.ResolveReference(&url.URL{Path: "/roots"})
retry:
	resp, err := c.client.GetWithContext(ctx, u.String())
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) { //nolint:contextcheck // deeply nested context; retry using the same context
			retried = true
			goto retry
		}
		return nil, readError(resp.Body)
	}
	var roots api.RootsResponse
	if err := readJSON(resp.Body, &roots); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	return &roots, nil
}

// Federation performs the get federation request to the CA with an empty context
// and returns the api.FederationResponse struct.
func (c *Client) Federation() (*api.FederationResponse, error) {
	return c.FederationWithContext(context.Background())
}

// FederationWithContext performs the get federation request to the CA with the provided context
// and returns the api.FederationResponse struct.
func (c *Client) FederationWithContext(ctx context.Context) (*api.FederationResponse, error) {
	var retried bool
	u := c.endpoint.ResolveReference(&url.URL{Path: "/federation"})
retry:
	resp, err := c.client.GetWithContext(ctx, u.String())
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) { //nolint:contextcheck // deeply nested context; retry using the same context
			retried = true
			goto retry
		}
		return nil, readError(resp.Body)
	}
	var federation api.FederationResponse
	if err := readJSON(resp.Body, &federation); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	return &federation, nil
}

// SSHSign performs the POST /ssh/sign request to the CA with an empty context
// and returns the api.SSHSignResponse struct.
func (c *Client) SSHSign(req *api.SSHSignRequest) (*api.SSHSignResponse, error) {
	return c.SSHSignWithContext(context.Background(), req)
}

// SSHSignWithContext performs the POST /ssh/sign request to the CA with the provided context
// and returns the api.SSHSignResponse struct.
func (c *Client) SSHSignWithContext(ctx context.Context, req *api.SSHSignRequest) (*api.SSHSignResponse, error) {
	var retried bool
	body, err := json.Marshal(req)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling request")
	}
	u := c.endpoint.ResolveReference(&url.URL{Path: "/ssh/sign"})
retry:
	resp, err := c.client.PostWithContext(ctx, u.String(), "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) { //nolint:contextcheck // deeply nested context; retry using the same context
			retried = true
			goto retry
		}
		return nil, readError(resp.Body)
	}
	var sign api.SSHSignResponse
	if err := readJSON(resp.Body, &sign); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	return &sign, nil
}

// SSHRenew performs the POST /ssh/renew request to the CA with an empty context
// and returns the api.SSHRenewResponse struct.
func (c *Client) SSHRenew(req *api.SSHRenewRequest) (*api.SSHRenewResponse, error) {
	return c.SSHRenewWithContext(context.Background(), req)
}

// SSHRenewWithContext performs the POST /ssh/renew request to the CA with the provided context
// and returns the api.SSHRenewResponse struct.
func (c *Client) SSHRenewWithContext(ctx context.Context, req *api.SSHRenewRequest) (*api.SSHRenewResponse, error) {
	var retried bool
	body, err := json.Marshal(req)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling request")
	}
	u := c.endpoint.ResolveReference(&url.URL{Path: "/ssh/renew"})
retry:
	resp, err := c.client.PostWithContext(ctx, u.String(), "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) { //nolint:contextcheck // deeply nested context; retry using the same context
			retried = true
			goto retry
		}
		return nil, readError(resp.Body)
	}
	var renew api.SSHRenewResponse
	if err := readJSON(resp.Body, &renew); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	return &renew, nil
}

// SSHRekey performs the POST /ssh/rekey request to the CA with an empty context
// and returns the api.SSHRekeyResponse struct.
func (c *Client) SSHRekey(req *api.SSHRekeyRequest) (*api.SSHRekeyResponse, error) {
	return c.SSHRekeyWithContext(context.Background(), req)
}

// SSHRekeyWithContext performs the POST /ssh/rekey request to the CA with the provided context
// and returns the api.SSHRekeyResponse struct.
func (c *Client) SSHRekeyWithContext(ctx context.Context, req *api.SSHRekeyRequest) (*api.SSHRekeyResponse, error) {
	var retried bool
	body, err := json.Marshal(req)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling request")
	}
	u := c.endpoint.ResolveReference(&url.URL{Path: "/ssh/rekey"})
retry:
	resp, err := c.client.PostWithContext(ctx, u.String(), "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) { //nolint:contextcheck // deeply nested context; retry using the same context
			retried = true
			goto retry
		}
		return nil, readError(resp.Body)
	}
	var rekey api.SSHRekeyResponse
	if err := readJSON(resp.Body, &rekey); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	return &rekey, nil
}

// SSHRevoke performs the POST /ssh/revoke request to the CA with an empty context
// and returns the api.SSHRevokeResponse struct.
func (c *Client) SSHRevoke(req *api.SSHRevokeRequest) (*api.SSHRevokeResponse, error) {
	return c.SSHRevokeWithContext(context.Background(), req)
}

// SSHRevokeWithContext performs the POST /ssh/revoke request to the CA with the provided context
// and returns the api.SSHRevokeResponse struct.
func (c *Client) SSHRevokeWithContext(ctx context.Context, req *api.SSHRevokeRequest) (*api.SSHRevokeResponse, error) {
	var retried bool
	body, err := json.Marshal(req)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling request")
	}
	u := c.endpoint.ResolveReference(&url.URL{Path: "/ssh/revoke"})
retry:
	resp, err := c.client.PostWithContext(ctx, u.String(), "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) { //nolint:contextcheck // deeply nested context; retry using the same context
			retried = true
			goto retry
		}
		return nil, readError(resp.Body)
	}
	var revoke api.SSHRevokeResponse
	if err := readJSON(resp.Body, &revoke); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	return &revoke, nil
}

// SSHRoots performs the GET /ssh/roots request to the CA with an empty context
// and returns the api.SSHRootsResponse struct.
func (c *Client) SSHRoots() (*api.SSHRootsResponse, error) {
	return c.SSHRootsWithContext(context.Background())
}

// SSHRootsWithContext performs the GET /ssh/roots request to the CA with the provided context
// and returns the api.SSHRootsResponse struct.
func (c *Client) SSHRootsWithContext(ctx context.Context) (*api.SSHRootsResponse, error) {
	var retried bool
	u := c.endpoint.ResolveReference(&url.URL{Path: "/ssh/roots"})
retry:
	resp, err := c.client.GetWithContext(ctx, u.String())
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) { //nolint:contextcheck // deeply nested context; retry using the same context
			retried = true
			goto retry
		}
		return nil, readError(resp.Body)
	}
	var keys api.SSHRootsResponse
	if err := readJSON(resp.Body, &keys); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	return &keys, nil
}

// SSHFederation performs the get /ssh/federation request to the CA with an empty context
// and returns the api.SSHRootsResponse struct.
func (c *Client) SSHFederation() (*api.SSHRootsResponse, error) {
	return c.SSHFederationWithContext(context.Background())
}

// SSHFederationWithContext performs the get /ssh/federation request to the CA with the provided context
// and returns the api.SSHRootsResponse struct.
func (c *Client) SSHFederationWithContext(ctx context.Context) (*api.SSHRootsResponse, error) {
	var retried bool
	u := c.endpoint.ResolveReference(&url.URL{Path: "/ssh/federation"})
retry:
	resp, err := c.client.GetWithContext(ctx, u.String())
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) { //nolint:contextcheck // deeply nested context; retry using the same context
			retried = true
			goto retry
		}
		return nil, readError(resp.Body)
	}
	var keys api.SSHRootsResponse
	if err := readJSON(resp.Body, &keys); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	return &keys, nil
}

// SSHConfig performs the POST /ssh/config request to the CA with an empty context
// to get the ssh configuration templates.
func (c *Client) SSHConfig(req *api.SSHConfigRequest) (*api.SSHConfigResponse, error) {
	return c.SSHConfigWithContext(context.Background(), req)
}

// SSHConfigWithContext performs the POST /ssh/config request to the CA with the provided context
// to get the ssh configuration templates.
func (c *Client) SSHConfigWithContext(ctx context.Context, req *api.SSHConfigRequest) (*api.SSHConfigResponse, error) {
	var retried bool
	body, err := json.Marshal(req)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling request")
	}
	u := c.endpoint.ResolveReference(&url.URL{Path: "/ssh/config"})
retry:
	resp, err := c.client.PostWithContext(ctx, u.String(), "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) { //nolint:contextcheck // deeply nested context; retry using the same context
			retried = true
			goto retry
		}
		return nil, readError(resp.Body)
	}
	var cfg api.SSHConfigResponse
	if err := readJSON(resp.Body, &cfg); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	return &cfg, nil
}

// SSHCheckHost performs the POST /ssh/check-host request to the CA with an empty context,
// the principal and a token and returns the api.SSHCheckPrincipalResponse.
func (c *Client) SSHCheckHost(principal, token string) (*api.SSHCheckPrincipalResponse, error) {
	return c.SSHCheckHostWithContext(context.Background(), principal, token)
}

// SSHCheckHostWithContext performs the POST /ssh/check-host request to the CA with the provided context,
// principal and token and returns the api.SSHCheckPrincipalResponse.
func (c *Client) SSHCheckHostWithContext(ctx context.Context, principal, token string) (*api.SSHCheckPrincipalResponse, error) {
	var retried bool
	body, err := json.Marshal(&api.SSHCheckPrincipalRequest{
		Type:      provisioner.SSHHostCert,
		Principal: principal,
		Token:     token,
	})
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "error marshaling request",
			errs.WithMessage("Failed to marshal the check-host request"))
	}
	u := c.endpoint.ResolveReference(&url.URL{Path: "/ssh/check-host"})
retry:
	resp, err := c.client.PostWithContext(ctx, u.String(), "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) { //nolint:contextcheck // deeply nested context; retry using the same context
			retried = true
			goto retry
		}
		return nil, readError(resp.Body)
	}
	var check api.SSHCheckPrincipalResponse
	if err := readJSON(resp.Body, &check); err != nil {
		return nil, errs.Wrapf(http.StatusInternalServerError, err, "error reading %s response",
			[]any{u, errs.WithMessage("Failed to parse response from /ssh/check-host endpoint")}...)
	}
	return &check, nil
}

// SSHGetHosts performs the GET /ssh/get-hosts request to the CA with an empty context.
func (c *Client) SSHGetHosts() (*api.SSHGetHostsResponse, error) {
	return c.SSHGetHostsWithContext(context.Background())
}

// SSHGetHostsWithContext performs the GET /ssh/get-hosts request to the CA with the provided context.
func (c *Client) SSHGetHostsWithContext(ctx context.Context) (*api.SSHGetHostsResponse, error) {
	var retried bool
	u := c.endpoint.ResolveReference(&url.URL{Path: "/ssh/hosts"})
retry:
	resp, err := c.client.GetWithContext(ctx, u.String())
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) { //nolint:contextcheck // deeply nested context; retry using the same context
			retried = true
			goto retry
		}
		return nil, readError(resp.Body)
	}
	var hosts api.SSHGetHostsResponse
	if err := readJSON(resp.Body, &hosts); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	return &hosts, nil
}

// SSHBastion performs the POST /ssh/bastion request to the CA with an empty context.
func (c *Client) SSHBastion(req *api.SSHBastionRequest) (*api.SSHBastionResponse, error) {
	return c.SSHBastionWithContext(context.Background(), req)
}

// SSHBastionWithContext performs the POST /ssh/bastion request to the CA with the provided context.
func (c *Client) SSHBastionWithContext(ctx context.Context, req *api.SSHBastionRequest) (*api.SSHBastionResponse, error) {
	var retried bool
	body, err := json.Marshal(req)
	if err != nil {
		return nil, errors.Wrap(err, "client.SSHBastion; error marshaling request")
	}
	u := c.endpoint.ResolveReference(&url.URL{Path: "/ssh/bastion"})
retry:
	resp, err := c.client.PostWithContext(ctx, u.String(), "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) { //nolint:contextcheck // deeply nested context; retry using the same context
			retried = true
			goto retry
		}
		return nil, readError(resp.Body)
	}
	var bastion api.SSHBastionResponse
	if err := readJSON(resp.Body, &bastion); err != nil {
		return nil, errors.Wrapf(err, "client.SSHBastion; error reading %s", u)
	}
	return &bastion, nil
}

// RootFingerprint is a helper method that returns the current root fingerprint.
// It does an health connection and gets the fingerprint from the TLS verified chains.
func (c *Client) RootFingerprint() (string, error) {
	return c.RootFingerprintWithContext(context.Background())
}

// RootFingerprintWithContext is a helper method that returns the current root fingerprint.
// It does an health connection and gets the fingerprint from the TLS verified chains.
func (c *Client) RootFingerprintWithContext(ctx context.Context) (string, error) {
	u := c.endpoint.ResolveReference(&url.URL{Path: "/health"})
	resp, err := c.client.GetWithContext(ctx, u.String())
	if err != nil {
		return "", clientError(err)
	}
	defer resp.Body.Close()
	if resp.TLS == nil || len(resp.TLS.VerifiedChains) == 0 {
		return "", errors.New("missing verified chains")
	}
	lastChain := resp.TLS.VerifiedChains[len(resp.TLS.VerifiedChains)-1]
	if len(lastChain) == 0 {
		return "", errors.New("missing verified chains")
	}
	return x509util.Fingerprint(lastChain[len(lastChain)-1]), nil
}

// CreateSignRequest is a helper function that given an x509 OTT returns a
// simple but secure sign request as well as the private key used.
func CreateSignRequest(ott string) (*api.SignRequest, crypto.PrivateKey, error) {
	token, err := jwt.ParseSigned(ott)
	if err != nil {
		return nil, nil, errors.Wrap(err, "error parsing ott")
	}
	var claims authority.Claims
	if err := token.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, nil, errors.Wrap(err, "error parsing ott")
	}

	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, errors.Wrap(err, "error generating key")
	}

	dnsNames, ips, emails, uris := x509util.SplitSANs(claims.SANs)
	if claims.Email != "" {
		emails = append(emails, claims.Email)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: claims.Subject,
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		DNSNames:           dnsNames,
		IPAddresses:        ips,
		EmailAddresses:     emails,
		URIs:               uris,
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, template, pk)
	if err != nil {
		return nil, nil, errors.Wrap(err, "error creating certificate request")
	}
	cr, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return nil, nil, errors.Wrap(err, "error parsing certificate request")
	}
	if err := cr.CheckSignature(); err != nil {
		return nil, nil, errors.Wrap(err, "error signing certificate request")
	}
	return &api.SignRequest{
		CsrPEM: api.CertificateRequest{CertificateRequest: cr},
		OTT:    ott,
	}, pk, nil
}

// CreateCertificateRequest creates a new CSR with the given common name and
// SANs. If no san is provided the commonName will set also a SAN.
func CreateCertificateRequest(commonName string, sans ...string) (*api.CertificateRequest, crypto.PrivateKey, error) {
	key, err := keyutil.GenerateDefaultKey()
	if err != nil {
		return nil, nil, err
	}
	return createCertificateRequest(commonName, sans, key)
}

// CreateIdentityRequest returns a new CSR to create the identity. If an
// identity was already present it reuses the private key.
func CreateIdentityRequest(commonName string, sans ...string) (*api.CertificateRequest, crypto.PrivateKey, error) {
	var identityKey crypto.PrivateKey
	if i, err := identity.LoadDefaultIdentity(); err == nil && i.Key != "" {
		if k, err := pemutil.Read(i.Key); err == nil {
			identityKey = k
		}
	}
	if identityKey == nil {
		return CreateCertificateRequest(commonName, sans...)
	}
	return createCertificateRequest(commonName, sans, identityKey)
}

// LoadDefaultIdentity is a wrapper for identity.LoadDefaultIdentity.
func LoadDefaultIdentity() (*identity.Identity, error) {
	return identity.LoadDefaultIdentity()
}

// WriteDefaultIdentity is a wrapper for identity.WriteDefaultIdentity.
func WriteDefaultIdentity(certChain []api.Certificate, key crypto.PrivateKey) error {
	return identity.WriteDefaultIdentity(certChain, key)
}

func createCertificateRequest(commonName string, sans []string, key crypto.PrivateKey) (*api.CertificateRequest, crypto.PrivateKey, error) {
	if len(sans) == 0 {
		sans = []string{commonName}
	}
	dnsNames, ips, emails, uris := x509util.SplitSANs(sans)
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		DNSNames:       dnsNames,
		IPAddresses:    ips,
		EmailAddresses: emails,
		URIs:           uris,
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, nil, err
	}
	cr, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return nil, nil, err
	}
	if err := cr.CheckSignature(); err != nil {
		return nil, nil, err
	}

	return &api.CertificateRequest{CertificateRequest: cr}, key, nil
}

// getRootCAPath returns the path where the root CA is stored based on the
// STEPPATH environment variable.
func getRootCAPath() string {
	return filepath.Join(step.Path(), "certs", "root_ca.crt")
}

func readJSON(r io.ReadCloser, v interface{}) error {
	defer r.Close()
	return json.NewDecoder(r).Decode(v)
}

func readProtoJSON(r io.ReadCloser, m proto.Message) error {
	defer r.Close()
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	return protojson.Unmarshal(data, m)
}

func readError(r io.ReadCloser) error {
	defer r.Close()
	apiErr := new(errs.Error)
	if err := json.NewDecoder(r).Decode(apiErr); err != nil {
		return err
	}
	return apiErr
}

func clientError(err error) error {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		return fmt.Errorf("client %s %s failed: %w",
			strings.ToUpper(uerr.Op), uerr.URL, uerr.Err)
	}
	return fmt.Errorf("client request failed: %w", err)
}
