package ca

import (
	"bytes"
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
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/ca-component/api"
	"golang.org/x/net/http2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// ClientOption is the type of options passed to the Client constructor.
type ClientOption func(o *clientOptions) error

type clientOptions struct {
	transport    http.RoundTripper
	rootSHA256   string
	rootFilename string
}

func (o *clientOptions) apply(opts []ClientOption) (err error) {
	for _, fn := range opts {
		if err = fn(o); err != nil {
			return
		}
	}
	return
}

// checkTransport checks if other ways to set up a transport have been provided.
// If they have it returns an error.
func (o *clientOptions) checkTransport() error {
	if o.transport != nil || o.rootFilename != "" || o.rootSHA256 != "" {
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
	if tr == nil {
		return nil, errors.New("a transport, a root cert, or a root sha256 must be used")
	}
	return tr, nil
}

// WithTransport adds a custom transport to the Client. If the transport is
// given is given it will have preference over WithRootFile and WithRootSHA256.
func WithTransport(tr http.RoundTripper) ClientOption {
	return func(o *clientOptions) error {
		if err := o.checkTransport(); err != nil {
			return err
		}
		o.transport = tr
		return nil
	}
}

// WithRootFile will create the transport using the given root certificate. If
// the root file is given it will have preference over WithRootSHA256, but less
// preference than WithTransport.
func WithRootFile(filename string) ClientOption {
	return func(o *clientOptions) error {
		if err := o.checkTransport(); err != nil {
			return err
		}
		o.rootFilename = filename
		return nil
	}
}

// WithRootSHA256 will create the transport using an insecure client to retrieve the
// root certificate. It has less preference than WithTransport and WithRootFile.
func WithRootSHA256(sum string) ClientOption {
	return func(o *clientOptions) error {
		if err := o.checkTransport(); err != nil {
			return err
		}
		o.rootSHA256 = sum
		return nil
	}
}

func getTransportFromFile(filename string) (http.RoundTripper, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading %s", filename)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.Errorf("error decoding %s", filename)
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing %s", filename)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return getDefaultTransport(&tls.Config{
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		RootCAs:                  pool,
	})
}

func getTransportFromSHA256(endpoint, sum string) (http.RoundTripper, error) {
	client, err := NewClient(endpoint)
	if err != nil {
		return nil, err
	}
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
	})
}

// Client implements an HTTP client for the CA server.
type Client struct {
	client   *http.Client
	endpoint *url.URL
	certPool *x509.CertPool
}

// NewClient creates a new Client with the given endpoint and options.
func NewClient(endpoint string, opts ...ClientOption) (*Client, error) {
	// Validate endpoint
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing endpoint")
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, errors.New("error parsing endpoint: url is not valid")
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

	var cp *x509.CertPool
	switch tr := tr.(type) {
	case *http.Transport:
		if tr.TLSClientConfig != nil && tr.TLSClientConfig.RootCAs != nil {
			cp = tr.TLSClientConfig.RootCAs
		}
	case *http2.Transport:
		if tr.TLSClientConfig != nil && tr.TLSClientConfig.RootCAs != nil {
			cp = tr.TLSClientConfig.RootCAs
		}
	}
	return &Client{
		client: &http.Client{
			Transport: tr,
		},
		endpoint: u,
		certPool: cp,
	}, nil
}

// Health performs the health request to the CA and returns the
// api.HealthResponse struct.
func (c *Client) Health() (*api.HealthResponse, error) {
	u := c.endpoint.ResolveReference(&url.URL{Path: "/health"})
	resp, err := c.client.Get(u.String())
	if err != nil {
		return nil, errors.Wrapf(err, "client GET %s failed", u)
	}
	if resp.StatusCode >= 400 {
		return nil, readError(resp.Body)
	}
	var health api.HealthResponse
	if err := readJSON(resp.Body, &health); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	return &health, nil
}

// Root performs the root request to the CA with the given SHA256 and returns
// the api.RootResponse struct. It uses an insecure client, but it checks the
// resulting root certificate with the given SHA256, returning an error if they
// do not match.
func (c *Client) Root(sha256Sum string) (*api.RootResponse, error) {
	sha256Sum = strings.ToLower(strings.Replace(sha256Sum, "-", "", -1))
	u := c.endpoint.ResolveReference(&url.URL{Path: "/root/" + sha256Sum})
	resp, err := getInsecureClient().Get(u.String())
	if err != nil {
		return nil, errors.Wrapf(err, "client GET %s failed", u)
	}
	if resp.StatusCode >= 400 {
		return nil, readError(resp.Body)
	}
	var root api.RootResponse
	if err := readJSON(resp.Body, &root); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	// verify the sha256
	sum := sha256.Sum256(root.RootPEM.Raw)
	if sha256Sum != strings.ToLower(hex.EncodeToString(sum[:])) {
		return nil, errors.New("root certificate SHA256 fingerprint do not match")
	}
	return &root, nil
}

// Sign performs the sign request to the CA and returns the api.SignResponse
// struct.
func (c *Client) Sign(req *api.SignRequest) (*api.SignResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling request")
	}
	u := c.endpoint.ResolveReference(&url.URL{Path: "/sign"})
	resp, err := c.client.Post(u.String(), "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, errors.Wrapf(err, "client POST %s failed", u)
	}
	if resp.StatusCode >= 400 {
		return nil, readError(resp.Body)
	}
	var sign api.SignResponse
	if err := readJSON(resp.Body, &sign); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	// Add tls.ConnectionState:
	// We'll extract the root certificate from the verified chains
	sign.TLS = resp.TLS
	return &sign, nil
}

// Renew performs the renew request to the CA and returns the api.SignResponse
// struct.
func (c *Client) Renew(tr http.RoundTripper) (*api.SignResponse, error) {
	u := c.endpoint.ResolveReference(&url.URL{Path: "/renew"})
	client := &http.Client{Transport: tr}
	resp, err := client.Post(u.String(), "application/json", http.NoBody)
	if err != nil {
		return nil, errors.Wrapf(err, "client POST %s failed", u)
	}
	if resp.StatusCode >= 400 {
		return nil, readError(resp.Body)
	}
	var sign api.SignResponse
	if err := readJSON(resp.Body, &sign); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	return &sign, nil
}

// Provisioners performs the provisioners request to the CA and returns the
// api.ProvisionersResponse struct with a map of provisioners.
func (c *Client) Provisioners() (*api.ProvisionersResponse, error) {
	u := c.endpoint.ResolveReference(&url.URL{Path: "/provisioners"})
	resp, err := c.client.Get(u.String())
	if err != nil {
		return nil, errors.Wrapf(err, "client GET %s failed", u)
	}
	if resp.StatusCode >= 400 {
		return nil, readError(resp.Body)
	}
	var provisioners api.ProvisionersResponse
	if err := readJSON(resp.Body, &provisioners); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	return &provisioners, nil
}

// ProvisionerKey performs the request to the CA to get the encrypted key for
// the given provisioner kid and returns the api.ProvisionerKeyResponse struct
// with the encrypted key.
func (c *Client) ProvisionerKey(kid string) (*api.ProvisionerKeyResponse, error) {
	u := c.endpoint.ResolveReference(&url.URL{Path: "/provisioners/" + kid + "/encrypted-key"})
	resp, err := c.client.Get(u.String())
	if err != nil {
		return nil, errors.Wrapf(err, "client GET %s failed", u)
	}
	if resp.StatusCode >= 400 {
		return nil, readError(resp.Body)
	}
	var key api.ProvisionerKeyResponse
	if err := readJSON(resp.Body, &key); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	return &key, nil
}

// CreateSignRequest is a helper function that given an x509 OTT returns a
// simple but secure sign request as well as the private key used.
func CreateSignRequest(ott string) (*api.SignRequest, crypto.PrivateKey, error) {
	token, err := jwt.ParseSigned(ott)
	if err != nil {
		return nil, nil, errors.Wrap(err, "error parsing ott")
	}
	var claims jwt.Claims
	if err := token.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, nil, errors.Wrap(err, "error parsing ott")
	}

	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, errors.Wrap(err, "error generating key")
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: claims.Subject,
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		DNSNames:           []string{claims.Subject},
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

func getInsecureClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

func readJSON(r io.ReadCloser, v interface{}) error {
	defer r.Close()
	return json.NewDecoder(r).Decode(v)
}

func readError(r io.ReadCloser) error {
	defer r.Close()
	apiErr := new(api.Error)
	if err := json.NewDecoder(r).Decode(apiErr); err != nil {
		return err
	}
	return apiErr
}
