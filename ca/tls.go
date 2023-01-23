package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/ca/identity"
)

// mTLSDialContext will hold the dial context function to use in
// getDefaultTransport.
var mTLSDialContext func() func(ctx context.Context, network, address string) (net.Conn, error)

// localAddr is the local address to use when dialing an address. This address
// is defined by the environment variable STEP_CLIENT_ADDR.
var localAddr net.Addr

func init() {
	// STEP_TLS_TUNNEL is an environment variable that can be set to do an TLS
	// over (m)TLS tunnel to step-ca using identity-like credentials. The value
	// is a path to a json file with the tunnel host, certificate, key and root
	// used to create the (m)TLS tunnel.
	//
	// The configuration should look like:
	//  {
	//      "type": "tTLS",
	//      "host": "tunnel.example.com:443"
	//      "crt": "/path/to/tunnel.crt",
	//      "key": "/path/to/tunnel.key",
	//      "root": "/path/to/tunnel-root.crt"
	//  }
	//
	// This feature is EXPERIMENTAL and might change at any time.
	if path := os.Getenv("STEP_TLS_TUNNEL"); path != "" {
		id, err := identity.LoadIdentity(path)
		if err != nil {
			panic(err)
		}
		if err := id.Validate(); err != nil {
			panic(err)
		}
		host, port, err := net.SplitHostPort(id.Host)
		if err != nil {
			panic(err)
		}
		pool, err := id.GetCertPool()
		if err != nil {
			panic(err)
		}
		mTLSDialContext = func() func(ctx context.Context, network, address string) (net.Conn, error) {
			d := &tls.Dialer{
				NetDialer: getDefaultDialer(),
				Config: &tls.Config{
					MinVersion:           tls.VersionTLS12,
					RootCAs:              pool,
					GetClientCertificate: id.GetClientCertificateFunc(),
				},
			}
			return func(ctx context.Context, network, address string) (net.Conn, error) {
				return d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
			}
		}
	}

	// STEP_CLIENT_ADDR is an environment variable that can be set to define the
	// local address to use when dialing an address. This can be useful when
	// step is run behind a CIDR-based ACL.
	//
	// STEP_CLIENT_ADDR can be set to an IP ("127.0.0.1", "[::1]"), a hostname
	// ("localhost"), or a host:port ("[::1]:0"). If the port is set to
	// something other than ":0" and the dialer is created multiple times it
	// will fail with an "address already in use" error.
	//
	// See https://github.com/smallstep/cli/issues/730
	if v := os.Getenv("STEP_CLIENT_ADDR"); v != "" {
		_, _, err := net.SplitHostPort(v)
		if err != nil {
			// assuming that the error is a missing port, if it's not it will
			// panic below.
			v += ":0"
		}
		localAddr, err = net.ResolveTCPAddr("tcp", v)
		if err != nil {
			panic(err)
		}
	}
}

// GetClientTLSConfig returns a tls.Config for client use configured with the
// sign certificate, and a new certificate pool with the sign root certificate.
// The client certificate will automatically rotate before expiring.
func (c *Client) GetClientTLSConfig(ctx context.Context, sign *api.SignResponse, pk crypto.PrivateKey, options ...TLSOption) (*tls.Config, error) {
	tlsConfig, _, err := c.getClientTLSConfig(ctx, sign, pk, options)
	if err != nil {
		return nil, err
	}
	return tlsConfig, nil
}

func (c *Client) getClientTLSConfig(ctx context.Context, sign *api.SignResponse, pk crypto.PrivateKey, options []TLSOption) (*tls.Config, *http.Transport, error) {
	cert, err := TLSCertificate(sign, pk)
	if err != nil {
		return nil, nil, err
	}
	renewer, err := NewTLSRenewer(cert, nil)
	if err != nil {
		return nil, nil, err
	}

	tlsConfig := getDefaultTLSConfig(sign)
	// Note that with GetClientCertificate tlsConfig.Certificates is not used.
	// Without tlsConfig.Certificates there's not need to use tlsConfig.BuildNameToCertificate()
	tlsConfig.GetClientCertificate = renewer.GetClientCertificate

	// Apply options and initialize mutable tls.Config
	tlsCtx := newTLSOptionCtx(c, tlsConfig, sign)
	if err := tlsCtx.apply(options); err != nil {
		return nil, nil, err
	}

	tr := getDefaultTransport(tlsConfig)
	//nolint:staticcheck // Use mutable tls.Config on renew
	tr.DialTLS = c.buildDialTLS(tlsCtx)
	// tr.DialTLSContext = c.buildDialTLSContext(tlsCtx)
	renewer.RenewCertificate = getRenewFunc(tlsCtx, c, tr, pk) //nolint:contextcheck // deeply nested context

	// Update client transport
	c.SetTransport(tr)

	// Start renewer
	renewer.RunContext(ctx)
	return tlsConfig, tr, nil
}

// GetServerTLSConfig returns a tls.Config for server use configured with the
// sign certificate, and a new certificate pool with the sign root certificate.
// The returned tls.Config will only verify the client certificate if provided.
// The server certificate will automatically rotate before expiring.
func (c *Client) GetServerTLSConfig(ctx context.Context, sign *api.SignResponse, pk crypto.PrivateKey, options ...TLSOption) (*tls.Config, error) {
	cert, err := TLSCertificate(sign, pk)
	if err != nil {
		return nil, err
	}
	renewer, err := NewTLSRenewer(cert, nil)
	if err != nil {
		return nil, err
	}

	tlsConfig := getDefaultTLSConfig(sign)
	// Note that GetCertificate will only be called if the client supplies SNI
	// information or if tlsConfig.Certificates is empty.
	// Without tlsConfig.Certificates there's not need to use tlsConfig.BuildNameToCertificate()
	tlsConfig.GetCertificate = renewer.GetCertificate
	tlsConfig.GetClientCertificate = renewer.GetClientCertificate
	tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert

	// Apply options and initialize mutable tls.Config
	tlsCtx := newTLSOptionCtx(c, tlsConfig, sign)
	if err := tlsCtx.apply(options); err != nil {
		return nil, err
	}

	// GetConfigForClient allows seamless root and federated roots rotation.
	// If the return of the callback is not-nil, it will use the returned
	// tls.Config instead of the default one.
	tlsConfig.GetConfigForClient = c.buildGetConfigForClient(tlsCtx)

	// Update renew function with transport
	tr := getDefaultTransport(tlsConfig)
	//nolint:staticcheck // Use mutable tls.Config on renew
	tr.DialTLS = c.buildDialTLS(tlsCtx)
	// tr.DialTLSContext = c.buildDialTLSContext(tlsCtx)
	renewer.RenewCertificate = getRenewFunc(tlsCtx, c, tr, pk) //nolint:contextcheck // deeply nested context

	// Update client transport
	c.SetTransport(tr)

	// Start renewer
	renewer.RunContext(ctx)
	return tlsConfig, nil
}

// Transport returns an http.Transport configured to use the client certificate from the sign response.
func (c *Client) Transport(ctx context.Context, sign *api.SignResponse, pk crypto.PrivateKey, options ...TLSOption) (*http.Transport, error) {
	_, tr, err := c.getClientTLSConfig(ctx, sign, pk, options)
	if err != nil {
		return nil, err
	}
	return tr, nil
}

// buildGetConfigForClient returns an implementation of GetConfigForClient
// callback in tls.Config.
//
// If the implementation returns a nil tls.Config, the original Config will be
// used, but if it's non-nil, the returned Config will be used to handle this
// connection.
func (c *Client) buildGetConfigForClient(ctx *TLSOptionCtx) func(*tls.ClientHelloInfo) (*tls.Config, error) {
	return func(*tls.ClientHelloInfo) (*tls.Config, error) {
		return ctx.mutableConfig.TLSConfig(), nil
	}
}

// buildDialTLS returns an implementation of DialTLS callback in http.Transport.
func (c *Client) buildDialTLS(ctx *TLSOptionCtx) func(network, addr string) (net.Conn, error) {
	return func(network, addr string) (net.Conn, error) {
		return tls.DialWithDialer(getDefaultDialer(), network, addr, ctx.mutableConfig.TLSConfig())
	}
}

//nolint:unused // buildDialTLSContext returns an implementation of DialTLSContext callback in http.Transport.
func (c *Client) buildDialTLSContext(tlsCtx *TLSOptionCtx) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		d := getDefaultDialer()
		// TLS dialers do not support context, but we can use the context
		// deadline if it is set.
		if t, ok := ctx.Deadline(); ok {
			d.Deadline = t
		}
		return tls.DialWithDialer(d, network, addr, tlsCtx.mutableConfig.TLSConfig())
	}
}

// Certificate returns the server or client certificate from the sign response.
func Certificate(sign *api.SignResponse) (*x509.Certificate, error) {
	if sign.ServerPEM.Certificate == nil {
		return nil, errors.New("ca: certificate does not exist")
	}
	return sign.ServerPEM.Certificate, nil
}

// IntermediateCertificate returns the CA intermediate certificate from the sign
// response.
func IntermediateCertificate(sign *api.SignResponse) (*x509.Certificate, error) {
	if sign.CaPEM.Certificate == nil {
		return nil, errors.New("ca: certificate does not exist")
	}
	return sign.CaPEM.Certificate, nil
}

// RootCertificate returns the root certificate from the sign response.
func RootCertificate(sign *api.SignResponse) (*x509.Certificate, error) {
	if sign == nil || sign.TLS == nil || len(sign.TLS.VerifiedChains) == 0 {
		return nil, errors.New("ca: certificate does not exist")
	}
	lastChain := sign.TLS.VerifiedChains[len(sign.TLS.VerifiedChains)-1]
	if len(lastChain) == 0 {
		return nil, errors.New("ca: certificate does not exist")
	}
	return lastChain[len(lastChain)-1], nil
}

// TLSCertificate creates a new TLS certificate from the sign response and the
// private key used.
func TLSCertificate(sign *api.SignResponse, pk crypto.PrivateKey) (*tls.Certificate, error) {
	certPEM, err := getPEM(sign.ServerPEM)
	if err != nil {
		return nil, err
	}
	caPEM, err := getPEM(sign.CaPEM)
	if err != nil {
		return nil, err
	}
	keyPEM, err := getPEM(pk)
	if err != nil {
		return nil, err
	}

	//nolint:gocritic // using a new variable for clarity
	chain := append(certPEM, caPEM...)
	cert, err := tls.X509KeyPair(chain, keyPEM)
	if err != nil {
		return nil, errors.Wrap(err, "error creating tls certificate")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, errors.Wrap(err, "error parsing tls certificate")
	}
	cert.Leaf = leaf
	return &cert, nil
}

func getDefaultTLSConfig(sign *api.SignResponse) *tls.Config {
	if sign.TLSOptions != nil {
		return sign.TLSOptions.TLSConfig()
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
}

// getDefaultDialer returns a new dialer with the default configuration.
func getDefaultDialer() *net.Dialer {
	// With the KeepAlive parameter set to 0, it will be use Golang's default.
	return &net.Dialer{
		Timeout:   30 * time.Second,
		LocalAddr: localAddr,
	}
}

// getDefaultTransport returns an http.Transport with the same parameters than
// http.DefaultTransport, but adds the given tls.Config and configures the
// transport for HTTP/2.
func getDefaultTransport(tlsConfig *tls.Config) *http.Transport {
	var dialContext func(ctx context.Context, network string, addr string) (net.Conn, error)
	switch {
	case runtime.GOOS == "js" && runtime.GOARCH == "wasm":
		// when running in js/wasm and using the default dialer context all requests
		// performed by the CA client resulted in a "protocol not supported" error.
		// By setting the dial context to nil requests will be handled by the browser
		// fetch API instead. Currently this will always set the dial context to nil,
		// but we could implement some additional logic similar to what's found in
		// https://github.com/golang/go/pull/46923/files to support a different dial
		// context if it is available, required and expected to work.
		dialContext = nil
	case mTLSDialContext == nil:
		d := getDefaultDialer()
		dialContext = d.DialContext
	default:
		dialContext = mTLSDialContext()
	}
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       tlsConfig,
	}
}

func getPEM(i interface{}) ([]byte, error) {
	block := new(pem.Block)
	switch i := i.(type) {
	case api.Certificate:
		block.Type = "CERTIFICATE"
		block.Bytes = i.Raw
	case *x509.Certificate:
		block.Type = "CERTIFICATE"
		block.Bytes = i.Raw
	case *rsa.PrivateKey:
		block.Type = "RSA PRIVATE KEY"
		block.Bytes = x509.MarshalPKCS1PrivateKey(i)
	case *ecdsa.PrivateKey:
		var err error
		block.Type = "EC PRIVATE KEY"
		block.Bytes, err = x509.MarshalECPrivateKey(i)
		if err != nil {
			return nil, errors.Wrap(err, "error marshaling private key")
		}
	case ed25519.PrivateKey:
		var err error
		block.Type = "PRIVATE KEY"
		block.Bytes, err = x509.MarshalPKCS8PrivateKey(i)
		if err != nil {
			return nil, errors.Wrap(err, "error marshaling private key")
		}
	default:
		return nil, errors.Errorf("unsupported key type %T", i)
	}
	return pem.EncodeToMemory(block), nil
}

func getRenewFunc(ctx *TLSOptionCtx, client *Client, tr *http.Transport, pk crypto.PrivateKey) RenewFunc {
	return func() (*tls.Certificate, error) {
		// Get updated list of roots
		if err := ctx.applyRenew(); err != nil {
			return nil, err
		}
		// Get new certificate
		sign, err := client.Renew(tr)
		if err != nil {
			return nil, err
		}
		return TLSCertificate(sign, pk)
	}
}
