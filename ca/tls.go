package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/api"
	"golang.org/x/net/http2"
)

// GetClientTLSConfig returns a tls.Config for client use configured with the
// sign certificate, and a new certificate pool with the sign root certificate.
// The client certificate will automatically rotate before expiring.
func (c *Client) GetClientTLSConfig(ctx context.Context, sign *api.SignResponse, pk crypto.PrivateKey, options ...TLSOption) (*tls.Config, error) {
	cert, err := TLSCertificate(sign, pk)
	if err != nil {
		return nil, err
	}
	renewer, err := NewTLSRenewer(cert, nil)
	if err != nil {
		return nil, err
	}

	tlsConfig := getDefaultTLSConfig(sign)
	// Note that with GetClientCertificate tlsConfig.Certificates is not used.
	// Without tlsConfig.Certificates there's not need to use tlsConfig.BuildNameToCertificate()
	tlsConfig.GetClientCertificate = renewer.GetClientCertificate
	tlsConfig.PreferServerCipherSuites = true
	// Build RootCAs with given root certificate
	if pool := getCertPool(sign); pool != nil {
		tlsConfig.RootCAs = pool
	}

	// Apply options if given
	if err := setTLSOptions(tlsConfig, options); err != nil {
		return nil, err
	}

	// Update renew function with transport
	tr, err := getDefaultTransport(tlsConfig)
	if err != nil {
		return nil, err
	}
	renewer.RenewCertificate = getRenewFunc(c, tr, pk)

	// Start renewer
	renewer.RunContext(ctx)
	return tlsConfig, nil
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
	tlsConfig.PreferServerCipherSuites = true
	// Build RootCAs with given root certificate
	if pool := getCertPool(sign); pool != nil {
		tlsConfig.ClientCAs = pool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		// Add RootCAs for refresh client
		tlsConfig.RootCAs = pool
	}

	// Apply options if given
	if err := setTLSOptions(tlsConfig, options); err != nil {
		return nil, err
	}

	// Update renew function with transport
	tr, err := getDefaultTransport(tlsConfig)
	if err != nil {
		return nil, err
	}
	renewer.RenewCertificate = getRenewFunc(c, tr, pk)

	// Start renewer
	renewer.RunContext(ctx)
	return tlsConfig, nil
}

// Transport returns an http.Transport configured to use the client certificate from the sign response.
func (c *Client) Transport(ctx context.Context, sign *api.SignResponse, pk crypto.PrivateKey, options ...TLSOption) (*http.Transport, error) {
	tlsConfig, err := c.GetClientTLSConfig(ctx, sign, pk, options...)
	if err != nil {
		return nil, err
	}
	return getDefaultTransport(tlsConfig)
}

// Certificate returns the server or client certificate from the sign response.
func Certificate(sign *api.SignResponse) (*x509.Certificate, error) {
	if sign.ServerPEM.Certificate == nil {
		return nil, errors.New("ca: certificate does not exists")
	}
	return sign.ServerPEM.Certificate, nil
}

// IntermediateCertificate returns the CA intermediate certificate from the sign
// response.
func IntermediateCertificate(sign *api.SignResponse) (*x509.Certificate, error) {
	if sign.CaPEM.Certificate == nil {
		return nil, errors.New("ca: certificate does not exists")
	}
	return sign.CaPEM.Certificate, nil
}

// RootCertificate returns the root certificate from the sign response.
func RootCertificate(sign *api.SignResponse) (*x509.Certificate, error) {
	if sign.TLS == nil || len(sign.TLS.VerifiedChains) == 0 {
		return nil, errors.New("ca: certificate does not exists")
	}
	lastChain := sign.TLS.VerifiedChains[len(sign.TLS.VerifiedChains)-1]
	if len(lastChain) == 0 {
		return nil, errors.New("ca: certificate does not exists")
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

// getCertPool returns the transport x509.CertPool or the one from the sign
// request.
func getCertPool(sign *api.SignResponse) *x509.CertPool {
	if root, err := RootCertificate(sign); err == nil {
		pool := x509.NewCertPool()
		pool.AddCert(root)
		return pool
	}
	return nil
}

func getDefaultTLSConfig(sign *api.SignResponse) *tls.Config {
	if sign.TLSOptions != nil {
		return sign.TLSOptions.TLSConfig()
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
}

// getDefaultTransport returns an http.Transport with the same parameters than
// http.DefaultTransport, but adds the given tls.Config and configures the
// transport for HTTP/2.
func getDefaultTransport(tlsConfig *tls.Config) (*http.Transport, error) {
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       tlsConfig,
	}
	if err := http2.ConfigureTransport(tr); err != nil {
		return nil, errors.Wrap(err, "error configuring transport")
	}
	return tr, nil
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
	default:
		return nil, errors.Errorf("unsupported key type %T", i)
	}
	return pem.EncodeToMemory(block), nil
}

func getRenewFunc(client *Client, tr *http.Transport, pk crypto.PrivateKey) RenewFunc {
	return func() (*tls.Certificate, error) {
		sign, err := client.Renew(tr)
		if err != nil {
			return nil, err
		}
		return TLSCertificate(sign, pk)
	}
}
