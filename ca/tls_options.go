package ca

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"net/http"

	"github.com/smallstep/certificates/api"
)

// TLSOption defines the type of a function that modifies a tls.Config.
type TLSOption func(c *Client, tr http.RoundTripper, config *tls.Config) error

// setTLSOptions takes one or more option function and applies them in order to
// a tls.Config.
func setTLSOptions(c *Client, sign *api.SignResponse, pk crypto.PrivateKey, config *tls.Config, options []TLSOption) error {
	tr, err := getTLSOptionsTransport(sign, pk)
	if err != nil {
		return err
	}

	for _, opt := range options {
		if err := opt(c, tr, config); err != nil {
			return err
		}
	}
	return nil
}

// getTLSOptionsTransport is the transport used by TLSOptions. It is used to get
// root certificates using a mTLS connection with the CA.
func getTLSOptionsTransport(sign *api.SignResponse, pk crypto.PrivateKey) (http.RoundTripper, error) {
	cert, err := TLSCertificate(sign, pk)
	if err != nil {
		return nil, err
	}

	// Build default transport with fixed certificate
	tlsConfig := getDefaultTLSConfig(sign)
	tlsConfig.Certificates = []tls.Certificate{*cert}
	tlsConfig.PreferServerCipherSuites = true
	// Build RootCAs with given root certificate
	if pool := getCertPool(sign); pool != nil {
		tlsConfig.RootCAs = pool
	}

	return getDefaultTransport(tlsConfig)
}

// RequireAndVerifyClientCert is a tls.Config option used on servers to enforce
// a valid TLS client certificate. This is the default option for mTLS servers.
func RequireAndVerifyClientCert() TLSOption {
	return func(_ *Client, _ http.RoundTripper, config *tls.Config) error {
		config.ClientAuth = tls.RequireAndVerifyClientCert
		return nil
	}
}

// VerifyClientCertIfGiven is a tls.Config option used on on servers to validate
// a TLS client certificate if it is provided. It does not requires a certificate.
func VerifyClientCertIfGiven() TLSOption {
	return func(_ *Client, _ http.RoundTripper, config *tls.Config) error {
		config.ClientAuth = tls.VerifyClientCertIfGiven
		return nil
	}
}

// AddRootCA adds to the tls.Config RootCAs the given certificate. RootCAs
// defines the set of root certificate authorities that clients use when
// verifying server certificates.
func AddRootCA(cert *x509.Certificate) TLSOption {
	return func(_ *Client, _ http.RoundTripper, config *tls.Config) error {
		if config.RootCAs == nil {
			config.RootCAs = x509.NewCertPool()
		}
		config.RootCAs.AddCert(cert)
		return nil
	}
}

// AddClientCA adds to the tls.Config ClientCAs the given certificate. ClientCAs
// defines the set of root certificate authorities that servers use if required
// to verify a client certificate by the policy in ClientAuth.
func AddClientCA(cert *x509.Certificate) TLSOption {
	return func(_ *Client, _ http.RoundTripper, config *tls.Config) error {
		if config.ClientCAs == nil {
			config.ClientCAs = x509.NewCertPool()
		}
		config.ClientCAs.AddCert(cert)
		return nil
	}
}

// AddRootsToRootCAs does a roots request and adds to the tls.Config RootCAs all
// the certificates in the response. RootCAs defines the set of root certificate
// authorities that clients use when verifying server certificates.
func AddRootsToRootCAs() TLSOption {
	return func(c *Client, tr http.RoundTripper, config *tls.Config) error {
		certs, err := c.Roots(tr)
		if err != nil {
			return err
		}
		if config.RootCAs == nil {
			config.RootCAs = x509.NewCertPool()
		}
		for _, cert := range certs.Certificates {
			config.RootCAs.AddCert(cert.Certificate)
		}
		return nil
	}
}

// AddRootsToClientCAs does a roots request and adds to the tls.Config ClientCAs
// all the certificates in the response. ClientCAs defines the set of root
// certificate authorities that servers use if required to verify a client
// certificate by the policy in ClientAuth.
func AddRootsToClientCAs() TLSOption {
	return func(c *Client, tr http.RoundTripper, config *tls.Config) error {
		certs, err := c.Roots(tr)
		if err != nil {
			return err
		}
		if config.ClientCAs == nil {
			config.ClientCAs = x509.NewCertPool()
		}
		for _, cert := range certs.Certificates {
			config.ClientCAs.AddCert(cert.Certificate)
		}
		return nil
	}
}

// AddFederationToRootCAs does a federation request and adds to the tls.Config
// RootCAs all the certificates in the response. RootCAs defines the set of root
// certificate authorities that clients use when verifying server certificates.
func AddFederationToRootCAs() TLSOption {
	return func(c *Client, tr http.RoundTripper, config *tls.Config) error {
		certs, err := c.Federation(tr)
		if err != nil {
			return err
		}
		if config.RootCAs == nil {
			config.RootCAs = x509.NewCertPool()
		}
		for _, cert := range certs.Certificates {
			config.RootCAs.AddCert(cert.Certificate)
		}
		return nil
	}
}

// AddFederationToClientCAs does a federation request and adds to the tls.Config
// ClientCAs all the certificates in the response. ClientCAs defines the set of
// root certificate authorities that servers use if required to verify a client
// certificate by the policy in ClientAuth.
func AddFederationToClientCAs() TLSOption {
	return func(c *Client, tr http.RoundTripper, config *tls.Config) error {
		certs, err := c.Federation(tr)
		if err != nil {
			return err
		}
		if config.ClientCAs == nil {
			config.ClientCAs = x509.NewCertPool()
		}
		for _, cert := range certs.Certificates {
			config.ClientCAs.AddCert(cert.Certificate)
		}
		return nil
	}
}
