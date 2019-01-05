package ca

import (
	"crypto/tls"
	"crypto/x509"
)

// TLSOption defines the type of a function that modifies a tls.Config.
type TLSOption func(c *Client, config *tls.Config) error

// setTLSOptions takes one or more option function and applies them in order to
// a tls.Config.
func setTLSOptions(c *Client, config *tls.Config, options []TLSOption) error {
	for _, opt := range options {
		if err := opt(c, config); err != nil {
			return err
		}
	}
	return nil
}

// RequireAndVerifyClientCert is a tls.Config option used on servers to enforce
// a valid TLS client certificate. This is the default option for mTLS servers.
func RequireAndVerifyClientCert() TLSOption {
	return func(_ *Client, config *tls.Config) error {
		config.ClientAuth = tls.RequireAndVerifyClientCert
		return nil
	}
}

// VerifyClientCertIfGiven is a tls.Config option used on on servers to validate
// a TLS client certificate if it is provided. It does not requires a certificate.
func VerifyClientCertIfGiven() TLSOption {
	return func(_ *Client, config *tls.Config) error {
		config.ClientAuth = tls.VerifyClientCertIfGiven
		return nil
	}
}

// AddRootCA adds to the tls.Config RootCAs the given certificate. RootCAs
// defines the set of root certificate authorities that clients use when
// verifying server certificates.
func AddRootCA(cert *x509.Certificate) TLSOption {
	return func(_ *Client, config *tls.Config) error {
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
	return func(_ *Client, config *tls.Config) error {
		if config.ClientCAs == nil {
			config.ClientCAs = x509.NewCertPool()
		}
		config.ClientCAs.AddCert(cert)
		return nil
	}
}

// AddRootFederation does a federation request and adds to the tls.Config
// RootCAs all the certificates in the response. RootCAs
// defines the set of root certificate authorities that clients use when
// verifying server certificates.
func AddRootFederation() TLSOption {
	return func(c *Client, config *tls.Config) error {
		if config.RootCAs == nil {
			config.RootCAs = x509.NewCertPool()
		}
		certs, err := c.Federation(nil)
		if err != nil {
			return err
		}
		for _, cert := range certs.Certificates {
			config.RootCAs.AddCert(cert.Certificate)
		}
		return nil
	}
}

// AddClientFederation does a federation request and adds to the tls.Config
// ClientCAs all the certificates in the response. ClientCAs defines the set of
// root certificate authorities that servers use if required to verify a client
// certificate by the policy in ClientAuth.
func AddClientFederation() TLSOption {
	return func(c *Client, config *tls.Config) error {
		if config.ClientCAs == nil {
			config.ClientCAs = x509.NewCertPool()
		}
		certs, err := c.Federation(nil)
		if err != nil {
			return err
		}
		for _, cert := range certs.Certificates {
			config.ClientCAs.AddCert(cert.Certificate)
		}
		return nil
	}
}
