package ca

import (
	"crypto/tls"
	"crypto/x509"
)

// TLSOption defines the type of a function that modifies a tls.Config.
type TLSOption func(c *tls.Config) error

// setTLSOptions takes one or more option function and applies them in order to
// a tls.Config.
func setTLSOptions(c *tls.Config, options []TLSOption) error {
	for _, opt := range options {
		if err := opt(c); err != nil {
			return err
		}
	}
	return nil
}

// RequireAndVerifyClientCert is a tls.Config option used on servers to enforce
// a valid TLS client certificate. This is the default option for mTLS servers.
func RequireAndVerifyClientCert() TLSOption {
	return func(c *tls.Config) error {
		c.ClientAuth = tls.RequireAndVerifyClientCert
		return nil
	}
}

// VerifyClientCertIfGiven is a tls.Config option used on on servers to validate
// a TLS client certificate if it is provided. It does not requires a certificate.
func VerifyClientCertIfGiven() TLSOption {
	return func(c *tls.Config) error {
		c.ClientAuth = tls.VerifyClientCertIfGiven
		return nil
	}
}

// AddRootCA adds to the tls.Config RootCAs the given certificate. RootCAs
// defines the set of root certificate authorities that clients use when
// verifying server certificates.
func AddRootCA(cert *x509.Certificate) TLSOption {
	return func(c *tls.Config) error {
		if c.RootCAs == nil {
			c.RootCAs = x509.NewCertPool()
		}
		c.RootCAs.AddCert(cert)
		return nil
	}
}

// AddClientCA adds to the tls.Config ClientCAs the given certificate. ClientCAs
// defines the set of root certificate authorities that servers use if required
// to verify a client certificate by the policy in ClientAuth.
func AddClientCA(cert *x509.Certificate) TLSOption {
	return func(c *tls.Config) error {
		if c.ClientCAs == nil {
			c.ClientCAs = x509.NewCertPool()
		}
		c.ClientCAs.AddCert(cert)
		return nil
	}
}
