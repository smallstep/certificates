package ca

import (
	"crypto/tls"
	"crypto/x509"
)

// TLSOption defines the type of a function that modifies a tls.Config.
type TLSOption func(ctx *TLSOptionCtx) error

// TLSOptionCtx is the context modified on TLSOption methods.
type TLSOptionCtx struct {
	Client      *Client
	Config      *tls.Config
	OnRenewFunc []TLSOption
}

// newTLSOptionCtx creates the TLSOption context.
func newTLSOptionCtx(c *Client, config *tls.Config) *TLSOptionCtx {
	return &TLSOptionCtx{
		Client: c,
		Config: config,
	}
}

func (ctx *TLSOptionCtx) apply(options []TLSOption) error {
	for _, fn := range options {
		if err := fn(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (ctx *TLSOptionCtx) applyRenew() error {
	for _, fn := range ctx.OnRenewFunc {
		if err := fn(ctx); err != nil {
			return err
		}
	}
	return nil
}

// RequireAndVerifyClientCert is a tls.Config option used on servers to enforce
// a valid TLS client certificate. This is the default option for mTLS servers.
func RequireAndVerifyClientCert() TLSOption {
	return func(ctx *TLSOptionCtx) error {
		ctx.Config.ClientAuth = tls.RequireAndVerifyClientCert
		return nil
	}
}

// VerifyClientCertIfGiven is a tls.Config option used on on servers to validate
// a TLS client certificate if it is provided. It does not requires a certificate.
func VerifyClientCertIfGiven() TLSOption {
	return func(ctx *TLSOptionCtx) error {
		ctx.Config.ClientAuth = tls.VerifyClientCertIfGiven
		return nil
	}
}

// AddRootCA adds to the tls.Config RootCAs the given certificate. RootCAs
// defines the set of root certificate authorities that clients use when
// verifying server certificates.
func AddRootCA(cert *x509.Certificate) TLSOption {
	return func(ctx *TLSOptionCtx) error {
		if ctx.Config.RootCAs == nil {
			ctx.Config.RootCAs = x509.NewCertPool()
		}
		ctx.Config.RootCAs.AddCert(cert)
		return nil
	}
}

// AddClientCA adds to the tls.Config ClientCAs the given certificate. ClientCAs
// defines the set of root certificate authorities that servers use if required
// to verify a client certificate by the policy in ClientAuth.
func AddClientCA(cert *x509.Certificate) TLSOption {
	return func(ctx *TLSOptionCtx) error {
		if ctx.Config.ClientCAs == nil {
			ctx.Config.ClientCAs = x509.NewCertPool()
		}
		ctx.Config.ClientCAs.AddCert(cert)
		return nil
	}
}

// AddRootsToRootCAs does a roots request and adds to the tls.Config RootCAs all
// the certificates in the response. RootCAs defines the set of root certificate
// authorities that clients use when verifying server certificates.
//
// BootstrapServer and BootstrapClient methods include this option by default.
func AddRootsToRootCAs() TLSOption {
	fn := func(ctx *TLSOptionCtx) error {
		certs, err := ctx.Client.Roots()
		if err != nil {
			return err
		}
		if ctx.Config.RootCAs == nil {
			ctx.Config.RootCAs = x509.NewCertPool()
		}
		for _, cert := range certs.Certificates {
			ctx.Config.RootCAs.AddCert(cert.Certificate)
		}
		return nil
	}
	return func(ctx *TLSOptionCtx) error {
		ctx.OnRenewFunc = append(ctx.OnRenewFunc, fn)
		return fn(ctx)
	}
}

// AddRootsToClientCAs does a roots request and adds to the tls.Config ClientCAs
// all the certificates in the response. ClientCAs defines the set of root
// certificate authorities that servers use if required to verify a client
// certificate by the policy in ClientAuth.
//
// BootstrapServer method includes this option by default.
func AddRootsToClientCAs() TLSOption {
	fn := func(ctx *TLSOptionCtx) error {
		certs, err := ctx.Client.Roots()
		if err != nil {
			return err
		}
		if ctx.Config.ClientCAs == nil {
			ctx.Config.ClientCAs = x509.NewCertPool()
		}
		for _, cert := range certs.Certificates {
			ctx.Config.ClientCAs.AddCert(cert.Certificate)
		}
		return nil
	}
	return func(ctx *TLSOptionCtx) error {
		ctx.OnRenewFunc = append(ctx.OnRenewFunc, fn)
		return fn(ctx)
	}
}

// AddFederationToRootCAs does a federation request and adds to the tls.Config
// RootCAs all the certificates in the response. RootCAs defines the set of root
// certificate authorities that clients use when verifying server certificates.
func AddFederationToRootCAs() TLSOption {
	fn := func(ctx *TLSOptionCtx) error {
		certs, err := ctx.Client.Federation()
		if err != nil {
			return err
		}
		if ctx.Config.RootCAs == nil {
			ctx.Config.RootCAs = x509.NewCertPool()
		}
		for _, cert := range certs.Certificates {
			ctx.Config.RootCAs.AddCert(cert.Certificate)
		}
		return nil
	}
	return func(ctx *TLSOptionCtx) error {
		ctx.OnRenewFunc = append(ctx.OnRenewFunc, fn)
		return fn(ctx)
	}
}

// AddFederationToClientCAs does a federation request and adds to the tls.Config
// ClientCAs all the certificates in the response. ClientCAs defines the set of
// root certificate authorities that servers use if required to verify a client
// certificate by the policy in ClientAuth.
func AddFederationToClientCAs() TLSOption {
	fn := func(ctx *TLSOptionCtx) error {
		certs, err := ctx.Client.Federation()
		if err != nil {
			return err
		}
		if ctx.Config.ClientCAs == nil {
			ctx.Config.ClientCAs = x509.NewCertPool()
		}
		for _, cert := range certs.Certificates {
			ctx.Config.ClientCAs.AddCert(cert.Certificate)
		}
		return nil
	}
	return func(ctx *TLSOptionCtx) error {
		ctx.OnRenewFunc = append(ctx.OnRenewFunc, fn)
		return fn(ctx)
	}
}

// AddRootsToCAs does a roots request and adds the resulting certs to the
// tls.Config RootCAs and ClientCAs. Combines the functionality of
// AddRootsToRootCAs and AddRootsToClientCAs.
func AddRootsToCAs() TLSOption {
	fn := func(ctx *TLSOptionCtx) error {
		certs, err := ctx.Client.Roots()
		if err != nil {
			return err
		}
		if ctx.Config.ClientCAs == nil {
			ctx.Config.ClientCAs = x509.NewCertPool()
		}
		if ctx.Config.RootCAs == nil {
			ctx.Config.RootCAs = x509.NewCertPool()
		}
		for _, cert := range certs.Certificates {
			ctx.Config.ClientCAs.AddCert(cert.Certificate)
			ctx.Config.RootCAs.AddCert(cert.Certificate)
		}
		return nil
	}
	return func(ctx *TLSOptionCtx) error {
		ctx.OnRenewFunc = append(ctx.OnRenewFunc, fn)
		return fn(ctx)
	}
}

// AddFederationToCAs does a federation request and adds the resulting certs to the
// tls.Config RootCAs and ClientCAs. Combines the functionality of
// AddFederationToRootCAs and AddFederationToClientCAs.
func AddFederationToCAs() TLSOption {
	fn := func(ctx *TLSOptionCtx) error {
		certs, err := ctx.Client.Federation()
		if err != nil {
			return err
		}
		if ctx.Config.ClientCAs == nil {
			ctx.Config.ClientCAs = x509.NewCertPool()
		}
		if ctx.Config.RootCAs == nil {
			ctx.Config.RootCAs = x509.NewCertPool()
		}
		for _, cert := range certs.Certificates {
			ctx.Config.ClientCAs.AddCert(cert.Certificate)
			ctx.Config.RootCAs.AddCert(cert.Certificate)
		}
		return nil
	}
	return func(ctx *TLSOptionCtx) error {
		ctx.OnRenewFunc = append(ctx.OnRenewFunc, fn)
		return fn(ctx)
	}
}
