package est

import (
	"context"
	"crypto/x509"
)

type clientCertificateKey struct{}
type clientCertificateChainKey struct{}

// NewClientCertificateContext stores the TLS client certificate in the context.
func NewClientCertificateContext(ctx context.Context, cert *x509.Certificate) context.Context {
	if cert == nil {
		return ctx
	}
	return context.WithValue(ctx, clientCertificateKey{}, cert)
}

// ClientCertificateFromContext returns the TLS client certificate stored in the context.
func ClientCertificateFromContext(ctx context.Context) (*x509.Certificate, bool) {
	cert, ok := ctx.Value(clientCertificateKey{}).(*x509.Certificate)
	return cert, ok
}

// NewClientCertificateChainContext stores the TLS client certificate chain in the context.
func NewClientCertificateChainContext(ctx context.Context, chain []*x509.Certificate) context.Context {
	if len(chain) == 0 {
		return ctx
	}
	return context.WithValue(ctx, clientCertificateChainKey{}, chain)
}

// ClientCertificateChainFromContext returns the TLS client certificate chain stored in the context.
func ClientCertificateChainFromContext(ctx context.Context) ([]*x509.Certificate, bool) {
	chain, ok := ctx.Value(clientCertificateChainKey{}).([]*x509.Certificate)
	return chain, ok
}
