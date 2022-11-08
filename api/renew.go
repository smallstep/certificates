package api

import (
	"crypto/x509"
	"net/http"
	"strings"

	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/errs"
)

const (
	authorizationHeader = "Authorization"
	bearerScheme        = "Bearer"
)

// Renew uses the information of certificate in the TLS connection to create a
// new one.
func Renew(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get the leaf certificate from the peer or the token.
	cert, token, err := getPeerCertificate(r)
	if err != nil {
		render.Error(w, err)
		return
	}

	// The token can be used by RAs to renew a certificate.
	if token != "" {
		ctx = authority.NewTokenContext(ctx, token)
	}

	a := mustAuthority(ctx)
	certChain, err := a.RenewContext(ctx, cert, nil)
	if err != nil {
		render.Error(w, errs.Wrap(http.StatusInternalServerError, err, "cahandler.Renew"))
		return
	}
	certChainPEM := certChainToPEM(certChain)
	var caPEM Certificate
	if len(certChainPEM) > 1 {
		caPEM = certChainPEM[1]
	}

	LogCertificate(w, certChain[0])
	render.JSONStatus(w, &SignResponse{
		ServerPEM:    certChainPEM[0],
		CaPEM:        caPEM,
		CertChainPEM: certChainPEM,
		TLSOptions:   a.GetTLSOptions(),
	}, http.StatusCreated)
}

func getPeerCertificate(r *http.Request) (*x509.Certificate, string, error) {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return r.TLS.PeerCertificates[0], "", nil
	}
	if s := r.Header.Get(authorizationHeader); s != "" {
		if parts := strings.SplitN(s, bearerScheme+" ", 2); len(parts) == 2 {
			ctx := r.Context()
			peer, err := mustAuthority(ctx).AuthorizeRenewToken(ctx, parts[1])
			return peer, parts[1], err
		}
	}
	return nil, "", errs.BadRequest("missing client certificate")
}
