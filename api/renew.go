package api

import (
	"crypto/x509"
	"net/http"
	"strings"

	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/errs"
)

const (
	authorizationHeader = "Authorization"
	bearerScheme        = "Bearer"
)

// Renew uses the information of certificate in the TLS connection to create a
// new one.
func (h *caHandler) Renew(w http.ResponseWriter, r *http.Request) {
	cert, err := h.getPeerCertificate(r)
	if err != nil {
		render.Error(w, err)
		return
	}

	certChain, err := h.Authority.Renew(cert)
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
		TLSOptions:   h.Authority.GetTLSOptions(),
	}, http.StatusCreated)
}

func (h *caHandler) getPeerCertificate(r *http.Request) (*x509.Certificate, error) {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return r.TLS.PeerCertificates[0], nil
	}
	if s := r.Header.Get(authorizationHeader); s != "" {
		if parts := strings.SplitN(s, bearerScheme+" ", 2); len(parts) == 2 {
			return h.Authority.AuthorizeRenewToken(r.Context(), parts[1])
		}
	}
	return nil, errs.BadRequest("missing client certificate")
}
