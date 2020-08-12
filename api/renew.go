package api

import (
	"net/http"

	"github.com/smallstep/certificates/errs"
)

// Renew uses the information of certificate in the TLS connection to create a
// new one.
func (h *caHandler) Renew(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		WriteError(w, errs.BadRequest("missing peer certificate"))
		return
	}

	certChain, err := h.Authority.Renew(r.TLS.PeerCertificates[0])
	if err != nil {
		WriteError(w, errs.Wrap(http.StatusInternalServerError, err, "cahandler.Renew"))
		return
	}
	certChainPEM := certChainToPEM(certChain)
	var caPEM Certificate
	if len(certChainPEM) > 1 {
		caPEM = certChainPEM[1]
	}

	LogCertificate(w, certChain[0])
	JSONStatus(w, &SignResponse{
		ServerPEM:    certChainPEM[0],
		CaPEM:        caPEM,
		CertChainPEM: certChainPEM,
		TLSOptions:   h.Authority.GetTLSOptions(),
	}, http.StatusCreated)
}
