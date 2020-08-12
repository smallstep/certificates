package api

import (
	"net/http"

	"github.com/smallstep/certificates/errs"
)

// RekeyRequest is the request body for a certificate rekey request.
type RekeyRequest struct {
	CsrPEM CertificateRequest `json:"csr"`
}

// Validate checks the fields of the RekeyRequest and returns nil if they are ok
// or an error if something is wrong.
func (s *RekeyRequest) Validate() error {
	if s.CsrPEM.CertificateRequest == nil {
		return errs.BadRequest("missing csr")
	}
	if err := s.CsrPEM.CertificateRequest.CheckSignature(); err != nil {
		return errs.Wrap(http.StatusBadRequest, err, "invalid csr")
	}

	return nil
}

// Rekey is similar to renew except that the certificate will be renewed with new key from csr.
func (h *caHandler) Rekey(w http.ResponseWriter, r *http.Request) {

	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		WriteError(w, errs.BadRequest("missing peer certificate"))
		return
	}

	var body RekeyRequest
	if err := ReadJSON(r.Body, &body); err != nil {
		WriteError(w, errs.Wrap(http.StatusBadRequest, err, "error reading request body"))
		return
	}

	if err := body.Validate(); err != nil {
		WriteError(w, err)
		return
	}

	certChain, err := h.Authority.Rekey(r.TLS.PeerCertificates[0], body.CsrPEM.CertificateRequest.PublicKey)
	if err != nil {
		WriteError(w, errs.Wrap(http.StatusInternalServerError, err, "cahandler.Rekey"))
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
