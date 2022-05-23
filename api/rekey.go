package api

import (
	"net/http"

	"github.com/smallstep/certificates/api/read"
	"github.com/smallstep/certificates/api/render"
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
		return errs.BadRequestErr(err, "invalid csr")
	}

	return nil
}

// Rekey is similar to renew except that the certificate will be renewed with new key from csr.
func Rekey(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		render.Error(w, errs.BadRequest("missing client certificate"))
		return
	}

	var body RekeyRequest
	if err := read.JSON(r.Body, &body); err != nil {
		render.Error(w, errs.BadRequestErr(err, "error reading request body"))
		return
	}

	if err := body.Validate(); err != nil {
		render.Error(w, err)
		return
	}

	a := mustAuthority(r.Context())
	certChain, err := a.Rekey(r.TLS.PeerCertificates[0], body.CsrPEM.CertificateRequest.PublicKey)
	if err != nil {
		render.Error(w, errs.Wrap(http.StatusInternalServerError, err, "cahandler.Rekey"))
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
