package api

import (
	"crypto/tls"
	"net/http"

	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/errs"
	"github.com/smallstep/cli/crypto/tlsutil"
)

// SignRequest is the request body for a certificate signature request.
type SignRequest struct {
	CsrPEM    CertificateRequest `json:"csr"`
	OTT       string             `json:"ott"`
	NotAfter  TimeDuration       `json:"notAfter"`
	NotBefore TimeDuration       `json:"notBefore"`
}

// Validate checks the fields of the SignRequest and returns nil if they are ok
// or an error if something is wrong.
func (s *SignRequest) Validate() error {
	if s.CsrPEM.CertificateRequest == nil {
		return errs.BadRequest("missing csr")
	}
	if err := s.CsrPEM.CertificateRequest.CheckSignature(); err != nil {
		return errs.Wrap(http.StatusBadRequest, err, "invalid csr")
	}
	if s.OTT == "" {
		return errs.BadRequest("missing ott")
	}

	return nil
}

// SignResponse is the response object of the certificate signature request.
type SignResponse struct {
	ServerPEM    Certificate          `json:"crt"`
	CaPEM        Certificate          `json:"ca"`
	CertChainPEM []Certificate        `json:"certChain"`
	TLSOptions   *tlsutil.TLSOptions  `json:"tlsOptions,omitempty"`
	TLS          *tls.ConnectionState `json:"-"`
}

// Sign is an HTTP handler that reads a certificate request and an
// one-time-token (ott) from the body and creates a new certificate with the
// information in the certificate request.
func (h *caHandler) Sign(w http.ResponseWriter, r *http.Request) {
	var body SignRequest
	if err := ReadJSON(r.Body, &body); err != nil {
		WriteError(w, errs.Wrap(http.StatusBadRequest, err, "error reading request body"))
		return
	}

	logOtt(w, body.OTT)
	if err := body.Validate(); err != nil {
		WriteError(w, err)
		return
	}

	opts := provisioner.Options{
		NotBefore: body.NotBefore,
		NotAfter:  body.NotAfter,
	}

	signOpts, err := h.Authority.AuthorizeSign(body.OTT)
	if err != nil {
		WriteError(w, errs.UnauthorizedErr(err))
		return
	}

	certChain, err := h.Authority.Sign(body.CsrPEM.CertificateRequest, opts, signOpts...)
	if err != nil {
		WriteError(w, errs.ForbiddenErr(err))
		return
	}
	certChainPEM := certChainToPEM(certChain)
	var caPEM Certificate
	if len(certChainPEM) > 1 {
		caPEM = certChainPEM[1]
	}
	logCertificate(w, certChain[0])
	JSONStatus(w, &SignResponse{
		ServerPEM:    certChainPEM[0],
		CaPEM:        caPEM,
		CertChainPEM: certChainPEM,
		TLSOptions:   h.Authority.GetTLSOptions(),
	}, http.StatusCreated)
}
