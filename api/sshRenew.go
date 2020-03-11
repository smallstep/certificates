package api

import (
	"net/http"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/errs"
)

// SSHRenewRequest is the request body of an SSH certificate request.
type SSHRenewRequest struct {
	OTT string `json:"ott"`
}

// Validate validates the SSHSignRequest.
func (s *SSHRenewRequest) Validate() error {
	switch {
	case len(s.OTT) == 0:
		return errors.New("missing or empty ott")
	default:
		return nil
	}
}

// SSHRenewResponse is the response object that returns the SSH certificate.
type SSHRenewResponse struct {
	Certificate         SSHCertificate `json:"crt"`
	IdentityCertificate []Certificate  `json:"identityCrt,omitempty"`
}

// SSHRenew is an HTTP handler that reads an RenewSSHRequest with a one-time-token
// (ott) from the body and creates a new SSH certificate with the information in
// the request.
func (h *caHandler) SSHRenew(w http.ResponseWriter, r *http.Request) {
	var body SSHRenewRequest
	if err := ReadJSON(r.Body, &body); err != nil {
		WriteError(w, errs.Wrap(http.StatusBadRequest, err, "error reading request body"))
		return
	}

	logOtt(w, body.OTT)
	if err := body.Validate(); err != nil {
		WriteError(w, errs.BadRequestErr(err))
		return
	}

	ctx := provisioner.NewContextWithMethod(r.Context(), provisioner.SSHRenewMethod)
	_, err := h.Authority.Authorize(ctx, body.OTT)
	if err != nil {
		WriteError(w, errs.UnauthorizedErr(err))
		return
	}
	oldCert, _, err := provisioner.ExtractSSHPOPCert(body.OTT)
	if err != nil {
		WriteError(w, errs.InternalServerErr(err))
	}

	newCert, err := h.Authority.RenewSSH(ctx, oldCert)
	if err != nil {
		WriteError(w, errs.ForbiddenErr(err))
		return
	}

	identity, err := h.renewIdentityCertificate(r)
	if err != nil {
		WriteError(w, errs.ForbiddenErr(err))
		return
	}

	JSONStatus(w, &SSHSignResponse{
		Certificate:         SSHCertificate{newCert},
		IdentityCertificate: identity,
	}, http.StatusCreated)
}

// renewIdentityCertificate request the client TLS certificate if present.
func (h *caHandler) renewIdentityCertificate(r *http.Request) ([]Certificate, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, nil
	}

	certChain, err := h.Authority.Renew(r.TLS.PeerCertificates[0])
	if err != nil {
		return nil, err
	}

	return certChainToPEM(certChain), nil
}
