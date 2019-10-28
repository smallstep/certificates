package api

import (
	"context"
	"net/http"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/provisioner"
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
	Certificate SSHCertificate `json:"crt"`
}

// SSHRenew is an HTTP handler that reads an RenewSSHRequest with a one-time-token
// (ott) from the body and creates a new SSH certificate with the information in
// the request.
func (h *caHandler) SSHRenew(w http.ResponseWriter, r *http.Request) {
	var body SSHRenewRequest
	if err := ReadJSON(r.Body, &body); err != nil {
		WriteError(w, BadRequest(errors.Wrap(err, "error reading request body")))
		return
	}

	logOtt(w, body.OTT)
	if err := body.Validate(); err != nil {
		WriteError(w, BadRequest(err))
		return
	}

	ctx := provisioner.NewContextWithMethod(context.Background(), provisioner.RenewSSHMethod)
	_, err := h.Authority.Authorize(ctx, body.OTT)
	if err != nil {
		WriteError(w, Unauthorized(err))
		return
	}
	oldCert, err := provisioner.ExtractSSHPOPCert(body.OTT)
	if err != nil {
		WriteError(w, InternalServerError(err))
	}

	newCert, err := h.Authority.RenewSSH(oldCert)
	if err != nil {
		WriteError(w, Forbidden(err))
		return
	}

	w.WriteHeader(http.StatusCreated)
	JSON(w, &SSHSignResponse{
		Certificate: SSHCertificate{newCert},
	})
}
