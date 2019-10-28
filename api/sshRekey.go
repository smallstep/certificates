package api

import (
	"context"
	"net/http"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/provisioner"
	"golang.org/x/crypto/ssh"
)

// SSHRekeyRequest is the request body of an SSH certificate request.
type SSHRekeyRequest struct {
	OTT       string `json:"ott"`
	PublicKey []byte `json:"publicKey"` //base64 encoded
}

// Validate validates the SSHSignRekey.
func (s *SSHRekeyRequest) Validate() error {
	switch {
	case len(s.OTT) == 0:
		return errors.New("missing or empty ott")
	case len(s.PublicKey) == 0:
		return errors.New("missing or empty public key")
	default:
		return nil
	}
}

// SSHRekeyResponse is the response object that returns the SSH certificate.
type SSHRekeyResponse struct {
	Certificate SSHCertificate `json:"crt"`
}

// SSHRekey is an HTTP handler that reads an RekeySSHRequest with a one-time-token
// (ott) from the body and creates a new SSH certificate with the information in
// the request.
func (h *caHandler) SSHRekey(w http.ResponseWriter, r *http.Request) {
	var body SSHRekeyRequest
	if err := ReadJSON(r.Body, &body); err != nil {
		WriteError(w, BadRequest(errors.Wrap(err, "error reading request body")))
		return
	}

	logOtt(w, body.OTT)
	if err := body.Validate(); err != nil {
		WriteError(w, BadRequest(err))
		return
	}

	publicKey, err := ssh.ParsePublicKey(body.PublicKey)
	if err != nil {
		WriteError(w, BadRequest(errors.Wrap(err, "error parsing publicKey")))
		return
	}

	ctx := provisioner.NewContextWithMethod(context.Background(), provisioner.RekeySSHMethod)
	signOpts, err := h.Authority.Authorize(ctx, body.OTT)
	if err != nil {
		WriteError(w, Unauthorized(err))
		return
	}
	oldCert, err := provisioner.ExtractSSHPOPCert(body.OTT)
	if err != nil {
		WriteError(w, InternalServerError(err))
	}

	newCert, err := h.Authority.RekeySSH(oldCert, publicKey, signOpts...)
	if err != nil {
		WriteError(w, Forbidden(err))
		return
	}

	w.WriteHeader(http.StatusCreated)
	JSON(w, &SSHSignResponse{
		Certificate: SSHCertificate{newCert},
	})
}
