package api

import (
	"net/http"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/smallstep/certificates/api/read"
	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/errs"
)

// SSHRekeyRequest is the request body of an SSH certificate request.
type SSHRekeyRequest struct {
	OTT       string `json:"ott"`
	PublicKey []byte `json:"publicKey"` //base64 encoded
}

// Validate validates the SSHSignRekey.
func (s *SSHRekeyRequest) Validate() error {
	switch {
	case s.OTT == "":
		return errs.BadRequest("missing or empty ott")
	case len(s.PublicKey) == 0:
		return errs.BadRequest("missing or empty public key")
	default:
		return nil
	}
}

// SSHRekeyResponse is the response object that returns the SSH certificate.
type SSHRekeyResponse struct {
	Certificate         SSHCertificate `json:"crt"`
	IdentityCertificate []Certificate  `json:"identityCrt,omitempty"`
}

// SSHRekey is an HTTP handler that reads an RekeySSHRequest with a one-time-token
// (ott) from the body and creates a new SSH certificate with the information in
// the request.
func SSHRekey(w http.ResponseWriter, r *http.Request) {
	var body SSHRekeyRequest
	if err := read.JSON(r.Body, &body); err != nil {
		render.Error(w, errs.BadRequestErr(err, "error reading request body"))
		return
	}

	logOtt(w, body.OTT)
	if err := body.Validate(); err != nil {
		render.Error(w, err)
		return
	}

	publicKey, err := ssh.ParsePublicKey(body.PublicKey)
	if err != nil {
		render.Error(w, errs.BadRequestErr(err, "error parsing publicKey"))
		return
	}

	ctx := provisioner.NewContextWithMethod(r.Context(), provisioner.SSHRekeyMethod)
	ctx = provisioner.NewContextWithToken(ctx, body.OTT)

	a := mustAuthority(ctx)
	signOpts, err := a.Authorize(ctx, body.OTT)
	if err != nil {
		render.Error(w, errs.UnauthorizedErr(err))
		return
	}
	oldCert, _, err := provisioner.ExtractSSHPOPCert(body.OTT)
	if err != nil {
		render.Error(w, errs.InternalServerErr(err))
		return
	}

	newCert, err := a.RekeySSH(ctx, oldCert, publicKey, signOpts...)
	if err != nil {
		render.Error(w, errs.ForbiddenErr(err, "error rekeying ssh certificate"))
		return
	}

	// Match identity cert with the SSH cert
	notBefore := time.Unix(int64(oldCert.ValidAfter), 0)
	notAfter := time.Unix(int64(oldCert.ValidBefore), 0)

	identity, err := renewIdentityCertificate(r, notBefore, notAfter)
	if err != nil {
		render.Error(w, errs.ForbiddenErr(err, "error renewing identity certificate"))
		return
	}

	render.JSONStatus(w, &SSHRekeyResponse{
		Certificate:         SSHCertificate{newCert},
		IdentityCertificate: identity,
	}, http.StatusCreated)
}
