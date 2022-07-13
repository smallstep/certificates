package api

import (
	"crypto/x509"
	"net/http"
	"time"

	"github.com/pkg/errors"

	"github.com/smallstep/certificates/api/read"
	"github.com/smallstep/certificates/api/render"
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
	case s.OTT == "":
		return errs.BadRequest("missing or empty ott")
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
func SSHRenew(w http.ResponseWriter, r *http.Request) {
	var body SSHRenewRequest
	if err := read.JSON(r.Body, &body); err != nil {
		render.Error(w, errs.BadRequestErr(err, "error reading request body"))
		return
	}

	logOtt(w, body.OTT)
	if err := body.Validate(); err != nil {
		render.Error(w, err)
		return
	}

	ctx := provisioner.NewContextWithMethod(r.Context(), provisioner.SSHRenewMethod)
	ctx = provisioner.NewContextWithToken(ctx, body.OTT)

	a := mustAuthority(ctx)
	_, err := a.Authorize(ctx, body.OTT)
	if err != nil {
		render.Error(w, errs.UnauthorizedErr(err))
		return
	}
	oldCert, _, err := provisioner.ExtractSSHPOPCert(body.OTT)
	if err != nil {
		render.Error(w, errs.InternalServerErr(err))
		return
	}

	newCert, err := a.RenewSSH(ctx, oldCert)
	if err != nil {
		render.Error(w, errs.ForbiddenErr(err, "error renewing ssh certificate"))
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

	render.JSONStatus(w, &SSHSignResponse{
		Certificate:         SSHCertificate{newCert},
		IdentityCertificate: identity,
	}, http.StatusCreated)
}

// renewIdentityCertificate request the client TLS certificate if present. If notBefore and notAfter are passed the
func renewIdentityCertificate(r *http.Request, notBefore, notAfter time.Time) ([]Certificate, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, nil
	}

	// Clone the certificate as we can modify it.
	cert, err := x509.ParseCertificate(r.TLS.PeerCertificates[0].Raw)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing client certificate")
	}

	// Enforce the cert to match another certificate, for example an ssh
	// certificate.
	if !notBefore.IsZero() {
		cert.NotBefore = notBefore
	}
	if !notAfter.IsZero() {
		cert.NotAfter = notAfter
	}

	certChain, err := mustAuthority(r.Context()).Renew(cert)
	if err != nil {
		return nil, err
	}

	return certChainToPEM(certChain), nil
}
