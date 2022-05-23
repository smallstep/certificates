package api

import (
	"net/http"

	"golang.org/x/crypto/ocsp"

	"github.com/smallstep/certificates/api/read"
	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/errs"
	"github.com/smallstep/certificates/logging"
)

// SSHRevokeResponse is the response object that returns the health of the server.
type SSHRevokeResponse struct {
	Status string `json:"status"`
}

// SSHRevokeRequest is the request body for a revocation request.
type SSHRevokeRequest struct {
	Serial     string `json:"serial"`
	OTT        string `json:"ott"`
	ReasonCode int    `json:"reasonCode"`
	Reason     string `json:"reason"`
	Passive    bool   `json:"passive"`
}

// Validate checks the fields of the RevokeRequest and returns nil if they are ok
// or an error if something is wrong.
func (r *SSHRevokeRequest) Validate() (err error) {
	if r.Serial == "" {
		return errs.BadRequest("missing serial")
	}
	if r.ReasonCode < ocsp.Unspecified || r.ReasonCode > ocsp.AACompromise {
		return errs.BadRequest("reasonCode out of bounds")
	}
	if !r.Passive {
		return errs.NotImplemented("non-passive revocation not implemented")
	}
	if r.OTT == "" {
		return errs.BadRequest("missing ott")
	}
	return
}

// Revoke supports handful of different methods that revoke a Certificate.
//
// NOTE: currently only Passive revocation is supported.
func SSHRevoke(w http.ResponseWriter, r *http.Request) {
	var body SSHRevokeRequest
	if err := read.JSON(r.Body, &body); err != nil {
		render.Error(w, errs.BadRequestErr(err, "error reading request body"))
		return
	}

	if err := body.Validate(); err != nil {
		render.Error(w, err)
		return
	}

	opts := &authority.RevokeOptions{
		Serial:      body.Serial,
		Reason:      body.Reason,
		ReasonCode:  body.ReasonCode,
		PassiveOnly: body.Passive,
	}

	ctx := provisioner.NewContextWithMethod(r.Context(), provisioner.SSHRevokeMethod)
	a := mustAuthority(ctx)

	// A token indicates that we are using the api via a provisioner token,
	// otherwise it is assumed that the certificate is revoking itself over mTLS.
	logOtt(w, body.OTT)

	if _, err := a.Authorize(ctx, body.OTT); err != nil {
		render.Error(w, errs.UnauthorizedErr(err))
		return
	}
	opts.OTT = body.OTT

	if err := a.Revoke(ctx, opts); err != nil {
		render.Error(w, errs.ForbiddenErr(err, "error revoking ssh certificate"))
		return
	}

	logSSHRevoke(w, opts)
	render.JSON(w, &SSHRevokeResponse{Status: "ok"})
}

func logSSHRevoke(w http.ResponseWriter, ri *authority.RevokeOptions) {
	if rl, ok := w.(logging.ResponseLogger); ok {
		rl.WithFields(map[string]interface{}{
			"serial":      ri.Serial,
			"reasonCode":  ri.ReasonCode,
			"reason":      ri.Reason,
			"passiveOnly": ri.PassiveOnly,
			"mTLS":        ri.MTLS,
			"ssh":         true,
		})
	}
}
