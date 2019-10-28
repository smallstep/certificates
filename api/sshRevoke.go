package api

import (
	"context"
	"net/http"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/logging"
	"golang.org/x/crypto/ocsp"
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
		return BadRequest(errors.New("missing serial"))
	}
	if r.ReasonCode < ocsp.Unspecified || r.ReasonCode > ocsp.AACompromise {
		return BadRequest(errors.New("reasonCode out of bounds"))
	}
	if !r.Passive {
		return NotImplemented(errors.New("non-passive revocation not implemented"))
	}
	if len(r.OTT) == 0 {
		return BadRequest(errors.New("missing ott"))
	}
	return
}

// Revoke supports handful of different methods that revoke a Certificate.
//
// NOTE: currently only Passive revocation is supported.
func (h *caHandler) SSHRevoke(w http.ResponseWriter, r *http.Request) {
	var body SSHRevokeRequest
	if err := ReadJSON(r.Body, &body); err != nil {
		WriteError(w, BadRequest(errors.Wrap(err, "error reading request body")))
		return
	}

	if err := body.Validate(); err != nil {
		WriteError(w, err)
		return
	}

	opts := &authority.RevokeOptions{
		Serial:      body.Serial,
		Reason:      body.Reason,
		ReasonCode:  body.ReasonCode,
		PassiveOnly: body.Passive,
	}

	ctx := provisioner.NewContextWithMethod(context.Background(), provisioner.RevokeSSHMethod)
	// A token indicates that we are using the api via a provisioner token,
	// otherwise it is assumed that the certificate is revoking itself over mTLS.
	logOtt(w, body.OTT)
	if _, err := h.Authority.Authorize(ctx, body.OTT); err != nil {
		WriteError(w, Unauthorized(err))
		return
	}
	opts.OTT = body.OTT

	if err := h.Authority.Revoke(ctx, opts); err != nil {
		WriteError(w, Forbidden(err))
		return
	}

	logSSHRevoke(w, opts)
	JSON(w, &SSHRevokeResponse{Status: "ok"})
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
