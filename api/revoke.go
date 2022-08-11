package api

import (
	"math/big"
	"net/http"

	"golang.org/x/crypto/ocsp"

	"github.com/smallstep/certificates/api/read"
	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/errs"
	"github.com/smallstep/certificates/logging"
)

// RevokeResponse is the response object that returns the health of the server.
type RevokeResponse struct {
	Status string `json:"status"`
}

// RevokeRequest is the request body for a revocation request.
type RevokeRequest struct {
	Serial     string `json:"serial"`
	OTT        string `json:"ott"`
	ReasonCode int    `json:"reasonCode"`
	Reason     string `json:"reason"`
	Passive    bool   `json:"passive"`
}

// Validate checks the fields of the RevokeRequest and returns nil if they are ok
// or an error if something is wrong.
func (r *RevokeRequest) Validate() (err error) {
	if r.Serial == "" {
		return errs.BadRequest("missing serial")
	}
	sn, ok := new(big.Int).SetString(r.Serial, 0)
	if !ok {
		return errs.BadRequest("'%s' is not a valid serial number - use a base 10 representation or a base 16 representation with '0x' prefix", r.Serial)
	}
	r.Serial = sn.String()
	if r.ReasonCode < ocsp.Unspecified || r.ReasonCode > ocsp.AACompromise {
		return errs.BadRequest("reasonCode out of bounds")
	}
	if !r.Passive {
		return errs.NotImplemented("non-passive revocation not implemented")
	}

	return
}

// Revoke supports handful of different methods that revoke a Certificate.
//
// NOTE: currently only Passive revocation is supported.
//
// TODO: Add CRL and OCSP support.
func Revoke(w http.ResponseWriter, r *http.Request) {
	var body RevokeRequest
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

	ctx := provisioner.NewContextWithMethod(r.Context(), provisioner.RevokeMethod)
	a := mustAuthority(ctx)

	// A token indicates that we are using the api via a provisioner token,
	// otherwise it is assumed that the certificate is revoking itself over mTLS.
	if len(body.OTT) > 0 {
		logOtt(w, body.OTT)
		if _, err := a.Authorize(ctx, body.OTT); err != nil {
			render.Error(w, errs.UnauthorizedErr(err))
			return
		}
		opts.OTT = body.OTT
	} else {
		// If no token is present, then the request must be made over mTLS and
		// the client certificate Serial Number must match the serial number
		// being revoked.
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			render.Error(w, errs.BadRequest("missing ott or client certificate"))
			return
		}
		opts.Crt = r.TLS.PeerCertificates[0]
		if opts.Crt.SerialNumber.String() != opts.Serial {
			render.Error(w, errs.BadRequest("serial number in client certificate different than body"))
			return
		}
		// TODO: should probably be checking if the certificate was revoked here.
		// Will need to thread that request down to the authority, so will need
		// to add API for that.
		LogCertificate(w, opts.Crt)
		opts.MTLS = true
	}

	if err := a.Revoke(ctx, opts); err != nil {
		render.Error(w, errs.ForbiddenErr(err, "error revoking certificate"))
		return
	}

	logRevoke(w, opts)
	render.JSON(w, &RevokeResponse{Status: "ok"})
}

func logRevoke(w http.ResponseWriter, ri *authority.RevokeOptions) {
	if rl, ok := w.(logging.ResponseLogger); ok {
		rl.WithFields(map[string]interface{}{
			"serial":      ri.Serial,
			"reasonCode":  ri.ReasonCode,
			"reason":      ri.Reason,
			"passiveOnly": ri.PassiveOnly,
			"mTLS":        ri.MTLS,
		})
	}
}
