package api

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority"
	"golang.org/x/crypto/ocsp"
)

type revokePayload struct {
	Certificate string `json:"certificate"`
	ReasonCode  int    `json:"reason"`
}

func (h *Handler) RevokeCert(w http.ResponseWriter, r *http.Request) {

	// TODO: support the non-kid case, i.e. JWK with the public key of the cert
	// base the account + certificate JWK instead of the kid (which is now the case)

	ctx := r.Context()
	_, err := accountFromContext(ctx)
	if err != nil {
		api.WriteError(w, err)
		return
	}

	// TODO: do checks on account, i.e. is it still valid? is it allowed to do revocations? Revocations on the to be revoked cert?

	_, err = provisionerFromContext(ctx)
	if err != nil {
		api.WriteError(w, err)
		return
	}

	// TODO: let provisioner authorize the revocation? Necessary per provisioner? Or can it be done by the CA, like the Revoke itself.

	p, err := payloadFromContext(ctx)
	if err != nil {
		api.WriteError(w, err)
		return
	}

	var payload revokePayload
	err = json.Unmarshal(p.value, &payload)
	if err != nil {
		api.WriteError(w, err) // TODO: fix error type
		return
	}

	certBytes, err := base64.RawURLEncoding.DecodeString(payload.Certificate)
	if err != nil {
		api.WriteError(w, err) // TODO: fix error type
		return
	}

	certToBeRevoked, err := x509.ParseCertificate(certBytes)
	if err != nil {
		api.WriteError(w, err) // TODO: fix error type
		return
	}

	certID := certToBeRevoked.SerialNumber.String()
	// TODO: retrieving the certificate to verify the account does not seem to work? Results in certificate not found error.
	// When Revoke is called, the certificate IS in fact found? The (h *Handler) GetCertificate function is fairly similar, too.
	// existingCert, err := h.db.GetCertificate(ctx, certID)
	// if err != nil {
	// 	api.WriteError(w, acme.WrapErrorISE(err, "error retrieving certificate"))
	// 	return
	// }
	// if existingCert.AccountID != acc.ID {
	// 	api.WriteError(w, acme.NewError(acme.ErrorUnauthorizedType,
	// 		"account '%s' does not own certificate '%s'", acc.ID, certID))
	// 	return // TODO: this check should only be performed in case acc exists (i.e. KID revoke)
	// }

	// TODO: validate the certToBeRevoked against what we know about it?

	if payload.ReasonCode < ocsp.Unspecified || payload.ReasonCode > ocsp.AACompromise {
		api.WriteError(w, acme.NewError(acme.ErrorBadRevocationReasonType, "reasonCode out of bounds"))
		return
	}

	// TODO: check reason code; should be allowed (based on what? and determined by Provisioner?); otherwise send error

	options := &authority.RevokeOptions{
		Serial:     certID,
		Reason:     reason(payload.ReasonCode),
		ReasonCode: payload.ReasonCode,
		ACME:       true,
		Crt:        certToBeRevoked,
	}

	err = h.ca.Revoke(ctx, options)
	if err != nil {
		api.WriteError(w, err) // TODO: send the right error; 400; alreadyRevoked (or something else went wrong, of course)
		return
	}

	w.Write(nil)
}

func reason(reasonCode int) string {
	switch reasonCode {
	case ocsp.Unspecified:
		return "unspecified reason"
	case ocsp.KeyCompromise:
		return "key compromised"
	case ocsp.CACompromise:
		return "ca compromised"
	case ocsp.AffiliationChanged:
		return "affiliation changed"
	case ocsp.Superseded:
		return "superseded"
	case ocsp.CessationOfOperation:
		return "cessation of operation"
	case ocsp.CertificateHold:
		return "certificate hold"
	case ocsp.RemoveFromCRL:
		return "remove from crl"
	case ocsp.PrivilegeWithdrawn:
		return "privilege withdrawn"
	case ocsp.AACompromise:
		return "aa compromised"
	default:
		return "unspecified reason"
	}
}
