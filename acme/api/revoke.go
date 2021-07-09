package api

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/logging"
	"go.step.sm/crypto/jose"
	"golang.org/x/crypto/ocsp"
)

type revokePayload struct {
	Certificate string `json:"certificate"`
	ReasonCode  *int   `json:"reason,omitempty"`
}

// RevokeCert attempts to revoke a certificate.
func (h *Handler) RevokeCert(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()
	jws, err := jwsFromContext(ctx)
	if err != nil {
		api.WriteError(w, err)
		return
	}

	if shouldCheckAccount(jws) {
		_, err := accountFromContext(ctx)
		if err != nil {
			api.WriteError(w, err)
			return
		}
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
		api.WriteError(w, acme.WrapErrorISE(err, "error unmarshaling payload"))
		return
	}

	certBytes, err := base64.RawURLEncoding.DecodeString(payload.Certificate)
	if err != nil {
		api.WriteError(w, acme.WrapErrorISE(err, "error decoding base64 certificate"))
		return
	}

	certToBeRevoked, err := x509.ParseCertificate(certBytes)
	if err != nil {
		api.WriteError(w, acme.WrapErrorISE(err, "error parsing certificate"))
		return
	}

	serial := certToBeRevoked.SerialNumber.String()
	_, err = h.db.GetCertificateBySerial(ctx, serial)
	if err != nil {
		api.WriteError(w, acme.WrapErrorISE(err, "error retrieving certificate by serial"))
		return
	}

	// if existingCert.AccountID != acc.ID {
	// 	api.WriteError(w, acme.NewError(acme.ErrorUnauthorizedType,
	// 		"account '%s' does not own certificate '%s'", acc.ID, certID))
	// 	return // TODO: this check should only be performed in case acc exists (i.e. KeyID revoke)
	// }

	// TODO: validate the certToBeRevoked against what we know about it?

	reasonCode := payload.ReasonCode
	acmeErr := validateReasonCode(reasonCode)
	if acmeErr != nil {
		api.WriteError(w, acmeErr)
		return
	}

	options := revokeOptions(serial, certToBeRevoked, reasonCode)
	err = h.ca.Revoke(ctx, options)
	if err != nil {
		api.WriteError(w, err) // TODO: send the right error; 400; alreadyRevoked (or something else went wrong, of course)
		return
	}

	logRevoke(w, options)
	w.Header().Add("Link", link(h.linker.GetLink(ctx, DirectoryLinkType), "index"))
	w.Write(nil)
}

// logRevoke logs successful revocation of certificate
func logRevoke(w http.ResponseWriter, ri *authority.RevokeOptions) {
	if rl, ok := w.(logging.ResponseLogger); ok {
		rl.WithFields(map[string]interface{}{
			"serial":      ri.Serial,
			"reasonCode":  ri.ReasonCode,
			"reason":      ri.Reason,
			"passiveOnly": ri.PassiveOnly,
			"ACME":        ri.ACME,
		})
	}
}

// validateReasonCode validates the revocation reason
func validateReasonCode(reasonCode *int) *acme.Error {
	if reasonCode != nil && ((*reasonCode < ocsp.Unspecified || *reasonCode > ocsp.AACompromise) || *reasonCode == 7) {
		return acme.NewError(acme.ErrorBadRevocationReasonType, "reasonCode out of bounds")
	}
	// NOTE: it's possible to add additional requirements to the reason code:
	//		The server MAY disallow a subset of reasonCodes from being
	//		used by the user. If a request contains a disallowed reasonCode,
	//		then the server MUST reject it with the error type
	//		"urn:ietf:params:acme:error:badRevocationReason"
	// No additional checks have been implemented so far.
	return nil
}

// revokeOptions determines the the RevokeOptions for the Authority to use in revocation
func revokeOptions(serial string, certToBeRevoked *x509.Certificate, reasonCode *int) *authority.RevokeOptions {
	opts := &authority.RevokeOptions{
		Serial: serial,
		ACME:   true,
		Crt:    certToBeRevoked,
	}
	if reasonCode != nil { // NOTE: when implementing CRL and/or OCSP, and reason code is missing, CRL entry extension should be omitted
		opts.Reason = reason(*reasonCode)
		opts.ReasonCode = *reasonCode
	}
	return opts
}

// reason transforms an integer reason code to a
// textual description of the revocation reason.
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

// shouldCheckAccount indicates whether an account should be
// retrieved from the context, so that it can be used for
// additional checks.
func shouldCheckAccount(jws *jose.JSONWebSignature) bool {
	return !canExtractJWKFrom(jws)
}
