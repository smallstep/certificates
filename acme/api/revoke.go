package api

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/provisioner"
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

	prov, err := provisionerFromContext(ctx)
	if err != nil {
		api.WriteError(w, err)
		return
	}

	payload, err := payloadFromContext(ctx)
	if err != nil {
		api.WriteError(w, err)
		return
	}

	var p revokePayload
	err = json.Unmarshal(payload.value, &p)
	if err != nil {
		api.WriteError(w, acme.WrapErrorISE(err, "error unmarshaling payload"))
		return
	}

	certBytes, err := base64.RawURLEncoding.DecodeString(p.Certificate)
	if err != nil {
		// in this case the most likely cause is a client that didn't properly encode the certificate
		api.WriteError(w, acme.WrapError(acme.ErrorMalformedType, err, "error base64url decoding payload certificate property"))
		return
	}

	certToBeRevoked, err := x509.ParseCertificate(certBytes)
	if err != nil {
		// in this case a client may have encoded something different than a certificate
		api.WriteError(w, acme.WrapError(acme.ErrorMalformedType, err, "error parsing certificate"))
		return
	}

	serial := certToBeRevoked.SerialNumber.String()
	existingCert, err := h.db.GetCertificateBySerial(ctx, serial)
	if err != nil {
		api.WriteError(w, acme.WrapErrorISE(err, "error retrieving certificate by serial"))
		return
	}

	if shouldCheckAccountFrom(jws) {
		account, err := accountFromContext(ctx)
		if err != nil {
			api.WriteError(w, err)
			return
		}
		if !account.IsValid() {
			api.WriteError(w, wrapUnauthorizedError(certToBeRevoked, fmt.Sprintf("account '%s' has status '%s'", account.ID, account.Status), nil))
			return
		}
		if existingCert.AccountID != account.ID { // TODO: combine with the below; ony one of the two has to be true
			api.WriteError(w, wrapUnauthorizedError(certToBeRevoked, fmt.Sprintf("account '%s' does not own certificate '%s'", account.ID, existingCert.ID), nil))
			return
		}
		// TODO: check and implement "an account that holds authorizations for all of the identifiers in the certificate."
		// In that case the certificate may not have been created by this account, but another account that was authorized before.
	} else {
		// if account doesn't need to be checked, the JWS should be verified to be signed by the
		// private key that belongs to the public key in the certificate to be revoked.
		// TODO: implement test case for this
		_, err := jws.Verify(certToBeRevoked.PublicKey)
		if err != nil {
			api.WriteError(w, wrapUnauthorizedError(certToBeRevoked, "verification of jws using certificate public key failed", err))
			return
		}
	}

	hasBeenRevokedBefore, err := h.ca.IsRevoked(serial)
	if err != nil {
		api.WriteError(w, acme.WrapErrorISE(err, "error retrieving revocation status of certificate"))
		return
	}

	if hasBeenRevokedBefore {
		api.WriteError(w, acme.NewError(acme.ErrorAlreadyRevokedType, "certificate was already revoked"))
		return
	}

	reasonCode := p.ReasonCode
	acmeErr := validateReasonCode(reasonCode)
	if acmeErr != nil {
		api.WriteError(w, acmeErr)
		return
	}

	// Authorize revocation by ACME provisioner
	ctx = provisioner.NewContextWithMethod(ctx, provisioner.RevokeMethod)
	err = prov.AuthorizeRevoke(ctx, "")
	if err != nil {
		api.WriteError(w, acme.WrapErrorISE(err, "error authorizing revocation on provisioner"))
		return
	}

	options := revokeOptions(serial, certToBeRevoked, reasonCode)
	err = h.ca.Revoke(ctx, options)
	if err != nil {
		api.WriteError(w, wrapRevokeErr(err))
		return
	}

	logRevoke(w, options)
	w.Header().Add("Link", link(h.linker.GetLink(ctx, DirectoryLinkType), "index"))
	w.Write(nil)
}

// wrapRevokeErr is a best effort implementation to transform an error during
// revocation into an ACME error, so that clients can understand the error.
func wrapRevokeErr(err error) *acme.Error {
	t := err.Error()
	if strings.Contains(t, "has already been revoked") {
		return acme.NewError(acme.ErrorAlreadyRevokedType, t)
	}
	return acme.WrapErrorISE(err, "error when revoking certificate")
}

// unauthorizedError returns an ACME error indicating the request was
// not authorized to revoke the certificate.
func wrapUnauthorizedError(cert *x509.Certificate, msg string, err error) *acme.Error {
	var acmeErr *acme.Error
	if err == nil {
		acmeErr = acme.NewError(acme.ErrorUnauthorizedType, msg)
	} else {
		acmeErr = acme.WrapError(acme.ErrorUnauthorizedType, err, msg)
	}
	acmeErr.Status = http.StatusForbidden
	acmeErr.Detail = fmt.Sprintf("No authorization provided for name %s", cert.Subject.String()) // TODO: what about other SANs?

	return acmeErr
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

// shouldCheckAccountFrom indicates whether an account should be
// retrieved from the context, so that it can be used for
// additional checks. This should only be done when no JWK
// can be extracted from the request, as that would indicate
// that the revocation request was signed with a certificate
// key pair (and not an account key pair). Looking up such
// a JWK would result in no Account being found.
func shouldCheckAccountFrom(jws *jose.JSONWebSignature) bool {
	return !canExtractJWKFrom(jws)
}
