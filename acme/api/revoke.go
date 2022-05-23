package api

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"go.step.sm/crypto/jose"
	"golang.org/x/crypto/ocsp"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/logging"
)

type revokePayload struct {
	Certificate string `json:"certificate"`
	ReasonCode  *int   `json:"reason,omitempty"`
}

// RevokeCert attempts to revoke a certificate.
func RevokeCert(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	db := acme.MustDatabaseFromContext(ctx)
	linker := acme.MustLinkerFromContext(ctx)

	jws, err := jwsFromContext(ctx)
	if err != nil {
		render.Error(w, err)
		return
	}

	prov, err := provisionerFromContext(ctx)
	if err != nil {
		render.Error(w, err)
		return
	}

	payload, err := payloadFromContext(ctx)
	if err != nil {
		render.Error(w, err)
		return
	}

	var p revokePayload
	err = json.Unmarshal(payload.value, &p)
	if err != nil {
		render.Error(w, acme.WrapErrorISE(err, "error unmarshaling payload"))
		return
	}

	certBytes, err := base64.RawURLEncoding.DecodeString(p.Certificate)
	if err != nil {
		// in this case the most likely cause is a client that didn't properly encode the certificate
		render.Error(w, acme.WrapError(acme.ErrorMalformedType, err, "error base64url decoding payload certificate property"))
		return
	}

	certToBeRevoked, err := x509.ParseCertificate(certBytes)
	if err != nil {
		// in this case a client may have encoded something different than a certificate
		render.Error(w, acme.WrapError(acme.ErrorMalformedType, err, "error parsing certificate"))
		return
	}

	serial := certToBeRevoked.SerialNumber.String()
	dbCert, err := db.GetCertificateBySerial(ctx, serial)
	if err != nil {
		render.Error(w, acme.WrapErrorISE(err, "error retrieving certificate by serial"))
		return
	}

	if !bytes.Equal(dbCert.Leaf.Raw, certToBeRevoked.Raw) {
		// this should never happen
		render.Error(w, acme.NewErrorISE("certificate raw bytes are not equal"))
		return
	}

	if shouldCheckAccountFrom(jws) {
		account, err := accountFromContext(ctx)
		if err != nil {
			render.Error(w, err)
			return
		}
		acmeErr := isAccountAuthorized(ctx, dbCert, certToBeRevoked, account)
		if acmeErr != nil {
			render.Error(w, acmeErr)
			return
		}
	} else {
		// if account doesn't need to be checked, the JWS should be verified to be signed by the
		// private key that belongs to the public key in the certificate to be revoked.
		_, err := jws.Verify(certToBeRevoked.PublicKey)
		if err != nil {
			// TODO(hs): possible to determine an error vs. unauthorized and thus provide an ISE vs. Unauthorized?
			render.Error(w, wrapUnauthorizedError(certToBeRevoked, nil, "verification of jws using certificate public key failed", err))
			return
		}
	}

	ca := mustAuthority(ctx)
	hasBeenRevokedBefore, err := ca.IsRevoked(serial)
	if err != nil {
		render.Error(w, acme.WrapErrorISE(err, "error retrieving revocation status of certificate"))
		return
	}

	if hasBeenRevokedBefore {
		render.Error(w, acme.NewError(acme.ErrorAlreadyRevokedType, "certificate was already revoked"))
		return
	}

	reasonCode := p.ReasonCode
	acmeErr := validateReasonCode(reasonCode)
	if acmeErr != nil {
		render.Error(w, acmeErr)
		return
	}

	// Authorize revocation by ACME provisioner
	ctx = provisioner.NewContextWithMethod(ctx, provisioner.RevokeMethod)
	err = prov.AuthorizeRevoke(ctx, "")
	if err != nil {
		render.Error(w, acme.WrapErrorISE(err, "error authorizing revocation on provisioner"))
		return
	}

	options := revokeOptions(serial, certToBeRevoked, reasonCode)
	err = ca.Revoke(ctx, options)
	if err != nil {
		render.Error(w, wrapRevokeErr(err))
		return
	}

	logRevoke(w, options)
	w.Header().Add("Link", link(linker.GetLink(ctx, acme.DirectoryLinkType), "index"))
	w.Write(nil)
}

// isAccountAuthorized checks if an ACME account that was retrieved earlier is authorized
// to revoke the certificate. An Account must always be valid in order to revoke a certificate.
// In case the certificate retrieved from the database belongs to the Account, the Account is
// authorized. If the certificate retrieved from the database doesn't belong to the Account,
// the identifiers in the certificate are extracted and compared against the (valid) Authorizations
// that are stored for the ACME Account. If these sets match, the Account is considered authorized
// to revoke the certificate. If this check fails, the client will receive an unauthorized error.
func isAccountAuthorized(ctx context.Context, dbCert *acme.Certificate, certToBeRevoked *x509.Certificate, account *acme.Account) *acme.Error {
	if !account.IsValid() {
		return wrapUnauthorizedError(certToBeRevoked, nil, fmt.Sprintf("account '%s' has status '%s'", account.ID, account.Status), nil)
	}
	certificateBelongsToAccount := dbCert.AccountID == account.ID
	if certificateBelongsToAccount {
		return nil // return early
	}

	// TODO(hs): according to RFC8555: 7.6, a server MUST consider the following accounts authorized
	// to revoke a certificate:
	//
	//	o  the account that issued the certificate.
	//	o  an account that holds authorizations for all of the identifiers in the certificate.
	//
	// We currently only support the first case. The second might result in step going OOM when
	// large numbers of Authorizations are involved when the current nosql interface is in use.
	// We want to protect users from this failure scenario, so that's why it hasn't been added yet.
	// This issue is tracked in https://github.com/smallstep/certificates/issues/767

	// not authorized; fail closed.
	return wrapUnauthorizedError(certToBeRevoked, nil, fmt.Sprintf("account '%s' is not authorized", account.ID), nil)
}

// wrapRevokeErr is a best effort implementation to transform an error during
// revocation into an ACME error, so that clients can understand the error.
func wrapRevokeErr(err error) *acme.Error {
	t := err.Error()
	if strings.Contains(t, "is already revoked") {
		return acme.NewError(acme.ErrorAlreadyRevokedType, t)
	}
	return acme.WrapErrorISE(err, "error when revoking certificate")
}

// unauthorizedError returns an ACME error indicating the request was
// not authorized to revoke the certificate.
func wrapUnauthorizedError(cert *x509.Certificate, unauthorizedIdentifiers []acme.Identifier, msg string, err error) *acme.Error {
	var acmeErr *acme.Error
	if err == nil {
		acmeErr = acme.NewError(acme.ErrorUnauthorizedType, msg)
	} else {
		acmeErr = acme.WrapError(acme.ErrorUnauthorizedType, err, msg)
	}
	acmeErr.Status = http.StatusForbidden // RFC8555 7.6 shows example with 403

	switch {
	case len(unauthorizedIdentifiers) > 0:
		identifier := unauthorizedIdentifiers[0] // picking the first; compound may be an option too?
		acmeErr.Detail = fmt.Sprintf("No authorization provided for name %s", identifier.Value)
	case cert.Subject.String() != "":
		acmeErr.Detail = fmt.Sprintf("No authorization provided for name %s", cert.Subject.CommonName)
	default:
		acmeErr.Detail = "No authorization provided"
	}

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

// revokeOptions determines the RevokeOptions for the Authority to use in revocation
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
