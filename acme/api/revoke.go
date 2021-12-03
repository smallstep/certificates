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
	dbCert, err := h.db.GetCertificateBySerial(ctx, serial)
	if err != nil {
		api.WriteError(w, acme.WrapErrorISE(err, "error retrieving certificate by serial"))
		return
	}

	if !bytes.Equal(dbCert.Leaf.Raw, certToBeRevoked.Raw) {
		// this should never happen
		api.WriteError(w, acme.NewErrorISE("certificate raw bytes are not equal"))
		return
	}

	if shouldCheckAccountFrom(jws) {
		account, err := accountFromContext(ctx)
		if err != nil {
			api.WriteError(w, err)
			return
		}
		acmeErr := h.isAccountAuthorized(ctx, dbCert, certToBeRevoked, account)
		if acmeErr != nil {
			api.WriteError(w, acmeErr)
			return
		}
	} else {
		// if account doesn't need to be checked, the JWS should be verified to be signed by the
		// private key that belongs to the public key in the certificate to be revoked.
		_, err := jws.Verify(certToBeRevoked.PublicKey)
		if err != nil {
			// TODO(hs): possible to determine an error vs. unauthorized and thus provide an ISE vs. Unauthorized?
			api.WriteError(w, wrapUnauthorizedError(certToBeRevoked, nil, "verification of jws using certificate public key failed", err))
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

// isAccountAuthorized checks if an ACME account that was retrieved earlier is authorized
// to revoke the certificate. An Account must always be valid in order to revoke a certificate.
// In case the certificate retrieved from the database belongs to the Account, the Account is
// authorized. If the certificate retrieved from the database doesn't belong to the Account,
// the identifiers in the certificate are extracted and compared against the (valid) Authorizations
// that are stored for the ACME Account. If these sets match, the Account is considered authorized
// to revoke the certificate. If this check fails, the client will receive an unauthorized error.
func (h *Handler) isAccountAuthorized(ctx context.Context, dbCert *acme.Certificate, certToBeRevoked *x509.Certificate, account *acme.Account) *acme.Error {
	if !account.IsValid() {
		return wrapUnauthorizedError(certToBeRevoked, nil, fmt.Sprintf("account '%s' has status '%s'", account.ID, account.Status), nil)
	}
	certificateBelongsToAccount := dbCert.AccountID == account.ID
	if certificateBelongsToAccount {
		return nil // return early; skip relatively expensive database check
	}
	requiredIdentifiers := extractIdentifiers(certToBeRevoked)
	if len(requiredIdentifiers) == 0 {
		return wrapUnauthorizedError(certToBeRevoked, nil, "cannot authorize revocation without providing identifiers to authorize", nil)
	}
	authzs, err := h.db.GetAuthorizationsByAccountID(ctx, account.ID)
	if err != nil {
		return acme.WrapErrorISE(err, "error retrieving authorizations for Account %s", account.ID)
	}
	authorizedIdentifiers := map[string]acme.Identifier{}
	for _, authz := range authzs {
		// Only valid Authorizations are included
		if authz.Status != acme.StatusValid {
			continue
		}
		authorizedIdentifiers[identifierKey(authz.Identifier)] = authz.Identifier
	}
	if len(authorizedIdentifiers) == 0 {
		unauthorizedIdentifiers := []acme.Identifier{}
		for _, identifier := range requiredIdentifiers {
			unauthorizedIdentifiers = append(unauthorizedIdentifiers, identifier)
		}
		return wrapUnauthorizedError(certToBeRevoked, unauthorizedIdentifiers, fmt.Sprintf("account '%s' does not have valid authorizations", account.ID), nil)
	}
	unauthorizedIdentifiers := []acme.Identifier{}
	for key := range requiredIdentifiers {
		_, ok := authorizedIdentifiers[key]
		if !ok {
			unauthorizedIdentifiers = append(unauthorizedIdentifiers, requiredIdentifiers[key])
		}
	}
	if len(unauthorizedIdentifiers) != 0 {
		return wrapUnauthorizedError(certToBeRevoked, unauthorizedIdentifiers, fmt.Sprintf("account '%s' does not have authorizations for all identifiers", account.ID), nil)
	}

	return nil
}

// identifierKey creates a unique key for an ACME identifier using
// the following format: ip|127.0.0.1; dns|*.example.com
func identifierKey(identifier acme.Identifier) string {
	if identifier.Type == acme.IP {
		return "ip|" + identifier.Value
	}
	if identifier.Type == acme.DNS {
		return "dns|" + identifier.Value
	}
	return "unsupported|" + identifier.Value
}

// extractIdentifiers extracts ACME identifiers from an x509 certificate and
// creates a map from them. The map ensures that duplicate SANs are deduplicated.
// The Subject CommonName is included, because RFC8555 7.4 states that DNS
// identifiers can come from either the CommonName or a DNS SAN or both. When
// authorizing issuance, the DNS identifier must be in the request and will be
// included in the validation (see Order.sans()) as of now. This means that the
// CommonName will in fact have an authorization available.
func extractIdentifiers(cert *x509.Certificate) map[string]acme.Identifier {
	result := map[string]acme.Identifier{}
	for _, name := range cert.DNSNames {
		identifier := acme.Identifier{
			Type:  acme.DNS,
			Value: name,
		}
		result[identifierKey(identifier)] = identifier
	}
	for _, ip := range cert.IPAddresses {
		identifier := acme.Identifier{
			Type:  acme.IP,
			Value: ip.String(),
		}
		result[identifierKey(identifier)] = identifier
	}
	if cert.Subject.CommonName != "" {
		identifier := acme.Identifier{
			// assuming only DNS can be in Common Name (RFC8555, 7.4); RFC8738
			// IP Identifier Validation Extension does not state anything about this.
			// This logic is in accordance with the logic in order.canonicalize()
			Type:  acme.DNS,
			Value: cert.Subject.CommonName,
		}
		result[identifierKey(identifier)] = identifier
	}
	return result
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
