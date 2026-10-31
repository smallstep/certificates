package acme

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"go.step.sm/crypto/jose"

	"github.com/smallstep/certificates/attestation"
	"github.com/smallstep/certificates/attestation/cmw"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/webhook"
)

// remoteAttest01Validate validates a remote-attest-01 challenge
// (draft-ietf-acme-rats-03). The payload is a CMW record (RFC 9999) holding the
// evidence: a TDX quote or an SEV-SNP report in a configfs-tsm report, or a
// Confidential Space token. step-ca profiles the draft, which defines no
// binding, by requiring the evidence to bind first
//
//	SHA-256(keyAuthorization || DER SubjectPublicKeyInfo of the certificate key)
//
// where keyAuthorization is freshnessNonce || '.' || base64url(JWK thumbprint
// of the account key). The binding makes the evidence fresh, ties it to the
// account, and attests the key the order will be finalized with. A TDX quote or
// an SEV-SNP report carries it as the first half of its report data and the
// relying party's nonce, its claim nonce, as the second half; a Confidential
// Space token carries it, base64url encoded without padding, as its first
// eat_nonce value, and the relying party's nonces after it.
//
// The certificate request is sent only when the order is finalized, so this
// validation verifies the evidence and stores the key authorization, the
// binding and the claim nonce on the authorization, and Finalize checks the
// binding against the request's key. Evidence replayed from another challenge
// validates the challenge but can never finalize the order.
//
// An empty payload, or an empty JSON object, leaves the challenge unchanged.
func remoteAttest01Validate(ctx context.Context, ch *Challenge, db DB, jwk *jose.JSONWebKey, payload []byte) error {
	if p := bytes.TrimSpace(payload); len(p) == 0 || bytes.Equal(p, []byte("{}")) {
		return nil
	}
	if ch.FreshnessNonce == "" {
		return NewErrorISE("remote-attest-01 challenge %s has no freshness nonce", ch.ID)
	}

	record, err := cmw.Parse(payload)
	if err != nil {
		return WrapError(ErrorMalformedType, err, "error parsing remote attestation")
	}

	prov := MustProvisionerFromContext(ctx)
	var audience string
	if linker, ok := LinkerFromContext(ctx); ok {
		audience = linker.GetLink(ctx, DirectoryLinkType)
	}
	result, bound, err := prov.VerifyRemoteAttestation(ctx, record, audience)
	switch {
	case errors.Is(err, attestation.ErrInvalidEvidence):
		return storeError(ctx, db, ch, true, WrapDetailedError(ErrorBadAttestationStatementType, err, "%s", err))
	case err != nil:
		return WrapErrorISE(err, "error verifying remote attestation")
	}

	var claimNonce string
	switch len(bound) {
	case provisioner.RemoteAttestationBindingSize:
	case provisioner.RemoteAttestationBindingSize + provisioner.RemoteAttestationClaimNonceSize:
		claimNonce = base64.RawURLEncoding.EncodeToString(bound[provisioner.RemoteAttestationBindingSize:])
	default:
		return NewErrorISE("remote attestation binds %d bytes", len(bound))
	}

	keyAuth, err := KeyAuthorization(ch.FreshnessNonce, jwk)
	if err != nil {
		return err
	}

	az, err := db.GetAuthorization(ctx, ch.AuthorizationID)
	if err != nil {
		return WrapErrorISE(err, "error loading authorization")
	}
	az.Attestation = &webhook.Attestation{
		Challenge:        string(REMOTEATTEST01),
		Hint:             az.Identifier.Value,
		FreshnessNonce:   ch.FreshnessNonce,
		KeyAuthorization: keyAuth,
		BindingDigest:    hex.EncodeToString(bound[:provisioner.RemoteAttestationBindingSize]),
		ClaimNonce:       claimNonce,
		Result:           result,
	}

	ch.Status = StatusValid
	ch.Error = nil
	ch.ValidatedAt = clock.Now().Format(time.RFC3339)
	ch.PayloadFormat = string(result.Format)

	// TODO: add method to update authorization and challenge atomically.
	if err := db.UpdateAuthorization(ctx, az); err != nil {
		return WrapErrorISE(err, "error updating authorization")
	}
	if err := db.UpdateChallenge(ctx, ch); err != nil {
		return WrapErrorISE(err, "error updating challenge")
	}
	return nil
}

// RemoteAttestationBinding returns the hex encoded binding remote-attest-01
// evidence carries for a certificate request: SHA-256 of the key authorization
// followed by the DER SubjectPublicKeyInfo of the request's key.
func RemoteAttestationBinding(keyAuthorization string, csr *x509.CertificateRequest) string {
	h := sha256.New()
	h.Write([]byte(keyAuthorization))
	h.Write(csr.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(h.Sum(nil))
}
