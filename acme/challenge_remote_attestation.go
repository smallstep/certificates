package acme

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
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
// binding, by requiring the evidence to bind 64 bytes:
//
//   - The SHA-256 digest of the key authorization of the challenge, computed
//     over its freshnessNonce: freshnessNonce || '.' || base64url(JWK
//     thumbprint of the account key). It makes the evidence fresh and binds it
//     to the account.
//   - The SHA-256 digest of the DER SubjectPublicKeyInfo of the key the order
//     will be finalized with. The CSR has not been sent yet, so the digest is
//     stored on the authorization and finalize compares it with the CSR's key.
//
// A TDX quote or SEV-SNP report carries the 64 bytes as its report data; a
// Confidential Space token carries each digest, base64url encoded without
// padding, as its first two eat_nonce values.
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
	case len(bound) != provisioner.RemoteAttestationBoundSize:
		return NewErrorISE("remote attestation binds %d bytes, not %d", len(bound), provisioner.RemoteAttestationBoundSize)
	}

	keyAuth, err := KeyAuthorization(ch.FreshnessNonce, jwk)
	if err != nil {
		return err
	}
	keyAuthDigest := sha256.Sum256([]byte(keyAuth))
	if subtle.ConstantTimeCompare(bound[:sha256.Size], keyAuthDigest[:]) != 1 {
		return storeError(ctx, db, ch, true, NewDetailedError(ErrorBadAttestationStatementType,
			"the evidence does not bind the key authorization of the challenge"))
	}

	az, err := db.GetAuthorization(ctx, ch.AuthorizationID)
	if err != nil {
		return WrapErrorISE(err, "error loading authorization")
	}
	az.Attestation = &webhook.Attestation{
		Challenge:              string(REMOTEATTEST01),
		Hint:                   az.Identifier.Value,
		FreshnessNonce:         ch.FreshnessNonce,
		KeyAuthorizationDigest: hex.EncodeToString(keyAuthDigest[:]),
		KeyDigest:              hex.EncodeToString(bound[sha256.Size:]),
		Result:                 result,
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

// remoteAttestationKeyDigest returns the hex encoded SHA-256 digest of the DER
// SubjectPublicKeyInfo of the CSR's key, which remote-attest-01 evidence binds.
func remoteAttestationKeyDigest(csr *x509.CertificateRequest) string {
	sum := sha256.Sum256(csr.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}
