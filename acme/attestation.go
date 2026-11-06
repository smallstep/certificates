package acme

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"slices"

	"github.com/fxamacker/cbor/v2"
	"github.com/smallstep/certificates/authority/provisioner"
	"go.step.sm/crypto/jose"
)

// DeviceAttestationParams supplies the expected device-attest-01 bindings.
// The caller must authorize Identifier and issue, expire, and consume Token.
// AccountKey is the ACME account key used to form the key authorization; Apple
// statements bind directly to Token and do not use AccountKey.
type DeviceAttestationParams struct {
	Token      string
	Identifier string
	AccountKey *jose.JSONWebKey
}

// DeviceAttestationResult describes the verified statement. Fingerprint uses
// keyutil.Fingerprint's default encoding and must be compared with the key the
// caller intends to enroll or certify. It is not an authorization decision.
type DeviceAttestationResult struct {
	Format      string
	Fingerprint string
	// ChallengeBound is false for legacy Apple statements without a nonce.
	ChallengeBound bool
	// IdentifierBound reports a nonempty expected identifier attested by the statement.
	// It is false for TPM statements without permanent identifiers.
	// ACME binds these later through the CSR subject; standalone callers must
	// apply an equivalent check or reject the result.
	IdentifierBound bool
}

// VerifyDeviceAttestation verifies a CBOR device-attest-01 attestation object
// without reading or updating an ACME database. It enforces the provisioner's
// format and trust-root policy, signatures, and the challenge and identifier
// checks used by ACME. Android additionally requires a *provisioner.ACME for
// its Android-specific policies. attObj is raw CBOR, not the base64url-encoded
// JSON challenge response.
//
// Existing ACME compatibility is preserved: Apple statements may omit their
// nonce and TPM statements may omit permanent identifiers. Callers must inspect
// ChallengeBound and IdentifierBound and reject absent bindings unless they
// provide equivalent assurance elsewhere. A successful result alone does not
// prove freshness: the caller must enforce Token's lifecycle and compare the
// returned Fingerprint with the public key being enrolled or certified.
func VerifyDeviceAttestation(ctx context.Context, prov Provisioner, params DeviceAttestationParams, attObj []byte) (*DeviceAttestationResult, error) {
	ch := &Challenge{Token: params.Token, Value: params.Identifier}
	jwk := params.AccountKey
	if len(attObj) == 0 || bytes.Equal(attObj, []byte("{}")) {
		return nil, NewDetailedError(ErrorBadAttestationStatementType, "attObj must not be empty")
	}

	cborDecoderOptions := cbor.DecOptions{}
	cborDecoder, err := cborDecoderOptions.DecMode()
	if err != nil {
		return nil, WrapErrorISE(err, "failed creating CBOR decoder")
	}

	if err := cborDecoder.Wellformed(attObj); err != nil {
		return nil, NewDetailedError(ErrorBadAttestationStatementType, "attObj is not well formed CBOR: %v", err)
	}

	att := attestationObject{}
	if err := cborDecoder.Unmarshal(attObj, &att); err != nil {
		return nil, WrapErrorISE(err, "failed unmarshalling CBOR")
	}

	format := att.Format
	if prov == nil {
		return nil, NewErrorISE("attestation provisioner is required")
	}
	result := &DeviceAttestationResult{Format: format}
	if !prov.IsAttestationFormatEnabled(ctx, provisioner.ACMEAttestationFormat(format)) {
		if format != "apple" && format != "step" && format != "tpm" && format != "android-key" {
			return nil, NewDetailedError(ErrorBadAttestationStatementType, "unsupported attestation object format %q", format)
		}

		return nil, NewError(ErrorBadAttestationStatementType, "attestation format %q is not enabled", format)
	}

	switch format {
	case "android-key":
		data, err := doAndroidKeyAttestationFormat(ctx, prov, ch, jwk, &att)
		if err != nil {
			if acmeError, ok := errors.AsType[*Error](err); ok {
				return nil, acmeError
			}
			return nil, WrapErrorISE(err, "error validating attestation")
		}

		// Enforce hardware security level (TrustedEnvironment or StrongBox; Software not allowed)
		if data.Attestation.AttestationSecurityLevel < 1 {
			return nil, NewDetailedError(ErrorBadAttestationStatementType, "insufficient security level: %d", data.Attestation.AttestationSecurityLevel)
		}

		// Enforce hardware backed device serial
		if ch.Value != string(data.Attestation.TeeEnforced.AttestationIdSerial) {
			subproblem := NewSubproblemWithIdentifier(
				ErrorRejectedIdentifierType,
				Identifier{Type: "permanent-identifier", Value: ch.Value},
				"challenge identifier %q doesn't match any of the attested hardware identifiers %q",
				ch.Value, []string{string(data.Attestation.TeeEnforced.AttestationIdSerial)},
			)
			return nil, NewDetailedError(ErrorBadAttestationStatementType, "permanent identifier does not match").AddSubproblems(subproblem)
		}

		// Update attestation key fingerprint to compare against the CSR
		result.Fingerprint = data.Fingerprint
		result.IdentifierBound = ch.Value != ""
		result.ChallengeBound = true
	case "apple":
		data, err := doAppleAttestationFormat(ctx, prov, ch, &att)
		if err != nil {
			if acmeError, ok := errors.AsType[*Error](err); ok {
				return nil, acmeError
			}
			return nil, WrapErrorISE(err, "error validating attestation")
		}

		// Validate nonce with SHA-256 of the token.
		if len(data.Nonce) != 0 {
			sum := sha256.Sum256([]byte(ch.Token))
			if subtle.ConstantTimeCompare(data.Nonce, sum[:]) != 1 {
				return nil, NewDetailedError(ErrorBadAttestationStatementType, "challenge token does not match")
			}
		}

		// Validate Apple's ClientIdentifier (Identifier.Value) with device
		// identifiers.
		//
		// Note: We might want to use an external service for this.
		if data.UDID != ch.Value && data.SerialNumber != ch.Value {
			subproblem := NewSubproblemWithIdentifier(
				ErrorRejectedIdentifierType,
				Identifier{Type: "permanent-identifier", Value: ch.Value},
				"challenge identifier %q doesn't match any of the attested hardware identifiers %q", ch.Value, []string{data.UDID, data.SerialNumber},
			)
			return nil, NewDetailedError(ErrorBadAttestationStatementType, "permanent identifier does not match").AddSubproblems(subproblem)
		}

		// Update attestation key fingerprint to compare against the CSR
		result.Fingerprint = data.Fingerprint
		result.IdentifierBound = ch.Value != ""
		result.ChallengeBound = len(data.Nonce) != 0
	case "step":
		data, err := doStepAttestationFormat(ctx, prov, ch, jwk, &att)
		if err != nil {
			if acmeError, ok := errors.AsType[*Error](err); ok {
				return nil, acmeError
			}
			return nil, WrapErrorISE(err, "error validating attestation")
		}

		// Validate the YubiKey serial number from the attestation
		// certificate with the challenged Order value.
		//
		// Note: We might want to use an external service for this.
		if data.SerialNumber != ch.Value {
			subproblem := NewSubproblemWithIdentifier(
				ErrorRejectedIdentifierType,
				Identifier{Type: "permanent-identifier", Value: ch.Value},
				"challenge identifier %q doesn't match the attested hardware identifier %q", ch.Value, data.SerialNumber,
			)
			return nil, NewDetailedError(ErrorBadAttestationStatementType, "permanent identifier does not match").AddSubproblems(subproblem)
		}

		// Update attestation key fingerprint to compare against the CSR
		result.Fingerprint = data.Fingerprint
		result.IdentifierBound = ch.Value != ""
		result.ChallengeBound = true

	case "tpm":
		data, err := doTPMAttestationFormat(ctx, prov, ch, jwk, &att)
		if err != nil {
			if acmeError, ok := errors.AsType[*Error](err); ok {
				return nil, acmeError
			}
			return nil, WrapErrorISE(err, "error validating attestation")
		}

		// TODO(hs): currently this will allow a request for which no PermanentIdentifiers have been
		// extracted from the AK certificate. This is currently the case for AK certs from the CLI, as we
		// haven't implemented a way for AK certs requested by the CLI to always contain the requested
		// PermanentIdentifier. Omitting the check below doesn't allow just any request, as the Order can
		// still fail if the challenge value isn't equal to the CSR subject.
		if len(data.PermanentIdentifiers) > 0 && !slices.Contains(data.PermanentIdentifiers, ch.Value) { // TODO(hs): add support for HardwareModuleName
			subproblem := NewSubproblemWithIdentifier(
				ErrorRejectedIdentifierType,
				Identifier{Type: "permanent-identifier", Value: ch.Value},
				"challenge identifier %q doesn't match any of the attested hardware identifiers %q", ch.Value, data.PermanentIdentifiers,
			)
			return nil, NewDetailedError(ErrorBadAttestationStatementType, "permanent identifier does not match").AddSubproblems(subproblem)
		}

		// Update attestation key fingerprint to compare against the CSR
		result.Fingerprint = data.Fingerprint
		result.IdentifierBound = ch.Value != "" && len(data.PermanentIdentifiers) != 0
		result.ChallengeBound = true
	default:
		return nil, NewDetailedError(ErrorBadAttestationStatementType, "unsupported attestation object format %q", format)
	}

	return result, nil
}
