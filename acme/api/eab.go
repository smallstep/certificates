package api

import (
	"context"
	"encoding/json"
	"errors"

	"go.step.sm/crypto/jose"

	"github.com/smallstep/certificates/acme"
)

// ExternalAccountBinding represents the ACME externalAccountBinding JWS
type ExternalAccountBinding struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Sig       string `json:"signature"`
}

// validateExternalAccountBinding validates the externalAccountBinding property in a call to new-account.
func validateExternalAccountBinding(ctx context.Context, nar *NewAccountRequest) (*acme.ExternalAccountKey, error) {
	acmeProv, err := acmeProvisionerFromContext(ctx)
	if err != nil {
		return nil, acme.WrapErrorISE(err, "could not load ACME provisioner from context")
	}

	if !acmeProv.RequireEAB {
		//nolint:nilnil // legacy
		return nil, nil
	}

	if nar.ExternalAccountBinding == nil {
		return nil, acme.NewError(acme.ErrorExternalAccountRequiredType, "no external account binding provided")
	}

	eabJSONBytes, err := json.Marshal(nar.ExternalAccountBinding)
	if err != nil {
		return nil, acme.WrapErrorISE(err, "error marshaling externalAccountBinding into bytes")
	}

	eabJWS, err := jose.ParseJWS(string(eabJSONBytes))
	if err != nil {
		return nil, acme.WrapErrorISE(err, "error parsing externalAccountBinding jws")
	}

	// TODO(hs): implement strategy pattern to allow for different ways of verification (i.e. webhook call) based on configuration?

	keyID, acmeErr := validateEABJWS(ctx, eabJWS)
	if acmeErr != nil {
		return nil, acmeErr
	}

	db := acme.MustDatabaseFromContext(ctx)
	externalAccountKey, err := db.GetExternalAccountKey(ctx, acmeProv.ID, keyID)
	if err != nil {
		var ae *acme.Error
		if errors.As(err, &ae) {
			return nil, acme.WrapError(acme.ErrorUnauthorizedType, err, "the field 'kid' references an unknown key")
		}
		return nil, acme.WrapErrorISE(err, "error retrieving external account key")
	}

	if externalAccountKey == nil {
		return nil, acme.NewError(acme.ErrorUnauthorizedType, "the field 'kid' references an unknown key")
	}

	if len(externalAccountKey.HmacKey) == 0 {
		return nil, acme.NewError(acme.ErrorServerInternalType, "external account binding key with id '%s' does not have secret bytes", keyID)
	}

	if externalAccountKey.AlreadyBound() {
		return nil, acme.NewError(acme.ErrorUnauthorizedType, "external account binding key with id '%s' was already bound to account '%s' on %s", keyID, externalAccountKey.AccountID, externalAccountKey.BoundAt)
	}

	payload, err := eabJWS.Verify(externalAccountKey.HmacKey)
	if err != nil {
		return nil, acme.WrapErrorISE(err, "error verifying externalAccountBinding signature")
	}

	jwk, err := jwkFromContext(ctx)
	if err != nil {
		return nil, err
	}

	var payloadJWK *jose.JSONWebKey
	if err = json.Unmarshal(payload, &payloadJWK); err != nil {
		return nil, acme.WrapError(acme.ErrorMalformedType, err, "error unmarshaling payload into jwk")
	}

	if !keysAreEqual(jwk, payloadJWK) {
		return nil, acme.NewError(acme.ErrorUnauthorizedType, "keys in jws and eab payload do not match")
	}

	return externalAccountKey, nil
}

// keysAreEqual performs an equality check on two JWKs by comparing
// the (base64 encoding) of the Key IDs.
func keysAreEqual(x, y *jose.JSONWebKey) bool {
	if x == nil || y == nil {
		return false
	}
	digestX, errX := acme.KeyToID(x)
	digestY, errY := acme.KeyToID(y)
	if errX != nil || errY != nil {
		return false
	}
	return digestX == digestY
}

// validateEABJWS verifies the contents of the External Account Binding JWS.
// The protected header of the JWS MUST meet the following criteria:
//
//   - The "alg" field MUST indicate a MAC-based algorithm
//   - The "kid" field MUST contain the key identifier provided by the CA
//   - The "nonce" field MUST NOT be present
//   - The "url" field MUST be set to the same value as the outer JWS
func validateEABJWS(ctx context.Context, jws *jose.JSONWebSignature) (string, *acme.Error) {
	if jws == nil {
		return "", acme.NewErrorISE("no JWS provided")
	}

	if len(jws.Signatures) != 1 {
		return "", acme.NewError(acme.ErrorMalformedType, "JWS must have one signature")
	}

	header := jws.Signatures[0].Protected
	algorithm := header.Algorithm
	keyID := header.KeyID
	nonce := header.Nonce

	if !(algorithm == jose.HS256 || algorithm == jose.HS384 || algorithm == jose.HS512) {
		return "", acme.NewError(acme.ErrorMalformedType, "'alg' field set to invalid algorithm '%s'", algorithm)
	}

	if keyID == "" {
		return "", acme.NewError(acme.ErrorMalformedType, "'kid' field is required")
	}

	if nonce != "" {
		return "", acme.NewError(acme.ErrorMalformedType, "'nonce' must not be present")
	}

	jwsURL, ok := header.ExtraHeaders["url"]
	if !ok {
		return "", acme.NewError(acme.ErrorMalformedType, "'url' field is required")
	}

	outerJWS, err := jwsFromContext(ctx)
	if err != nil {
		return "", acme.WrapErrorISE(err, "could not retrieve outer JWS from context")
	}

	if len(outerJWS.Signatures) != 1 {
		return "", acme.NewError(acme.ErrorMalformedType, "outer JWS must have one signature")
	}

	outerJWSURL, ok := outerJWS.Signatures[0].Protected.ExtraHeaders["url"]
	if !ok {
		return "", acme.NewError(acme.ErrorMalformedType, "'url' field must be set in outer JWS")
	}

	if jwsURL != outerJWSURL {
		return "", acme.NewError(acme.ErrorMalformedType, "'url' field is not the same value as the outer JWS")
	}

	return keyID, nil
}
