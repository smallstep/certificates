// Package tpm verifies attestation statements of the "tpm" format of ACME
// device-attest-01 challenges, made with the attestation keys of TPM 2.0
// devices.
package tpm

import (
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/smallstep/go-attestation/attest"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/x509util"

	"github.com/smallstep/certificates/attestation"
	"github.com/smallstep/certificates/internal/cast"
)

var (
	oidSubjectAlternativeName = asn1.ObjectIdentifier{2, 5, 29, 17}
)

// Data is what a verified "tpm" attestation statement attests.
type Data struct {
	// Certificate is the AK certificate, the leaf of the x5c chain.
	Certificate *x509.Certificate
	// VerifiedChains are the chains from the AK certificate to the roots.
	VerifiedChains [][]*x509.Certificate
	// PermanentIdentifiers are the permanent identifiers in the Subject
	// Alternative Names of the AK certificate.
	PermanentIdentifiers []string
	// Fingerprint is the fingerprint of the attested key.
	Fingerprint string
}

// coseAlgorithmIdentifier models a COSEAlgorithmIdentifier.
// Also see https://www.w3.org/TR/webauthn-2/#sctn-alg-identifier.
type coseAlgorithmIdentifier int32

const (
	coseAlgES256 = coseAlgorithmIdentifier(-7)
	coseAlgRS256 = coseAlgorithmIdentifier(-257)
	coseAlgRS1   = coseAlgorithmIdentifier(-65535) // deprecated, but (still) often used in TPMs
)

// Verify verifies a "tpm" attestation statement: the x5c chain of its AK
// certificate against roots, the requirements on the AK certificate, the
// certification of the attested key by the AK, and that the certification's
// extra data is the SHA-256 digest of keyAuth, the key authorization of the
// challenge. It returns what the AK certificate and the certification attest.
// There are no default roots: Verify fails if roots is nil. Errors of the
// statement match attestation.ErrInvalidEvidence.
func Verify(attStmt map[string]any, roots *x509.CertPool, keyAuth []byte) (*Data, error) {
	ver, ok := attStmt["ver"].(string)
	if !ok {
		return nil, attestation.Invalidf("ver not present")
	}
	if ver != "2.0" {
		return nil, attestation.Invalidf("version %q is not supported", ver)
	}

	x5c, ok := attStmt["x5c"].([]any)
	if !ok {
		return nil, attestation.Invalidf("x5c not present")
	}
	if len(x5c) == 0 {
		return nil, attestation.Invalidf("x5c is empty")
	}

	akCertBytes, ok := x5c[0].([]byte)
	if !ok {
		return nil, attestation.Invalidf("x5c is malformed")
	}
	akCert, err := x509.ParseCertificate(akCertBytes)
	if err != nil {
		return nil, attestation.Invalidf("x5c is malformed: %w", err)
	}

	intermediates := x509.NewCertPool()
	for _, v := range x5c[1:] {
		intCertBytes, vok := v.([]byte)
		if !vok {
			return nil, attestation.Invalidf("x5c is malformed")
		}
		intCert, err := x509.ParseCertificate(intCertBytes)
		if err != nil {
			return nil, attestation.Invalidf("x5c is malformed: %w", err)
		}
		intermediates.AddCert(intCert)
	}

	// TODO(hs): this can be removed when permanent-identifier/hardware-module-name are handled correctly in
	// the stdlib in https://cs.opensource.google/go/go/+/refs/tags/go1.19:src/crypto/x509/parser.go;drc=b5b2cf519fe332891c165077f3723ee74932a647;l=362,
	// but I doubt that will happen.
	if len(akCert.UnhandledCriticalExtensions) > 0 {
		unhandledCriticalExtensions := akCert.UnhandledCriticalExtensions[:0]
		for _, extOID := range akCert.UnhandledCriticalExtensions {
			if !extOID.Equal(oidSubjectAlternativeName) {
				// critical extensions other than the Subject Alternative Name remain unhandled
				unhandledCriticalExtensions = append(unhandledCriticalExtensions, extOID)
			}
		}
		akCert.UnhandledCriticalExtensions = unhandledCriticalExtensions
	}

	if roots == nil {
		return nil, errors.New("no root CA bundle available to verify the attestation certificate")
	}

	// verify that the AK certificate was signed by a trusted root,
	// chained to by the intermediates provided by the client. As part
	// of building the verified certificate chain, the signature over the
	// AK certificate is checked to be a valid signature of one of the
	// provided intermediates. Signatures over the intermediates are in
	// turn also verified to be valid signatures from one of the trusted
	// roots.
	verifiedChains, err := akCert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now().Truncate(time.Second),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return nil, attestation.Invalidf("x5c is not valid: %w", err)
	}

	// validate additional AK certificate requirements
	if err := validateAKCertificate(akCert); err != nil {
		return nil, attestation.Invalidf("AK certificate is not valid: %w", err)
	}

	// TODO(hs): implement revocation check; Verify() doesn't perform CRL check nor OCSP lookup.

	sans, err := x509util.ParseSubjectAlternativeNames(akCert)
	if err != nil {
		return nil, attestation.Invalidf("failed parsing AK certificate Subject Alternative Names: %w", err)
	}

	permanentIdentifiers := make([]string, len(sans.PermanentIdentifiers))
	for i, pi := range sans.PermanentIdentifiers {
		permanentIdentifiers[i] = pi.Identifier
	}

	// extract and validate pubArea, sig, certInfo and alg properties from the request body
	pubArea, ok := attStmt["pubArea"].([]byte)
	if !ok {
		return nil, attestation.Invalidf("invalid pubArea in attestation statement")
	}
	if len(pubArea) == 0 {
		return nil, attestation.Invalidf("pubArea is empty")
	}

	sig, ok := attStmt["sig"].([]byte)
	if !ok {
		return nil, attestation.Invalidf("invalid sig in attestation statement")
	}
	if len(sig) == 0 {
		return nil, attestation.Invalidf("sig is empty")
	}

	certInfo, ok := attStmt["certInfo"].([]byte)
	if !ok {
		return nil, attestation.Invalidf("invalid certInfo in attestation statement")
	}
	if len(certInfo) == 0 {
		return nil, attestation.Invalidf("certInfo is empty")
	}

	alg, ok := attStmt["alg"].(int64)
	if !ok {
		return nil, attestation.Invalidf("invalid alg in attestation statement")
	}

	algI32, err := cast.SafeInt32(alg)
	if err != nil {
		return nil, attestation.Invalidf("invalid alg %d in attestation statement: %w", alg, err)
	}

	var hash crypto.Hash
	switch coseAlgorithmIdentifier(algI32) {
	case coseAlgRS256, coseAlgES256:
		hash = crypto.SHA256
	case coseAlgRS1:
		hash = crypto.SHA1
	default:
		return nil, attestation.Invalidf("invalid alg %d in attestation statement", alg)
	}

	// recreate the generated key certification parameter values and verify
	// the attested key using the public key of the AK.
	certificationParameters := &attest.CertificationParameters{
		Public:            pubArea,  // the public key that was attested
		CreateAttestation: certInfo, // the attested properties of the key
		CreateSignature:   sig,      // signature over the attested properties
	}
	verifyOpts := attest.VerifyOpts{
		Public: akCert.PublicKey, // public key of the AK that attested the key
		Hash:   hash,
	}
	if err = certificationParameters.Verify(verifyOpts); err != nil {
		return nil, attestation.Invalidf("invalid certification parameters: %w", err)
	}

	// decode the "certInfo" data. This won't fail, as it's also done as part of Verify().
	tpmCertInfo, err := tpm2.DecodeAttestationData(certInfo)
	if err != nil {
		return nil, attestation.Invalidf("failed decoding attestation data: %w", err)
	}

	hashedKeyAuth := sha256.Sum256(keyAuth)

	// verify the WebAuthn object contains the expect key authorization digest, which is carried
	// within the encoded `certInfo` property of the attestation statement.
	if subtle.ConstantTimeCompare(hashedKeyAuth[:], []byte(tpmCertInfo.ExtraData)) == 0 {
		return nil, attestation.Invalidf("key authorization invalid")
	}

	// decode the (attested) public key and determine its fingerprint.  This won't fail, as it's also done as part of Verify().
	pub, err := tpm2.DecodePublic(pubArea)
	if err != nil {
		return nil, attestation.Invalidf("failed decoding pubArea: %w", err)
	}

	publicKey, err := pub.Key()
	if err != nil {
		return nil, attestation.Invalidf("failed getting public key: %w", err)
	}

	data := &Data{
		Certificate:          akCert,
		VerifiedChains:       verifiedChains,
		PermanentIdentifiers: permanentIdentifiers,
	}

	if data.Fingerprint, err = keyutil.Fingerprint(publicKey); err != nil {
		return nil, fmt.Errorf("error calculating key fingerprint: %w", err)
	}

	// TODO(hs): pass more attestation data, so that that can be used/recorded too?
	return data, nil
}

var (
	oidExtensionExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidTCGKpAIKCertificate       = asn1.ObjectIdentifier{2, 23, 133, 8, 3}
)

// validateAKCertificate validates the X.509 AK certificate to be
// in accordance with the required properties. The requirements come from:
// https://www.w3.org/TR/webauthn-2/#sctn-tpm-cert-requirements.
//
//   - Version MUST be set to 3.
//   - Subject field MUST be set to empty.
//   - The Subject Alternative Name extension MUST be set as defined
//     in [TPMv2-EK-Profile] section 3.2.9.
//   - The Extended Key Usage extension MUST contain the OID 2.23.133.8.3
//     ("joint-iso-itu-t(2) international-organizations(23) 133 tcg-kp(8) tcg-kp-AIKCertificate(3)").
//   - The Basic Constraints extension MUST have the CA component set to false.
//   - An Authority Information Access (AIA) extension with entry id-ad-ocsp
//     and a CRL Distribution Point extension [RFC5280] are both OPTIONAL as
//     the status of many attestation certificates is available through metadata
//     services. See, for example, the FIDO Metadata Service.
func validateAKCertificate(c *x509.Certificate) error {
	if c.Version != 3 {
		return fmt.Errorf("AK certificate has invalid version %d; only version 3 is allowed", c.Version)
	}
	if c.Subject.String() != "" {
		return fmt.Errorf("AK certificate subject must be empty; got %q", c.Subject)
	}
	if c.IsCA {
		return errors.New("AK certificate must not be a CA")
	}
	if err := validateAKCertificateExtendedKeyUsage(c); err != nil {
		return err
	}
	return validateAKCertificateSubjectAlternativeNames(c)
}

// validateAKCertificateSubjectAlternativeNames checks if the AK certificate
// has TPM hardware details set.
func validateAKCertificateSubjectAlternativeNames(c *x509.Certificate) error {
	sans, err := x509util.ParseSubjectAlternativeNames(c)
	if err != nil {
		return fmt.Errorf("failed parsing AK certificate Subject Alternative Names: %w", err)
	}

	details := sans.TPMHardwareDetails
	manufacturer, model, version := details.Manufacturer, details.Model, details.Version

	switch {
	case manufacturer == "":
		return errors.New("missing TPM manufacturer")
	case model == "":
		return errors.New("missing TPM model")
	case version == "":
		return errors.New("missing TPM version")
	}

	return nil
}

// validateAKCertificateExtendedKeyUsage checks if the AK certificate
// has the "tcg-kp-AIKCertificate" Extended Key Usage set.
func validateAKCertificateExtendedKeyUsage(c *x509.Certificate) error {
	var (
		valid = false
		ekus  []asn1.ObjectIdentifier
	)
	for _, ext := range c.Extensions {
		if ext.Id.Equal(oidExtensionExtendedKeyUsage) {
			if _, err := asn1.Unmarshal(ext.Value, &ekus); err != nil || len(ekus) == 0 || !ekus[0].Equal(oidTCGKpAIKCertificate) {
				return errors.New("AK certificate is missing Extended Key Usage value tcg-kp-AIKCertificate (2.23.133.8.3)")
			}
			valid = true
		}
	}

	if !valid {
		return errors.New("AK certificate is missing Extended Key Usage extension")
	}

	return nil
}
