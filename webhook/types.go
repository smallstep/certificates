package webhook

import (
	"fmt"
	"time"

	"go.step.sm/crypto/sshutil"
	"go.step.sm/crypto/x509util"

	"github.com/smallstep/certificates/attestation"
)

// ResponseBody is the body returned by webhook servers.
type ResponseBody struct {
	Data  any    `json:"data"`
	Allow bool   `json:"allow"`
	Error *Error `json:"error,omitempty"`
}

// Error provides details explaining why the webhook was not permitted.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s (%s)", e.Message, e.Code)
}

// X509CertificateRequest is the certificate request sent to webhook servers for
// enriching webhooks when signing x509 certificates
type X509CertificateRequest struct {
	*x509util.CertificateRequest
	PublicKey          []byte `json:"publicKey"`
	PublicKeyAlgorithm string `json:"publicKeyAlgorithm"`
	Raw                []byte `json:"raw"`
}

// X509Certificate is the certificate sent to webhook servers for authorizing
// webhooks when signing x509 certificates
type X509Certificate struct {
	*x509util.Certificate
	PublicKey          []byte    `json:"publicKey"`
	PublicKeyAlgorithm string    `json:"publicKeyAlgorithm"`
	NotBefore          time.Time `json:"notBefore"`
	NotAfter           time.Time `json:"notAfter"`
	Raw                []byte    `json:"raw"`
}

// SSHCertificateRequest is the certificate request sent to webhook servers for
// enriching webhooks when signing SSH certificates
type SSHCertificateRequest struct {
	PublicKey  []byte   `json:"publicKey"`
	Type       string   `json:"type"`
	KeyID      string   `json:"keyID"`
	Principals []string `json:"principals"`
}

// SSHCertificate is the certificate sent to webhook servers for authorizing
// webhooks when signing SSH certificates
type SSHCertificate struct {
	*sshutil.Certificate
	PublicKey    []byte `json:"publicKey"`
	SignatureKey []byte `json:"signatureKey"`
	ValidBefore  uint64 `json:"validBefore"`
	ValidAfter   uint64 `json:"validAfter"`
}

// AttestationData is data validated by acme device-attest-01 challenge
type AttestationData struct {
	PermanentIdentifier string `json:"permanentIdentifier"`
}

// Attestation is the attestation evidence an ACME remote-attest-01 challenge
// verified (draft-ietf-acme-rats), sent to webhook servers when the order is
// finalized and given to certificate templates as .Attestation.
//
// The evidence binds two SHA-256 digests: of the challenge's key authorization,
// and of the DER SubjectPublicKeyInfo of the certificate's key. The CA has
// checked both, so the certificate's key is the attested one. Binary values are
// hex encoded. The fields of the embedded attestation.Result, the format and the
// verified measurements or claims, are at the top level.
type Attestation struct {
	// Challenge is the challenge type that verified the evidence,
	// remote-attest-01.
	Challenge string `json:"challenge"`
	// Hint is the value of the order's remote-attestation identifier.
	Hint string `json:"hint"`
	// FreshnessNonce is the challenge's freshness nonce.
	FreshnessNonce string `json:"freshnessNonce"`
	// KeyAuthorizationDigest is the SHA-256 digest of the challenge's key
	// authorization, which the evidence binds.
	KeyAuthorizationDigest string `json:"keyAuthorizationDigest"`
	// KeyDigest is the SHA-256 digest of the DER SubjectPublicKeyInfo of the
	// certificate's key, which the evidence binds.
	KeyDigest string `json:"keyDigest"`
	*attestation.Result
}

// X5CCertificate is the authorization certificate sent to webhook servers for
// enriching or authorizing webhooks when signing X509 or SSH certificates using
// the X5C provisioner.
type X5CCertificate struct {
	Raw                []byte    `json:"raw"`
	PublicKey          []byte    `json:"publicKey"`
	PublicKeyAlgorithm string    `json:"publicKeyAlgorithm"`
	NotBefore          time.Time `json:"notBefore"`
	NotAfter           time.Time `json:"notAfter"`
}

// RequestBody is the body sent to webhook servers.
type RequestBody struct {
	Timestamp       time.Time `json:"timestamp"`
	ProvisionerName string    `json:"provisionerName,omitempty"`
	// Only set after successfully completing acme device-attest-01 challenge
	AttestationData *AttestationData `json:"attestationData,omitempty"`
	// Only set after successfully completing acme remote-attest-01 challenge
	Attestation *Attestation `json:"attestation,omitempty"`
	// Set for most provisioners, but not acme or scep
	// Token any `json:"token,omitempty"`
	// Exactly one of the remaining fields should be set
	X509CertificateRequest *X509CertificateRequest `json:"x509CertificateRequest,omitempty"`
	X509Certificate        *X509Certificate        `json:"x509Certificate,omitempty"`
	SSHCertificateRequest  *SSHCertificateRequest  `json:"sshCertificateRequest,omitempty"`
	SSHCertificate         *SSHCertificate         `json:"sshCertificate,omitempty"`
	// Only set for SCEP webhook requests
	SCEPChallenge        string `json:"scepChallenge,omitempty"`
	SCEPTransactionID    string `json:"scepTransactionID,omitempty"`
	SCEPErrorCode        int    `json:"scepErrorCode,omitempty"`
	SCEPErrorDescription string `json:"scepErrorDescription,omitempty"`
	// Only set for X5C provisioners
	X5CCertificate *X5CCertificate `json:"x5cCertificate,omitempty"`
	// Set for X5C, AWS, GCP, and Azure provisioners
	AuthorizationPrincipal string `json:"authorizationPrincipal,omitempty"`
}
