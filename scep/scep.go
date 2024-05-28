// Package scep implements Simple Certificate Enrollment Protocol related functionality.
package scep

import (
	"crypto/x509"
	"encoding/asn1"

	"github.com/smallstep/pkcs7"
	smallscep "github.com/smallstep/scep"
)

// FailInfoName models the name/value of failInfo
type FailInfoName smallscep.FailInfo

// FailInfo models a failInfo object consisting of a
// name/identifier and a failInfoText, the latter of
// which can be more descriptive and is intended to be
// read by humans.
type FailInfo struct {
	Name FailInfoName
	Text string
}

// SCEP OIDs
var (
	oidSCEPmessageType    = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 2}
	oidSCEPpkiStatus      = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 3}
	oidSCEPfailInfo       = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 4}
	oidSCEPsenderNonce    = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 5}
	oidSCEPrecipientNonce = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 6}
	oidSCEPtransactionID  = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 7}
	oidSCEPfailInfoText   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 24, 1}
	//oidChallengePassword  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}
)

// PKIMessage defines the possible SCEP message types
type PKIMessage struct {
	smallscep.TransactionID
	smallscep.MessageType
	smallscep.SenderNonce
	*smallscep.CSRReqMessage

	*CertRepMessage

	// DER Encoded PKIMessage
	Raw []byte

	// parsed
	P7 *pkcs7.PKCS7

	// decrypted enveloped content
	pkiEnvelope []byte

	// Used to sign message
	Recipients []*x509.Certificate
}

// CertRepMessage is a type of PKIMessage
type CertRepMessage struct {
	smallscep.PKIStatus
	smallscep.RecipientNonce
	smallscep.FailInfo

	Certificate *x509.Certificate

	degenerate []byte
}
