package scep

import (
	"crypto/x509"
	"encoding/asn1"

	microscep "github.com/micromdm/scep/scep"

	//"github.com/smallstep/certificates/scep/pkcs7"

	"go.mozilla.org/pkcs7"
)

// SCEP OIDs
var (
	oidSCEPmessageType    = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 2}
	oidSCEPpkiStatus      = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 3}
	oidSCEPfailInfo       = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 4}
	oidSCEPsenderNonce    = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 5}
	oidSCEPrecipientNonce = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 6}
	oidSCEPtransactionID  = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 7}
	oidChallengePassword  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}
)

// PKIMessage defines the possible SCEP message types
type PKIMessage struct {
	microscep.TransactionID
	microscep.MessageType
	microscep.SenderNonce
	*microscep.CSRReqMessage

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
	microscep.PKIStatus
	microscep.RecipientNonce
	microscep.FailInfo

	Certificate *x509.Certificate

	degenerate []byte
}
