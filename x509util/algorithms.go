package x509util

import (
	"crypto/x509"
	"strings"

	"github.com/pkg/errors"
)

// List of signature algorithms, all of them have values in upper case to match
// them with the string representation.
// nolint:golint
const (
	MD2_RSA       = "MD2-RSA"
	MD5_RSA       = "MD5-RSA"
	SHA1_RSA      = "SHA1-RSA"
	SHA256_RSA    = "SHA256-RSA"
	SHA384_RSA    = "SHA384-RSA"
	SHA512_RSA    = "SHA512-RSA"
	SHA256_RSAPSS = "SHA256-RSAPSS"
	SHA384_RSAPSS = "SHA384-RSAPSS"
	SHA512_RSAPSS = "SHA512-RSAPSS"
	DSA_SHA1      = "DSA-SHA1"
	DSA_SHA256    = "DSA-SHA256"
	ECDSA_SHA1    = "ECDSA-SHA1"
	ECDSA_SHA256  = "ECDSA-SHA256"
	ECDSA_SHA384  = "ECDSA-SHA384"
	ECDSA_SHA512  = "ECDSA-SHA512"
	Ed25519       = "ED25519"
)

// SignatureAlgorithm is the JSON representation of the X509 signature algorithms
type SignatureAlgorithm x509.SignatureAlgorithm

// Set sets the signature algorithm in the given certificate.
func (s SignatureAlgorithm) Set(c *x509.Certificate) {
	c.SignatureAlgorithm = x509.SignatureAlgorithm(s)
}

// UnmarshalJSON implements the json.Unmarshal interface and unmarshals and
// validates a string as a SignatureAlgorithm.
func (s *SignatureAlgorithm) UnmarshalJSON(data []byte) error {
	name, err := unmarshalString(data)
	if err != nil {
		return err
	}

	var sa x509.SignatureAlgorithm
	switch strings.ToUpper(name) {
	case MD2_RSA:
		sa = x509.MD2WithRSA
	case MD5_RSA:
		sa = x509.MD5WithRSA
	case SHA1_RSA:
		sa = x509.SHA1WithRSA
	case SHA256_RSA:
		sa = x509.SHA256WithRSA
	case SHA384_RSA:
		sa = x509.SHA384WithRSA
	case SHA512_RSA:
		sa = x509.SHA512WithRSA
	case SHA256_RSAPSS:
		sa = x509.SHA256WithRSAPSS
	case SHA384_RSAPSS:
		sa = x509.SHA384WithRSAPSS
	case SHA512_RSAPSS:
		sa = x509.SHA512WithRSAPSS
	case DSA_SHA1:
		sa = x509.DSAWithSHA1
	case DSA_SHA256:
		sa = x509.DSAWithSHA256
	case ECDSA_SHA1:
		sa = x509.ECDSAWithSHA1
	case ECDSA_SHA256:
		sa = x509.ECDSAWithSHA256
	case ECDSA_SHA384:
		sa = x509.ECDSAWithSHA384
	case ECDSA_SHA512:
		sa = x509.ECDSAWithSHA512
	case Ed25519:
		sa = x509.PureEd25519
	default:
		return errors.Errorf("unsupported signatureAlgorithm %s", name)
	}

	*s = SignatureAlgorithm(sa)
	return nil
}
