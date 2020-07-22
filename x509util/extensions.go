package x509util

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"

	"github.com/pkg/errors"
)

func convertName(s string) string {
	return strings.ReplaceAll(strings.ToLower(s), "_", "")
}

// Names used for key usages.
var (
	KeyUsageDigitalSignature  = convertName("DigitalSignature")
	KeyUsageContentCommitment = convertName("ContentCommitment")
	KeyUsageKeyEncipherment   = convertName("KeyEncipherment")
	KeyUsageDataEncipherment  = convertName("DataEncipherment")
	KeyUsageKeyAgreement      = convertName("KeyAgreement")
	KeyUsageCertSign          = convertName("CertSign")
	KeyUsageCRLSign           = convertName("CRLSign")
	KeyUsageEncipherOnly      = convertName("EncipherOnly")
	KeyUsageDecipherOnly      = convertName("DecipherOnly")
)

// Names used for extended key usages.
var (
	ExtKeyUsageAny                            = convertName("Any")
	ExtKeyUsageServerAuth                     = convertName("ServerAuth")
	ExtKeyUsageClientAuth                     = convertName("ClientAuth")
	ExtKeyUsageCodeSigning                    = convertName("CodeSigning")
	ExtKeyUsageEmailProtection                = convertName("EmailProtection")
	ExtKeyUsageIPSECEndSystem                 = convertName("IPSECEndSystem")
	ExtKeyUsageIPSECTunnel                    = convertName("IPSECTunnel")
	ExtKeyUsageIPSECUser                      = convertName("IPSECUser")
	ExtKeyUsageTimeStamping                   = convertName("TimeStamping")
	ExtKeyUsageOCSPSigning                    = convertName("OCSPSigning")
	ExtKeyUsageMicrosoftServerGatedCrypto     = convertName("MicrosoftServerGatedCrypto")
	ExtKeyUsageNetscapeServerGatedCrypto      = convertName("NetscapeServerGatedCrypto")
	ExtKeyUsageMicrosoftCommercialCodeSigning = convertName("MicrosoftCommercialCodeSigning")
	ExtKeyUsageMicrosoftKernelCodeSigning     = convertName("MicrosoftKernelCodeSigning")
)

// Names used and SubjectAlternativeNames types.
const (
	AutoType  = "auto"
	DNSType   = "dns"
	EmailType = "email"
	IPType    = "ip"
	URIType   = "uri"
)

// Extension is the JSON representation of a raw X.509 extensions.
type Extension struct {
	ID       ObjectIdentifier `json:"id"`
	Critical bool             `json:"critical"`
	Value    []byte           `json:"value"`
}

// newExtensions creates an Extension from a standard pkix.Extension.
func newExtension(e pkix.Extension) Extension {
	return Extension{
		ID:       ObjectIdentifier(e.Id),
		Critical: e.Critical,
		Value:    e.Value,
	}
}

// newExtensions creates a slice of Extension from a slice of pkix.Exntesion.
func newExtensions(extensions []pkix.Extension) []Extension {
	if extensions == nil {
		return nil
	}
	ret := make([]Extension, len(extensions))
	for i, e := range extensions {
		ret[i] = newExtension(e)
	}
	return ret

}

// Set adds the extension to the given X509 certificate.
func (e Extension) Set(c *x509.Certificate) {
	c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{
		Id:       asn1.ObjectIdentifier(e.ID),
		Critical: e.Critical,
		Value:    e.Value,
	})
}

// ObjectIdentifier represents a JSON strings that unmarshals into an ASN1
// object identifier or OID.
type ObjectIdentifier asn1.ObjectIdentifier

// MarshalJSON implements the json.Marshaler interface and returns the string
// version of the asn1.ObjectIdentifier.
func (o ObjectIdentifier) MarshalJSON() ([]byte, error) {
	return json.Marshal(asn1.ObjectIdentifier(o).String())
}

// UnmarshalJSON implements the json.Unmarshaler interface and coverts a strings
// like "2.5.29.17" into an ASN1 object identifier.
func (o *ObjectIdentifier) UnmarshalJSON(data []byte) error {
	s, err := unmarshalString(data)
	if err != nil {
		return err
	}

	oid, err := parseObjectIdentifier(s)
	if err != nil {
		return err
	}
	*o = ObjectIdentifier(oid)
	return nil
}

type SubjectAlternativeName struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func (s SubjectAlternativeName) Set(c *x509.Certificate) {
	switch strings.ToLower(s.Type) {
	case DNSType:
		c.DNSNames = append(c.DNSNames, s.Value)
	case EmailType:
		c.EmailAddresses = append(c.EmailAddresses, s.Value)
	case IPType:
		// The validation of the IP would happen in the unmarshaling, but just
		// to be sure we are only adding valid IPs.
		if ip := net.ParseIP(s.Value); ip != nil {
			c.IPAddresses = append(c.IPAddresses, ip)
		}
	case URIType:
		if u, err := url.Parse(s.Value); err == nil {
			c.URIs = append(c.URIs, u)
		}
	case "", AutoType:
		dnsNames, ips, emails, uris := SplitSANs([]string{s.Value})
		c.DNSNames = append(c.DNSNames, dnsNames...)
		c.IPAddresses = append(c.IPAddresses, ips...)
		c.EmailAddresses = append(c.EmailAddresses, emails...)
		c.URIs = append(c.URIs, uris...)
	default:
		panic(fmt.Sprintf("unsupported subject alternative name type %s", s.Type))
	}
}

// KeyUsage type represents the JSON array used to represent the key usages of a
// X509 certificate.
type KeyUsage x509.KeyUsage

// Set sets the key usage to the given certificate.
func (k KeyUsage) Set(c *x509.Certificate) {
	c.KeyUsage = x509.KeyUsage(k)
}

// UnmarshalJSON implements the json.Unmarshaler interface and coverts a string
// or a list of strings into a key usage.
func (k *KeyUsage) UnmarshalJSON(data []byte) error {
	ms, err := unmarshalMultiString(data)
	if err != nil {
		return err
	}

	*k = 0

	for _, s := range ms {
		var ku x509.KeyUsage
		switch convertName(s) {
		case KeyUsageDigitalSignature:
			ku = x509.KeyUsageDigitalSignature
		case KeyUsageContentCommitment:
			ku = x509.KeyUsageContentCommitment
		case KeyUsageKeyEncipherment:
			ku = x509.KeyUsageKeyEncipherment
		case KeyUsageDataEncipherment:
			ku = x509.KeyUsageDataEncipherment
		case KeyUsageKeyAgreement:
			ku = x509.KeyUsageKeyAgreement
		case KeyUsageCertSign:
			ku = x509.KeyUsageCertSign
		case KeyUsageCRLSign:
			ku = x509.KeyUsageCRLSign
		case KeyUsageEncipherOnly:
			ku = x509.KeyUsageEncipherOnly
		case KeyUsageDecipherOnly:
			ku = x509.KeyUsageDecipherOnly
		default:
			return errors.Errorf("unsupported keyUsage %s", s)
		}
		*k |= KeyUsage(ku)
	}

	return nil
}

// ExtKeyUsage represents a JSON array of extended key usages.
type ExtKeyUsage []x509.ExtKeyUsage

// Set sets the extended key usages in the given certificate.
func (k ExtKeyUsage) Set(c *x509.Certificate) {
	c.ExtKeyUsage = []x509.ExtKeyUsage(k)
}

// UnmarshalJSON implements the json.Unmarshaler interface and coverts a string
// or a list of strings into a list of extended key usages.
func (k *ExtKeyUsage) UnmarshalJSON(data []byte) error {
	ms, err := unmarshalMultiString(data)
	if err != nil {
		return err
	}

	eku := make([]x509.ExtKeyUsage, len(ms))
	for i, s := range ms {
		var ku x509.ExtKeyUsage
		switch convertName(s) {
		case ExtKeyUsageAny:
			ku = x509.ExtKeyUsageAny
		case ExtKeyUsageServerAuth:
			ku = x509.ExtKeyUsageServerAuth
		case ExtKeyUsageClientAuth:
			ku = x509.ExtKeyUsageClientAuth
		case ExtKeyUsageCodeSigning:
			ku = x509.ExtKeyUsageCodeSigning
		case ExtKeyUsageEmailProtection:
			ku = x509.ExtKeyUsageEmailProtection
		case ExtKeyUsageIPSECEndSystem:
			ku = x509.ExtKeyUsageIPSECEndSystem
		case ExtKeyUsageIPSECTunnel:
			ku = x509.ExtKeyUsageIPSECTunnel
		case ExtKeyUsageIPSECUser:
			ku = x509.ExtKeyUsageIPSECUser
		case ExtKeyUsageTimeStamping:
			ku = x509.ExtKeyUsageTimeStamping
		case ExtKeyUsageOCSPSigning:
			ku = x509.ExtKeyUsageOCSPSigning
		case ExtKeyUsageMicrosoftServerGatedCrypto:
			ku = x509.ExtKeyUsageMicrosoftServerGatedCrypto
		case ExtKeyUsageNetscapeServerGatedCrypto:
			ku = x509.ExtKeyUsageNetscapeServerGatedCrypto
		case ExtKeyUsageMicrosoftCommercialCodeSigning:
			ku = x509.ExtKeyUsageMicrosoftCommercialCodeSigning
		case ExtKeyUsageMicrosoftKernelCodeSigning:
			ku = x509.ExtKeyUsageMicrosoftKernelCodeSigning
		default:
			return errors.Errorf("unsupported extKeyUsage %s", s)
		}
		eku[i] = ku
	}

	*k = ExtKeyUsage(eku)
	return nil
}

// SubjectKeyID represents the binary value of the subject key identifier
// extension, this should be the SHA-1 hash of the public key. In JSON this
// value should be a base64-encoded string, and in most cases it should not be
// set because it will be automatically generated.
type SubjectKeyID []byte

// Set sets the subject key identifier to the given certificate.
func (id SubjectKeyID) Set(c *x509.Certificate) {
	c.SubjectKeyId = id
}

// AuthorityKeyID represents the binary value of the authority key identifier
// extension. It should be the subject key identifier of the parent certificate.
// In JSON this value should be a base64-encoded string, and in most cases it
// should not be set, as it will be automatically provided.
type AuthorityKeyID []byte

// Set sets the authority key identifier to the given certificate.
func (id AuthorityKeyID) Set(c *x509.Certificate) {
	c.AuthorityKeyId = id
}

// OCSPServer contains the list of OSCP servers that will be encoded in the
// authority information access extension.
type OCSPServer MultiString

// UnmarshalJSON implements the json.Unmarshaler interface in OCSPServer.
func (o *OCSPServer) UnmarshalJSON(data []byte) error {
	ms, err := unmarshalMultiString(data)
	if err != nil {
		return err
	}
	*o = ms
	return nil
}

// Set sets the list of OSCP servers to the given certificate.
func (o OCSPServer) Set(c *x509.Certificate) {
	c.OCSPServer = o
}

// IssuingCertificateURL contains the list of the issuing certificate url that
// will be encoded in the authority information access extension.
type IssuingCertificateURL MultiString

// UnmarshalJSON implements the json.Unmarshaler interface in IssuingCertificateURL.
func (u *IssuingCertificateURL) UnmarshalJSON(data []byte) error {
	ms, err := unmarshalMultiString(data)
	if err != nil {
		return err
	}
	*u = ms
	return nil
}

// Set sets the list of issuing certificate urls to the given certificate.
func (u IssuingCertificateURL) Set(c *x509.Certificate) {
	c.IssuingCertificateURL = u
}

// CRLDistributionPoints contains the list of CRL distribution points that will
// be encoded in the CRL distribution points extension.
type CRLDistributionPoints MultiString

// UnmarshalJSON implements the json.Unmarshaler interface in CRLDistributionPoints.
func (u *CRLDistributionPoints) UnmarshalJSON(data []byte) error {
	ms, err := unmarshalMultiString(data)
	if err != nil {
		return err
	}
	*u = ms
	return nil
}

// Set sets the CRL distribution points to the given certificate.
func (u CRLDistributionPoints) Set(c *x509.Certificate) {
	c.CRLDistributionPoints = u
}

// PolicyIdentifiers represents the list of OIDs to set in the certificate
// policies extension.
type PolicyIdentifiers MultiObjectIdentifier

// MarshalJSON implements the json.Marshaler interface in PolicyIdentifiers.
func (p PolicyIdentifiers) MarshalJSON() ([]byte, error) {
	return MultiObjectIdentifier(p).MarshalJSON()
}

// UnmarshalJSON implements the json.Unmarshaler interface in PolicyIdentifiers.
func (p *PolicyIdentifiers) UnmarshalJSON(data []byte) error {
	var v MultiObjectIdentifier
	if err := json.Unmarshal(data, &v); err != nil {
		return errors.Wrap(err, "error unmarshaling json")
	}
	*p = PolicyIdentifiers(v)
	return nil
}

// Sets sets the policy identifiers to the given certificate.
func (p PolicyIdentifiers) Set(c *x509.Certificate) {
	c.PolicyIdentifiers = p
}

// BasicConstraints represents the X509 basic constraints extension and defines
// if a certificate is a CA and then maximum depth of valid certification paths
// that include the certificate. A MaxPathLen of zero indicates that no non-
// self-issued intermediate CA certificates may follow in a valid certification
// path. To do not impose a limit the MaxPathLen should be set to -1.
type BasicConstraints struct {
	IsCA       bool `json:"isCA"`
	MaxPathLen int  `json:"maxPathLen"`
}

// Set sets the basic constraints to the given certificate.
func (b BasicConstraints) Set(c *x509.Certificate) {
	c.IsCA = b.IsCA
	if c.IsCA {
		c.BasicConstraintsValid = true
		switch {
		case b.MaxPathLen == 0:
			c.MaxPathLen = 0
			c.MaxPathLenZero = true
		case b.MaxPathLen < 0:
			c.MaxPathLen = -1
			c.MaxPathLenZero = false
		default:
			c.MaxPathLen = b.MaxPathLen
			c.MaxPathLenZero = false
		}
	} else {
		c.BasicConstraintsValid = false
		c.MaxPathLen = 0
		c.MaxPathLenZero = false
	}
}

// NameConstraints represents the X509 Name constraints extension and defines a
// names space within which all subject names in subsequent certificates in a
// certificate path must be located. The name constraints extension must be used
// only in a CA.
type NameConstraints struct {
	Critical                bool        `json:"critical"`
	PermittedDNSDomains     MultiString `json:"permittedDNSDomains"`
	ExcludedDNSDomains      MultiString `json:"excludedDNSDomains"`
	PermittedIPRanges       MultiIPNet  `json:"permittedIPRanges"`
	ExcludedIPRanges        MultiIPNet  `json:"excludedIPRanges"`
	PermittedEmailAddresses MultiString `json:"permittedEmailAddresses"`
	ExcludedEmailAddresses  MultiString `json:"excludedEmailAddresses"`
	PermittedURIDomains     MultiString `json:"permittedURIDomains"`
	ExcludedURIDomains      MultiString `json:"excludedURIDomains"`
}

// Sets sets the name constraints in the given certificate.
func (n NameConstraints) Set(c *x509.Certificate) {
	c.PermittedDNSDomainsCritical = n.Critical
	c.PermittedDNSDomains = n.PermittedDNSDomains
	c.ExcludedDNSDomains = n.ExcludedDNSDomains
	c.PermittedIPRanges = n.PermittedIPRanges
	c.ExcludedIPRanges = n.ExcludedIPRanges
	c.PermittedEmailAddresses = n.PermittedEmailAddresses
	c.ExcludedEmailAddresses = n.ExcludedEmailAddresses
	c.PermittedURIDomains = n.PermittedURIDomains
	c.ExcludedURIDomains = n.ExcludedURIDomains
}

// SerialNumber is the JSON representation of the X509 serial number.
type SerialNumber struct {
	*big.Int
}

// Set sets the serial number in the given certificate.
func (s SerialNumber) Set(c *x509.Certificate) {
	c.SerialNumber = s.Int
}

func (s *SerialNumber) MarshalJSON() ([]byte, error) {
	if s == nil || s.Int == nil {
		return []byte(`null`), nil
	}
	return s.Int.MarshalJSON()
}

// UnmarshalJSON implements the json.Unmarshal interface and unmarshals an
// integer or a string into a serial number. If a string is used, a prefix of
// “0b” or “0B” selects base 2, “0”, “0o” or “0O” selects base 8, and “0x” or
// “0X” selects base 16. Otherwise, the selected base is 10 and no prefix is
// accepted.
func (s *SerialNumber) UnmarshalJSON(data []byte) error {
	if sn, ok := maybeString(data); ok {
		// Using base 0 to accept prefixes 0b, 0o, 0x but defaults as base 10.
		b, ok := new(big.Int).SetString(sn, 0)
		if !ok {
			return errors.Errorf("error unmarshaling json: serialNumber %s is not valid", sn)
		}
		*s = SerialNumber{
			Int: b,
		}
		return nil
	}

	// Assume a number.
	var i int64
	if err := json.Unmarshal(data, &i); err != nil {
		return errors.Wrap(err, "error unmarshaling json")
	}
	*s = SerialNumber{
		Int: new(big.Int).SetInt64(i),
	}
	return nil
}
