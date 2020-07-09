package x509util

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
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
	case "dns":
		c.DNSNames = append(c.DNSNames, s.Value)
	case "email":
		c.EmailAddresses = append(c.EmailAddresses, s.Value)
	case "ip":
		// The validation of the IP would happen in the unmarshaling, but just
		// to be sure we are only adding valid IPs.
		if ip := net.ParseIP(s.Value); ip != nil {
			c.IPAddresses = append(c.IPAddresses, ip)
		}
	case "uri":
		if u, err := url.Parse(s.Value); err != nil {
			c.URIs = append(c.URIs, u)
		}
	case "auto", "":
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

// Set sets the list of OSCP servers to the given certificate.
func (o OCSPServer) Set(c *x509.Certificate) {
	c.OCSPServer = o
}

// IssuingCertificateURL contains the list of the issuing certificate url that
// will be encoded in the authority information access extension.
type IssuingCertificateURL MultiString

// Set sets the list of issuing certificate urls to the given certificate.
func (u IssuingCertificateURL) Set(c *x509.Certificate) {
	c.IssuingCertificateURL = u
}

// CRLDistributionPoints contains the list of CRL distribution points that will
// be encoded in the CRL distribution points extension.
type CRLDistributionPoints MultiString

// Set sets the CRL distribution points to the given certificate.
func (u CRLDistributionPoints) Set(c *x509.Certificate) {
	c.CRLDistributionPoints = u
}

// PolicyIdentifiers represents the list of OIDs to set in the certificate
// policies extension.
type PolicyIdentifiers MultiObjectIdentifier

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
			c.MaxPathLen = b.MaxPathLen
			c.MaxPathLenZero = true
		case b.MaxPathLen < 0:
			c.MaxPathLen = -1
		default:
			c.MaxPathLen = b.MaxPathLen
		}
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
