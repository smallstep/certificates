package x509util

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"strings"

	"github.com/pkg/errors"
)

type Certificate struct {
	Version               int                     `json:"version"`
	Subject               Subject                 `json:"subject"`
	SerialNumber          SerialNumber            `json:"serialNumber"`
	DNSNames              MultiString             `json:"dnsNames"`
	EmailAddresses        MultiString             `json:"emailAddresses"`
	IPAddresses           MultiIP                 `json:"ipAddresses"`
	URIs                  MultiURL                `json:"uris"`
	Extensions            []Extension             `json:"extensions"`
	KeyUsage              KeyUsage                `json:"keyUsage"`
	ExtKeyUsage           ExtKeyUsage             `json:"extKeyUsage"`
	SubjectKeyID          SubjectKeyID            `json:"subjectKeyId"`
	AuthorityKeyID        AuthorityKeyID          `json:"authorityKeyId"`
	OCSPServer            OCSPServer              `json:"ocspServer"`
	IssuingCertificateURL IssuingCertificateURL   `json:"issuingCertificateURL"`
	CRLDistributionPoints CRLDistributionPoints   `json:"crlDistributionPoints"`
	PolicyIdentifiers     PolicyIdentifiers       `json:"policyIdentifiers"`
	BasicConstraints      *BasicConstraints       `json:"basicConstraints"`
	NameConstaints        *NameConstraints        `json:"nameConstraints"`
	SignatureAlgorithm    SignatureAlgorithm      `json:"signatureAlgorithm"`
	PublicKeyAlgorithm    x509.PublicKeyAlgorithm `json:"-"`
	PublicKey             interface{}             `json:"-"`
}

func NewCertificate(cr *x509.CertificateRequest, opts ...Option) (*Certificate, error) {
	if err := cr.CheckSignature(); err != nil {
		return nil, errors.Wrap(err, "error validating certificate request")
	}

	o, err := new(Options).apply(opts)
	if err != nil {
		return nil, err
	}

	// If no template use only the certificate request.
	if o.CertBuffer == nil {
		return newCertificateRequest(cr).GetCertificate(), nil
	}

	// With templates
	var cert Certificate
	if err := json.NewDecoder(o.CertBuffer).Decode(&cert); err != nil {
		return nil, errors.Wrap(err, "error unmarshaling certificate")
	}

	// Complete with certificate request
	cert.PublicKey = cr.PublicKey
	cert.PublicKeyAlgorithm = cr.PublicKeyAlgorithm

	return &cert, nil
}

func (c *Certificate) GetCertificate() *x509.Certificate {
	cert := new(x509.Certificate)
	// Unparsed data
	cert.PublicKey = c.PublicKey
	cert.PublicKeyAlgorithm = c.PublicKeyAlgorithm

	// SANs are directly converted.
	cert.DNSNames = c.DNSNames
	cert.EmailAddresses = c.EmailAddresses
	cert.IPAddresses = c.IPAddresses
	cert.URIs = c.URIs

	// Subject.
	c.Subject.Set(cert)

	// Defined extensions.
	c.KeyUsage.Set(cert)
	c.ExtKeyUsage.Set(cert)
	c.SubjectKeyID.Set(cert)
	c.AuthorityKeyID.Set(cert)
	c.OCSPServer.Set(cert)
	c.IssuingCertificateURL.Set(cert)
	c.PolicyIdentifiers.Set(cert)
	if c.BasicConstraints != nil {
		c.BasicConstraints.Set(cert)
	}
	if c.NameConstaints != nil {
		c.NameConstaints.Set(cert)
	}

	// Custom Extensions.
	for _, e := range c.Extensions {
		e.Set(cert)
	}

	// Others.
	c.SerialNumber.Set(cert)
	c.SignatureAlgorithm.Set(cert)

	return cert
}

// Subject is the JSON representation of the X509 subject field.
type Subject struct {
	Country            MultiString `json:"country"`
	Organization       MultiString `json:"organization"`
	OrganizationalUnit MultiString `json:"organizationUnit"`
	Locality           MultiString `json:"locality"`
	Province           MultiString `json:"province"`
	StreetAddress      MultiString `json:"streetAddress"`
	PostalCode         MultiString `json:"postalCode"`
	SerialNumber       string      `json:"serialNumber"`
	CommonName         string      `json:"commonName"`
}

func newSubject(n pkix.Name) Subject {
	return Subject{
		Country:            n.Country,
		Organization:       n.Organization,
		OrganizationalUnit: n.OrganizationalUnit,
		Locality:           n.Locality,
		Province:           n.Province,
		StreetAddress:      n.StreetAddress,
		PostalCode:         n.PostalCode,
		SerialNumber:       n.SerialNumber,
		CommonName:         n.CommonName,
	}
}

// Set sets the subject in the given certificate.
func (s Subject) Set(c *x509.Certificate) {
	c.Subject = pkix.Name{
		Country:            s.Country,
		Organization:       s.Organization,
		OrganizationalUnit: s.OrganizationalUnit,
		Locality:           s.Locality,
		Province:           s.Province,
		StreetAddress:      s.StreetAddress,
		PostalCode:         s.PostalCode,
		SerialNumber:       s.SerialNumber,
		CommonName:         s.CommonName,
	}
}

// UnmarshalJSON implements the json.Unmarshal interface and unmarshals a JSON
// object in the Subject struct or a string as just the subject common name.
func (s *Subject) UnmarshalJSON(data []byte) error {
	if cn, ok := maybeString(data); ok {
		s.CommonName = cn
		return nil
	}

	type subjectAlias Subject
	var ss subjectAlias
	if err := json.Unmarshal(data, &ss); err != nil {
		return errors.Wrap(err, "error unmarshaling json")
	}
	*s = Subject(ss)
	return nil
}

// SerialNumber is the JSON representation of the X509 serial number.
type SerialNumber struct {
	*big.Int
}

// Set sets the serial number in the given certificate.
func (s SerialNumber) Set(c *x509.Certificate) {
	c.SerialNumber = s.Int
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

// SignatureAlgorithm is the JSON representation of the X509 signature algorithms
type SignatureAlgorithm x509.SignatureAlgorithm

// Set sets the signature algorithm in the given certificate.
func (s SignatureAlgorithm) Set(c *x509.Certificate) {
	c.SignatureAlgorithm = s
}

// UnmarshalJSON implements the json.Unmarshal interface and unmarshals a JSON
// object in the Subject struct or a string as just the subject common name.
func (s *SignatureAlgorithm) UnmarshalJSON(data []byte) error {
	s, err := unmarshalString(data)
	if err != nil {
		return err
	}

	var sa x509.SignatureAlgorithm
	switch strings.ToUpper(s) {
	case "MD2-RSA":
		sa = x509.MD2WithRSA
	case "MD5-RSA":
		sa = x509.MD5WithRSA
	case "SHA1-RSA":
		sa = x509.SHA1WithRSA
	case "SHA1-RSA":
		sa = x509.SHA1WithRSA
	case "SHA256-RSA":
		sa = x509.SHA256WithRSA
	case "SHA384-RSA":
		sa = x509.SHA384WithRSA
	case "SHA512-RSA":
		sa = x509.SHA512WithRSA
	case "SHA256-RSAPSS":
		sa = x509.SHA256WithRSAPSS
	case "SHA384-RSAPSS":
		sa = x509.SHA384WithRSAPSS
	case "SHA512-RSAPSS":
		sa = x509.SHA512WithRSAPSS
	case "DSA-SHA1":
		sa = x509.DSAWithSHA1
	case "DSA-SHA256":
		sa = x509.DSAWithSHA256
	case "ECDSA-SHA1":
		sa = x509.ECDSAWithSHA1
	case "ECDSA-SHA256":
		sa = x509.ECDSAWithSHA256
	case "ECDSA-SHA384":
		sa = x509.ECDSAWithSHA384
	case "ECDSA-SHA512":
		sa = x509.ECDSAWithSHA512
	case "ED25519":
		sa = x509.PureEd25519
	default:
		return errors.Errorf("unsupported signatureAlgorithm %s", s)
	}

	*s = SignatureAlgorithm(sa)
	return nil
}
