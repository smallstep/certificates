package x509util

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"

	"github.com/pkg/errors"
)

type Certificate struct {
	Version               int                      `json:"version"`
	Subject               Subject                  `json:"subject"`
	Issuer                Issuer                   `json:"issuer"`
	SerialNumber          SerialNumber             `json:"serialNumber"`
	DNSNames              MultiString              `json:"dnsNames"`
	EmailAddresses        MultiString              `json:"emailAddresses"`
	IPAddresses           MultiIP                  `json:"ipAddresses"`
	URIs                  MultiURL                 `json:"uris"`
	SANs                  []SubjectAlternativeName `json:"sans"`
	Extensions            []Extension              `json:"extensions"`
	KeyUsage              KeyUsage                 `json:"keyUsage"`
	ExtKeyUsage           ExtKeyUsage              `json:"extKeyUsage"`
	SubjectKeyID          SubjectKeyID             `json:"subjectKeyId"`
	AuthorityKeyID        AuthorityKeyID           `json:"authorityKeyId"`
	OCSPServer            OCSPServer               `json:"ocspServer"`
	IssuingCertificateURL IssuingCertificateURL    `json:"issuingCertificateURL"`
	CRLDistributionPoints CRLDistributionPoints    `json:"crlDistributionPoints"`
	PolicyIdentifiers     PolicyIdentifiers        `json:"policyIdentifiers"`
	BasicConstraints      *BasicConstraints        `json:"basicConstraints"`
	NameConstaints        *NameConstraints         `json:"nameConstraints"`
	SignatureAlgorithm    SignatureAlgorithm       `json:"signatureAlgorithm"`
	PublicKeyAlgorithm    x509.PublicKeyAlgorithm  `json:"-"`
	PublicKey             interface{}              `json:"-"`
}

func NewCertificate(cr *x509.CertificateRequest, opts ...Option) (*Certificate, error) {
	if err := cr.CheckSignature(); err != nil {
		return nil, errors.Wrap(err, "error validating certificate request")
	}

	o, err := new(Options).apply(cr, opts)
	if err != nil {
		return nil, err
	}

	// If no template use only the certificate request with the default leaf key
	// usages.
	if o.CertBuffer == nil {
		return newCertificateRequest(cr).GetLeafCertificate(), nil
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

	// SANs slice.
	for _, san := range c.SANs {
		san.Set(cert)
	}

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

func CreateCertificate(template, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) (*x509.Certificate, error) {
	var err error
	// Complete certificate.
	if template.SerialNumber == nil {
		if template.SerialNumber, err = generateSerialNumber(); err != nil {
			return nil, err
		}
	}
	if template.SubjectKeyId == nil {
		if template.SubjectKeyId, err = generateSubjectKeyID(pub); err != nil {
			return nil, err
		}
	}

	// Sign certificate
	asn1Data, err := x509.CreateCertificate(rand.Reader, template, parent, pub, signer)
	if err != nil {
		return nil, errors.Wrap(err, "error creating certificate")
	}
	cert, err := x509.ParseCertificate(asn1Data)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing certificate")
	}
	return cert, nil
}

// Name is the JSON representation of X.501 type Name, used in the X.509 subject
// and issuer fields.
type Name struct {
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

// UnmarshalJSON implements the json.Unmarshal interface and unmarshals a JSON
// object in the Subject struct or a string as just the subject common name.
func (n *Name) UnmarshalJSON(data []byte) error {
	if cn, ok := maybeString(data); ok {
		n.CommonName = cn
		return nil
	}

	type nameAlias Name
	var nn nameAlias
	if err := json.Unmarshal(data, &nn); err != nil {
		return errors.Wrap(err, "error unmarshaling json")
	}
	*n = Name(nn)
	return nil
}

// Subject is the JSON representation of the X.509 subject field.
type Subject Name

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

// Issuer is the JSON representation of the X.509 issuer field.
type Issuer Name

func newIssuer(n pkix.Name) Issuer {
	return Issuer{
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

// Set sets the issuer in the given certificate.
func (i Issuer) Set(c *x509.Certificate) {
	c.Issuer = pkix.Name{
		Country:            i.Country,
		Organization:       i.Organization,
		OrganizationalUnit: i.OrganizationalUnit,
		Locality:           i.Locality,
		Province:           i.Province,
		StreetAddress:      i.StreetAddress,
		PostalCode:         i.PostalCode,
		SerialNumber:       i.SerialNumber,
		CommonName:         i.CommonName,
	}
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
