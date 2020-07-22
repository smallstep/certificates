package x509util

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"

	"github.com/pkg/errors"
)

// Name is the JSON representation of X.501 type Name, used in the X.509 subject
// and issuer fields.
type Name struct {
	Country            MultiString `json:"country,omitempty"`
	Organization       MultiString `json:"organization,omitempty"`
	OrganizationalUnit MultiString `json:"organizationalUnit,omitempty"`
	Locality           MultiString `json:"locality,omitempty"`
	Province           MultiString `json:"province,omitempty"`
	StreetAddress      MultiString `json:"streetAddress,omitempty"`
	PostalCode         MultiString `json:"postalCode,omitempty"`
	SerialNumber       string      `json:"serialNumber,omitempty"`
	CommonName         string      `json:"commonName,omitempty"`
}

// UnmarshalJSON implements the json.Unmarshal interface and unmarshals a JSON
// object in the Name struct or a string as just the subject common name.
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

// UnmarshalJSON implements the json.Unmarshal interface and unmarshals a JSON
// object in the Subject struct or a string as just the subject common name.
func (s *Subject) UnmarshalJSON(data []byte) error {
	var name Name
	if err := name.UnmarshalJSON(data); err != nil {
		return err
	}
	*s = Subject(name)
	return nil
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

// nolint:unused
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

// UnmarshalJSON implements the json.Unmarshal interface and unmarshals a JSON
// object in the Issuer struct or a string as just the subject common name.
func (i *Issuer) UnmarshalJSON(data []byte) error {
	var name Name
	if err := name.UnmarshalJSON(data); err != nil {
		return err
	}
	*i = Issuer(name)
	return nil
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
