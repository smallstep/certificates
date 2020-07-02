package x509util

import "crypto/x509"

type CertificateRequest struct {
	Version            int                     `json:"version"`
	Subject            Subject                 `json:"subject"`
	DNSNames           MultiString             `json:"dnsNames"`
	EmailAddresses     MultiString             `json:"emailAddresses"`
	IPAddresses        MultiIP                 `json:"ipAddresses"`
	URIs               MultiURL                `json:"uris"`
	Extensions         []Extension             `json:"extensions"`
	PublicKey          interface{}             `json:"-"`
	PublicKeyAlgorithm x509.PublicKeyAlgorithm `json:"-"`
	Signature          []byte                  `json:"-"`
	SignatureAlgorithm x509.SignatureAlgorithm `json:"-"`
}

func newCertificateRequest(cr *x509.CertificateRequest) *CertificateRequest {
	return &CertificateRequest{
		Version:            cr.Version,
		Subject:            newSubject(cr.Subject),
		DNSNames:           cr.DNSNames,
		EmailAddresses:     cr.EmailAddresses,
		IPAddresses:        cr.IPAddresses,
		URIs:               cr.URIs,
		Extensions:         nil,
		PublicKey:          cr.PublicKey,
		PublicKeyAlgorithm: cr.PublicKeyAlgorithm,
		Signature:          cr.Signature,
		SignatureAlgorithm: cr.SignatureAlgorithm,
	}
}

func (c *CertificateRequest) GetCertificate() *Certificate {
	return &Certificate{
		Subject:            c.Subject,
		DNSNames:           c.DNSNames,
		EmailAddresses:     c.EmailAddresses,
		IPAddresses:        c.IPAddresses,
		URIs:               c.URIs,
		Extensions:         c.Extensions,
		PublicKey:          c.PublicKey,
		PublicKeyAlgorithm: c.PublicKeyAlgorithm,
	}
}
