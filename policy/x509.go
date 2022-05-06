package policy

import (
	"crypto/x509"
	"net"
)

type X509NamePolicyEngine interface {
	IsX509CertificateAllowed(cert *x509.Certificate) error
	IsX509CertificateRequestAllowed(csr *x509.CertificateRequest) error
	AreSANsAllowed(sans []string) error
	IsDNSAllowed(dns string) error
	IsIPAllowed(ip net.IP) error
}
