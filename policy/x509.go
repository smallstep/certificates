package policy

import (
	"crypto/x509"
	"net"
)

type X509NamePolicyEngine interface {
	AreCertificateNamesAllowed(cert *x509.Certificate) (bool, error)
	AreCSRNamesAllowed(csr *x509.CertificateRequest) (bool, error)
	AreSANsAllowed(sans []string) (bool, error)
	IsDNSAllowed(dns string) (bool, error)
	IsIPAllowed(ip net.IP) (bool, error)
}
