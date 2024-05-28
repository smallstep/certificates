package authority

import (
	"crypto/x509"

	"github.com/smallstep/certificates/errs"
)

// Root returns the certificate corresponding to the given SHA sum argument.
func (a *Authority) Root(sum string) (*x509.Certificate, error) {
	val, ok := a.certificates.Load(sum)
	if !ok {
		return nil, errs.NotFound("certificate with fingerprint %s was not found", sum)
	}

	crt, ok := val.(*x509.Certificate)
	if !ok {
		return nil, errs.InternalServer("stored value is not a *x509.Certificate")
	}
	return crt, nil
}

// GetRootCertificate returns the server root certificate.
func (a *Authority) GetRootCertificate() *x509.Certificate {
	return a.rootX509Certs[0]
}

// GetRootCertificates returns the server root certificates.
//
// In the Authority interface we also have a similar method, GetRoots, at the
// moment the functionality of these two methods are almost identical, but this
// method is intended to be used internally by CA HTTP server to load the roots
// that will be set in the tls.Config while GetRoots will be used by the
// Authority interface and might have extra checks in the future.
func (a *Authority) GetRootCertificates() []*x509.Certificate {
	return a.rootX509Certs
}

// GetRoots returns all the root certificates for this CA.
// This method implements the Authority interface.
func (a *Authority) GetRoots() ([]*x509.Certificate, error) {
	return a.rootX509Certs, nil
}

// GetFederation returns all the root certificates in the federation.
// This method implements the Authority interface.
func (a *Authority) GetFederation() (federation []*x509.Certificate, err error) {
	a.certificates.Range(func(_, v interface{}) bool {
		crt, ok := v.(*x509.Certificate)
		if !ok {
			federation = nil
			err = errs.InternalServer("stored value is not a *x509.Certificate")
			return false
		}
		federation = append(federation, crt)
		return true
	})
	return
}

// GetIntermediateCertificate return the intermediate certificate that issues
// the leaf certificates in the CA.
//
// This method can return nil if the CA is configured with a Certificate
// Authority Service (CAS) that does not implement the
// CertificateAuthorityGetter interface.
func (a *Authority) GetIntermediateCertificate() *x509.Certificate {
	if len(a.intermediateX509Certs) > 0 {
		return a.intermediateX509Certs[0]
	}
	return nil
}

// GetIntermediateCertificates returns a list of all intermediate certificates
// configured. The first certificate in the list will be the issuer certificate.
//
// This method can return an empty list or nil if the CA is configured with a
// Certificate Authority Service (CAS) that does not implement the
// CertificateAuthorityGetter interface.
func (a *Authority) GetIntermediateCertificates() []*x509.Certificate {
	return a.intermediateX509Certs
}
