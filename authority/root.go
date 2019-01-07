package authority

import (
	"crypto/x509"
	"net/http"

	"github.com/pkg/errors"
)

// Root returns the certificate corresponding to the given SHA sum argument.
func (a *Authority) Root(sum string) (*x509.Certificate, error) {
	val, ok := a.certificates.Load(sum)
	if !ok {
		return nil, &apiError{errors.Errorf("certificate with fingerprint %s was not found", sum),
			http.StatusNotFound, context{}}
	}

	crt, ok := val.(*x509.Certificate)
	if !ok {
		return nil, &apiError{errors.Errorf("stored value is not a *x509.Certificate"),
			http.StatusInternalServerError, context{}}
	}
	return crt, nil
}

// GetRootCertificate returns the server root certificate.
func (a *Authority) GetRootCertificate() *x509.Certificate {
	return a.rootX509Certs[0]
}

// GetRootCertificates returns the server root certificates.
func (a *Authority) GetRootCertificates() []*x509.Certificate {
	return a.rootX509Certs
}

// GetFederation returns all the root certificates in the federation.
func (a *Authority) GetFederation(peer *x509.Certificate) (federation []*x509.Certificate, err error) {
	// Check step provisioner extensions
	if err := a.authorizeRenewal(peer); err != nil {
		return nil, err
	}

	a.certificates.Range(func(k, v interface{}) bool {
		crt, ok := v.(*x509.Certificate)
		if !ok {
			federation = nil
			err = &apiError{errors.Errorf("stored value is not a *x509.Certificate"),
				http.StatusInternalServerError, context{}}
			return false
		}
		federation = append(federation, crt)
		return true
	})
	return
}
