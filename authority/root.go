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
		return nil, &apiError{errors.Errorf("stored value is not a *cryto/x509.Certificate"),
			http.StatusInternalServerError, context{}}
	}
	return crt, nil
}

// GetRootCertificate returns the server root certificate.
func (a *Authority) GetRootCertificate() *x509.Certificate {
	return a.rootX509Crt
}
