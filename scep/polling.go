package scep

import (
	"crypto/x509"

	"github.com/pkg/errors"
)

// CertificateIsSigned looks if the certificate matching the csr is signed, and returns a bool if it's been signed or not.
func (a *Authority) CertificateIsSigned(csr *x509.CertificateRequest) (bool, error) {
	_, err := a.db.GetCertificateByCSR(csr)
	if err != nil {
		return false, errors.Errorf("Error finding certificate in database")
	}
	// If there's no errors, then it exists and is signed.
	return true, nil
}

// CertificateRequestInDB looks for the CSR matching the transaction ID, and returns a bool if it exists or not.
func (a *Authority) CertificateRequestInDB(transactionID string) (bool, error) {
	csr, err := a.db.GetCSR(transactionID)
	if err != nil {
		return false, nil
	}
	if csr == nil {
		return false, nil
	}
	return true, nil
}

// StoreCertificateRequest stores the incoming certificate signing request.
func (a *Authority) StoreCertificateRequest(transactionID string, csr *x509.CertificateRequest) error {
	err := a.db.StoreCSR(transactionID, csr)
	if err != nil {
		return err
	}
	return nil
}

// GetCertificateRequest fetches and returns the CSR matching the transaction ID.
func (a *Authority) GetCertificateRequest(transactionID string) (*x509.CertificateRequest, error) {
	csr, err := a.db.GetCSR(transactionID)
	if err != nil {
		return nil, errors.Errorf("Error finding serial number in database")
	}
	return csr, nil
}

// IsEnabled returns a bool if SCEP polling is enabled or not.
func (a *Authority) IsEnabled() bool {
	return a.polling
}
