package apiv1

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/pkg/errors"
)

var (
	oidStepRoot                 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64}
	oidStepCertificateAuthority = append(asn1.ObjectIdentifier(nil), append(oidStepRoot, 2)...)
)

// CertificateAuthorityExtension type is used to encode the certificate
// authority extension.
type CertificateAuthorityExtension struct {
	Type          string
	CertificateID string   `asn1:"optional,omitempty"`
	KeyValuePairs []string `asn1:"optional,omitempty"`
}

// CreateCertificateAuthorityExtension returns a X.509 extension that shows the
// CAS type, id and a list of optional key value pairs.
func CreateCertificateAuthorityExtension(typ Type, certificateID string, keyValuePairs ...string) (pkix.Extension, error) {
	b, err := asn1.Marshal(CertificateAuthorityExtension{
		Type:          typ.String(),
		CertificateID: certificateID,
		KeyValuePairs: keyValuePairs,
	})
	if err != nil {
		return pkix.Extension{}, errors.Wrapf(err, "error marshaling certificate id extension")
	}
	return pkix.Extension{
		Id:       oidStepCertificateAuthority,
		Critical: false,
		Value:    b,
	}, nil
}

// FindCertificateAuthorityExtension returns the certificate authority extension
// from a signed certificate.
func FindCertificateAuthorityExtension(cert *x509.Certificate) (pkix.Extension, bool) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidStepCertificateAuthority) {
			return ext, true
		}
	}
	return pkix.Extension{}, false
}

// RemoveCertificateAuthorityExtension removes the certificate authority
// extension from a certificate template.
func RemoveCertificateAuthorityExtension(cert *x509.Certificate) {
	for i, ext := range cert.ExtraExtensions {
		if ext.Id.Equal(oidStepCertificateAuthority) {
			cert.ExtraExtensions = append(cert.ExtraExtensions[:i], cert.ExtraExtensions[i+1:]...)
			return
		}
	}
}
