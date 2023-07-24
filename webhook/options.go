package webhook

import (
	"crypto/x509"

	"go.step.sm/crypto/sshutil"
	"go.step.sm/crypto/x509util"
	"golang.org/x/crypto/ssh"
)

type RequestBodyOption func(*RequestBody) error

func NewRequestBody(options ...RequestBodyOption) (*RequestBody, error) {
	rb := &RequestBody{}

	for _, fn := range options {
		if err := fn(rb); err != nil {
			return nil, err
		}
	}

	return rb, nil
}

func WithX509CertificateRequest(cr *x509.CertificateRequest) RequestBodyOption {
	return func(rb *RequestBody) error {
		rb.X509CertificateRequest = &X509CertificateRequest{
			CertificateRequest: x509util.NewCertificateRequestFromX509(cr),
			PublicKeyAlgorithm: cr.PublicKeyAlgorithm.String(),
			Raw:                cr.Raw,
		}
		if cr.PublicKey != nil {
			key, err := x509.MarshalPKIXPublicKey(cr.PublicKey)
			if err != nil {
				return err
			}
			rb.X509CertificateRequest.PublicKey = key
		}

		return nil
	}
}

func WithX509Certificate(cert *x509util.Certificate, leaf *x509.Certificate) RequestBodyOption {
	return func(rb *RequestBody) error {
		rb.X509Certificate = &X509Certificate{
			Certificate:        cert,
			PublicKeyAlgorithm: leaf.PublicKeyAlgorithm.String(),
			NotBefore:          leaf.NotBefore,
			NotAfter:           leaf.NotAfter,
		}
		if leaf.PublicKey != nil {
			key, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
			if err != nil {
				return err
			}
			rb.X509Certificate.PublicKey = key
		}

		return nil
	}
}

func WithAttestationData(data *AttestationData) RequestBodyOption {
	return func(rb *RequestBody) error {
		rb.AttestationData = data
		return nil
	}
}

func WithAuthorizationPrincipal(p string) RequestBodyOption {
	return func(rb *RequestBody) error {
		rb.AuthorizationPrincipal = p
		return nil
	}
}

func WithSSHCertificateRequest(cr sshutil.CertificateRequest) RequestBodyOption {
	return func(rb *RequestBody) error {
		rb.SSHCertificateRequest = &SSHCertificateRequest{
			Type:       cr.Type,
			KeyID:      cr.KeyID,
			Principals: cr.Principals,
		}
		if cr.Key != nil {
			rb.SSHCertificateRequest.PublicKey = cr.Key.Marshal()
		}
		return nil
	}
}

func WithSSHCertificate(cert *sshutil.Certificate, certTpl *ssh.Certificate) RequestBodyOption {
	return func(rb *RequestBody) error {
		rb.SSHCertificate = &SSHCertificate{
			Certificate: cert,
			ValidBefore: certTpl.ValidBefore,
			ValidAfter:  certTpl.ValidAfter,
		}
		if certTpl.Key != nil {
			rb.SSHCertificate.PublicKey = certTpl.Key.Marshal()
		}
		return nil
	}
}

func WithX5CCertificate(leaf *x509.Certificate) RequestBodyOption {
	return func(rb *RequestBody) error {
		rb.X5CCertificate = &X5CCertificate{
			Raw:                leaf.Raw,
			PublicKeyAlgorithm: leaf.PublicKeyAlgorithm.String(),
			NotBefore:          leaf.NotBefore,
			NotAfter:           leaf.NotAfter,
		}
		if leaf.PublicKey != nil {
			key, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
			if err != nil {
				return err
			}
			rb.X5CCertificate.PublicKey = key
		}

		return nil
	}
}
