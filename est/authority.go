package est

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"

	"github.com/smallstep/pkcs7"

	"go.step.sm/crypto/x509util"

	"github.com/smallstep/certificates/authority/provisioner"
)

// Authority handles EST interactions.
type Authority struct {
	signAuth      SignAuthority
	roots         []*x509.Certificate
	intermediates []*x509.Certificate
}

type authorityKey struct{}

// NewContext adds the given authority to the context.
func NewContext(ctx context.Context, a *Authority) context.Context {
	return context.WithValue(ctx, authorityKey{}, a)
}

// FromContext returns the current authority from the given context.
func FromContext(ctx context.Context) (a *Authority, ok bool) {
	a, ok = ctx.Value(authorityKey{}).(*Authority)
	return
}

// MustFromContext returns the current authority from the given context. It will
// panic if the authority is not in the context.
func MustFromContext(ctx context.Context) *Authority {
	var (
		a  *Authority
		ok bool
	)
	if a, ok = FromContext(ctx); !ok {
		panic("est authority is not in the context")
	}
	return a
}

// SignAuthority is the interface for a signing authority.
type SignAuthority interface {
	SignWithContext(ctx context.Context, cr *x509.CertificateRequest, opts provisioner.SignOptions, signOpts ...provisioner.SignOption) ([]*x509.Certificate, error)
	LoadProvisionerByName(string) (provisioner.Interface, error)
}

// New returns a new Authority that implements the EST interface.
func New(signAuth SignAuthority, opts Options) (*Authority, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}

	return &Authority{
		signAuth:      signAuth,
		roots:         opts.Roots,
		intermediates: opts.Intermediates,
	}, nil
}

// LoadProvisionerByName calls out to the SignAuthority interface to load a
// provisioner by name.
func (a *Authority) LoadProvisionerByName(name string) (provisioner.Interface, error) {
	return a.signAuth.LoadProvisionerByName(name)
}

// GetCACertificates returns the certificate chain for the CA.
func (a *Authority) GetCACertificates(ctx context.Context) (certs []*x509.Certificate, err error) {
	certs = append(a.intermediates, a.roots...)

	return certs, nil
}

// SignCSR signs the CSR using the provisioner and returns the issued chain.
func (a *Authority) SignCSR(ctx context.Context, csr *x509.CertificateRequest, signCSROpts ...provisioner.SignCSROption) (*x509.Certificate, error) {
	// TODO: intermediate storage of the request? In EST it's possible to request a csr/certificate
	// to be signed, which can be performed asynchronously / out-of-band. In that case a client can
	// poll for the status. It seems to be similar as what can happen in ACME and SCEP, so might want to model
	// the implementation after the one in the ACME authority. Requires storage, etc.
	// ref: https://datatracker.ietf.org/doc/html/rfc7030#section-4.2.3
	p := provisionerFromContext(ctx)

	// Template data
	sans := []string{}
	sans = append(sans, csr.DNSNames...)
	sans = append(sans, csr.EmailAddresses...)
	for _, v := range csr.IPAddresses {
		sans = append(sans, v.String())
	}
	for _, v := range csr.URIs {
		sans = append(sans, v.String())
	}
	if len(sans) == 0 {
		sans = append(sans, csr.Subject.CommonName)
	}
	data := x509util.CreateTemplateData(csr.Subject.CommonName, sans)
	data.SetCertificateRequest(csr)
	data.SetSubject(x509util.Subject{
		Country:            csr.Subject.Country,
		Organization:       csr.Subject.Organization,
		OrganizationalUnit: csr.Subject.OrganizationalUnit,
		Locality:           csr.Subject.Locality,
		Province:           csr.Subject.Province,
		StreetAddress:      csr.Subject.StreetAddress,
		PostalCode:         csr.Subject.PostalCode,
		SerialNumber:       csr.Subject.SerialNumber,
		CommonName:         csr.Subject.CommonName,
	})

	for _, o := range signCSROpts {
		if m, ok := o.(provisioner.TemplateDataModifier); ok {
			m.Modify(data)
		}
	}

	ctx = provisioner.NewContextWithMethod(ctx, provisioner.SignMethod)
	signOps, err := p.AuthorizeSign(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("error retrieving authorization options from EST provisioner: %w", err)
	}
	for _, signOp := range signOps {
		if wc, ok := signOp.(*provisioner.WebhookController); ok {
			wc.TemplateData = data
		}
	}

	opts := provisioner.SignOptions{}
	templateOptions, err := provisioner.TemplateOptions(p.GetOptions(), data)
	if err != nil {
		return nil, fmt.Errorf("error creating template options from EST provisioner: %w", err)
	}
	signOps = append(signOps, templateOptions)

	certChain, err := a.signAuth.SignWithContext(ctx, csr, opts, signOps...)
	if err != nil {
		return nil, fmt.Errorf("error generating certificate: %w", err)
	}

	// return leaf certificate (only): https://datatracker.ietf.org/doc/html/rfc7030#section-4.2.3
	return certChain[0], nil
}

// BuildResponse returns a certs-only PKCS7 SignedData for the given certs.
func (a *Authority) BuildResponse(ctx context.Context, certs []*x509.Certificate) ([]byte, error) {
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates to encode")
	}
	// Build degenerate PKCS7: SignedData with no encapsulated content or signer infos.
	var buf bytes.Buffer
	for _, cert := range certs {
		buf.Write(cert.Raw)
	}
	degenerate, err := pkcs7.DegenerateCertificate(buf.Bytes())
	if err != nil {
		return nil, err
	}
	return degenerate, nil
}
