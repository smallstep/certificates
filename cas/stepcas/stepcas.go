package stepcas

import (
	"context"
	"crypto/x509"
	"net/url"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/cas/apiv1"
)

func init() {
	apiv1.Register(apiv1.StepCAS, func(ctx context.Context, opts apiv1.Options) (apiv1.CertificateAuthorityService, error) {
		return New(ctx, opts)
	})
}

// StepCAS implements the cas.CertificateAuthorityService interface using
// another step-ca instance.
type StepCAS struct {
	x5c         *x5cIssuer
	client      *ca.Client
	fingerprint string
}

// New creates a new CertificateAuthorityService implementation using another
// step-ca instance.
func New(ctx context.Context, opts apiv1.Options) (*StepCAS, error) {
	switch {
	case opts.CertificateAuthority == "":
		return nil, errors.New("stepCAS 'certificateAuthority' cannot be empty")
	case opts.CertificateAuthorityFingerprint == "":
		return nil, errors.New("stepCAS 'certificateAuthorityFingerprint' cannot be empty")
	}

	caURL, err := url.Parse(opts.CertificateAuthority)
	if err != nil {
		return nil, errors.Wrap(err, "stepCAS `certificateAuthority` is not valid")
	}
	if err := validateCertificateIssuer(opts.CertificateIssuer); err != nil {
		return nil, err
	}

	// Create client.
	client, err := ca.NewClient(opts.CertificateAuthority, ca.WithRootSHA256(opts.CertificateAuthorityFingerprint))
	if err != nil {
		return nil, err
	}

	// X5C is the only one supported at the moment.
	x5c, err := newX5CIssuer(caURL, opts.CertificateIssuer)
	if err != nil {
		return nil, err
	}

	return &StepCAS{
		x5c:         x5c,
		client:      client,
		fingerprint: opts.CertificateAuthorityFingerprint,
	}, nil
}

func (s *StepCAS) CreateCertificate(req *apiv1.CreateCertificateRequest) (*apiv1.CreateCertificateResponse, error) {
	switch {
	case req.CSR == nil:
		return nil, errors.New("createCertificateRequest `template` cannot be nil")
	case req.Lifetime == 0:
		return nil, errors.New("createCertificateRequest `lifetime` cannot be 0")
	}

	cert, chain, err := s.createCertificate(req.CSR, req.Lifetime)
	if err != nil {
		return nil, err
	}

	return &apiv1.CreateCertificateResponse{
		Certificate:      cert,
		CertificateChain: chain,
	}, nil
}

func (s *StepCAS) RenewCertificate(req *apiv1.RenewCertificateRequest) (*apiv1.RenewCertificateResponse, error) {
	switch {
	case req.CSR == nil:
		return nil, errors.New("renewCertificateRequest `template` cannot be nil")
	case req.Lifetime == 0:
		return nil, errors.New("renewCertificateRequest `lifetime` cannot be 0")
	}

	cert, chain, err := s.createCertificate(req.CSR, req.Lifetime)
	if err != nil {
		return nil, err
	}

	return &apiv1.RenewCertificateResponse{
		Certificate:      cert,
		CertificateChain: chain,
	}, nil
}

func (s *StepCAS) RevokeCertificate(req *apiv1.RevokeCertificateRequest) (*apiv1.RevokeCertificateResponse, error) {
	switch {
	case req.SerialNumber == "" && req.Certificate == nil:
		return nil, errors.New("revokeCertificateRequest `serialNumber` or `certificate` are required")
	}

	serialNumber := req.SerialNumber
	if req.Certificate != nil {
		serialNumber = req.Certificate.SerialNumber.String()
	}

	token, err := s.revokeToken(serialNumber)
	if err != nil {
		return nil, err
	}

	_, err = s.client.Revoke(&api.RevokeRequest{
		Serial:     serialNumber,
		ReasonCode: req.ReasonCode,
		Reason:     req.Reason,
		OTT:        token,
		Passive:    req.PassiveOnly,
	}, nil)
	if err != nil {
		return nil, err
	}

	return &apiv1.RevokeCertificateResponse{
		Certificate:      req.Certificate,
		CertificateChain: nil,
	}, nil
}

// GetCertificateAuthority returns the root certificate of the certificate
// authority using the configured fingerprint.
func (s *StepCAS) GetCertificateAuthority(req *apiv1.GetCertificateAuthorityRequest) (*apiv1.GetCertificateAuthorityResponse, error) {
	resp, err := s.client.Root(s.fingerprint)
	if err != nil {
		return nil, err
	}
	return &apiv1.GetCertificateAuthorityResponse{
		RootCertificate: resp.RootPEM.Certificate,
	}, nil
}

func (s *StepCAS) createCertificate(cr *x509.CertificateRequest, lifetime time.Duration) (*x509.Certificate, []*x509.Certificate, error) {
	sans := make([]string, 0, len(cr.DNSNames)+len(cr.EmailAddresses)+len(cr.IPAddresses)+len(cr.URIs))
	for _, s := range cr.DNSNames {
		sans = append(sans, s)
	}
	for _, s := range cr.EmailAddresses {
		sans = append(sans, s)
	}
	for _, ip := range cr.IPAddresses {
		sans = append(sans, ip.String())
	}
	for _, u := range cr.URIs {
		sans = append(sans, u.String())
	}

	commonName := cr.Subject.CommonName
	if commonName == "" && len(sans) > 0 {
		commonName = sans[0]
	}

	token, err := s.signToken(commonName, sans)
	if err != nil {
		return nil, nil, err
	}

	resp, err := s.client.Sign(&api.SignRequest{
		CsrPEM:   api.CertificateRequest{CertificateRequest: cr},
		OTT:      token,
		NotAfter: s.lifetime(lifetime),
	})
	if err != nil {
		return nil, nil, err
	}

	var chain []*x509.Certificate
	cert := resp.CertChainPEM[0].Certificate
	for _, c := range resp.CertChainPEM[1:] {
		chain = append(chain, c.Certificate)
	}

	return cert, chain, nil
}

func (s *StepCAS) signToken(subject string, sans []string) (string, error) {
	if s.x5c != nil {
		return s.x5c.SignToken(subject, sans)
	}

	return "", errors.New("stepCAS does not have any provisioner configured")
}

func (s *StepCAS) revokeToken(subject string) (string, error) {
	if s.x5c != nil {
		return s.x5c.RevokeToken(subject)
	}

	return "", errors.New("stepCAS does not have any provisioner configured")
}

func (s *StepCAS) lifetime(d time.Duration) api.TimeDuration {
	if s.x5c != nil {
		d = s.x5c.Lifetime(d)
	}
	var td api.TimeDuration
	td.SetDuration(d)
	println(td.String(), d.String())
	return td
}
