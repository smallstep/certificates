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
	iss         stepIssuer
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

	// Create client.
	client, err := ca.NewClient(opts.CertificateAuthority, ca.WithRootSHA256(opts.CertificateAuthorityFingerprint))
	if err != nil {
		return nil, err
	}

	// Create configured issuer
	iss, err := newStepIssuer(caURL, client, opts.CertificateIssuer)
	if err != nil {
		return nil, err
	}

	return &StepCAS{
		iss:         iss,
		client:      client,
		fingerprint: opts.CertificateAuthorityFingerprint,
	}, nil
}

// CreateCertificate uses the step-ca sign request with the configured
// provisioner to get a new certificate from the certificate authority.
func (s *StepCAS) CreateCertificate(req *apiv1.CreateCertificateRequest) (*apiv1.CreateCertificateResponse, error) {
	switch {
	case req.CSR == nil:
		return nil, errors.New("createCertificateRequest `csr` cannot be nil")
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

// RenewCertificate will always return a non-implemented error as mTLS renewals
// are not supported yet.
func (s *StepCAS) RenewCertificate(req *apiv1.RenewCertificateRequest) (*apiv1.RenewCertificateResponse, error) {
	return nil, apiv1.ErrNotImplemented{Message: "stepCAS does not support mTLS renewals"}
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

	token, err := s.iss.RevokeToken(serialNumber)
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
	sans = append(sans, cr.DNSNames...)
	sans = append(sans, cr.EmailAddresses...)
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

	token, err := s.iss.SignToken(commonName, sans)
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

func (s *StepCAS) lifetime(d time.Duration) api.TimeDuration {
	var td api.TimeDuration
	td.SetDuration(s.iss.Lifetime(d))
	return td
}
