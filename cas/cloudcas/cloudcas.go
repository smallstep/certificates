package cloudcas

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"time"

	privateca "cloud.google.com/go/security/privateca/apiv1beta1"
	"github.com/google/uuid"
	gax "github.com/googleapis/gax-go/v2"
	"github.com/pkg/errors"
	"github.com/smallstep/certificates/cas/apiv1"
	"google.golang.org/api/option"
	pb "google.golang.org/genproto/googleapis/cloud/security/privateca/v1beta1"
	durationpb "google.golang.org/protobuf/types/known/durationpb"
)

func init() {
	apiv1.Register(apiv1.CloudCAS, func(ctx context.Context, opts apiv1.Options) (apiv1.CertificateAuthorityService, error) {
		return New(ctx, opts)
	})
}

// CertificateAuthorityClient is the interface implemented by the Google CAS
// client.
type CertificateAuthorityClient interface {
	CreateCertificate(ctx context.Context, req *pb.CreateCertificateRequest, opts ...gax.CallOption) (*pb.Certificate, error)
	RevokeCertificate(ctx context.Context, req *pb.RevokeCertificateRequest, opts ...gax.CallOption) (*pb.Certificate, error)
	GetCertificateAuthority(ctx context.Context, req *pb.GetCertificateAuthorityRequest, opts ...gax.CallOption) (*pb.CertificateAuthority, error)
}

// recocationCodeMap maps revocation reason codes from RFC 5280, to Google CAS
// revocation reasons. Revocation reason 7 is not used, and revocation reason 8
// (removeFromCRL) is not supported by Google CAS.
var revocationCodeMap = map[int]pb.RevocationReason{
	0:  pb.RevocationReason_REVOCATION_REASON_UNSPECIFIED,
	1:  pb.RevocationReason_KEY_COMPROMISE,
	2:  pb.RevocationReason_CERTIFICATE_AUTHORITY_COMPROMISE,
	3:  pb.RevocationReason_AFFILIATION_CHANGED,
	4:  pb.RevocationReason_SUPERSEDED,
	5:  pb.RevocationReason_CESSATION_OF_OPERATION,
	6:  pb.RevocationReason_CERTIFICATE_HOLD,
	9:  pb.RevocationReason_PRIVILEGE_WITHDRAWN,
	10: pb.RevocationReason_ATTRIBUTE_AUTHORITY_COMPROMISE,
}

// CloudCAS implements a Certificate Authority Service using Google Cloud CAS.
type CloudCAS struct {
	client               CertificateAuthorityClient
	certificateAuthority string
}

// newCertificateAuthorityClient creates the certificate authority client. This
// function is used for testing purposes.
var newCertificateAuthorityClient = func(ctx context.Context, credentialsFile string) (CertificateAuthorityClient, error) {
	var cloudOpts []option.ClientOption
	if credentialsFile != "" {
		cloudOpts = append(cloudOpts, option.WithCredentialsFile(credentialsFile))
	}
	client, err := privateca.NewCertificateAuthorityClient(ctx, cloudOpts...)
	if err != nil {
		return nil, errors.Wrap(err, "error creating client")
	}
	return client, nil
}

// New creates a new CertificateAuthorityService implementation using Google
// Cloud CAS.
func New(ctx context.Context, opts apiv1.Options) (*CloudCAS, error) {
	if opts.CertificateAuthority == "" {
		return nil, errors.New("cloudCAS 'certificateAuthority' cannot be empty")
	}

	client, err := newCertificateAuthorityClient(ctx, opts.CredentialsFile)
	if err != nil {
		return nil, err
	}

	return &CloudCAS{
		client:               client,
		certificateAuthority: opts.CertificateAuthority,
	}, nil
}

// GetCertificateAuthority returns the root certificate for the given
// certificate authority. It implements apiv1.CertificateAuthorityGetter
// interface.
func (c *CloudCAS) GetCertificateAuthority(req *apiv1.GetCertificateAuthorityRequest) (*apiv1.GetCertificateAuthorityResponse, error) {
	name := req.Name
	if name == "" {
		name = c.certificateAuthority
	}

	ctx, cancel := defaultContext()
	defer cancel()

	resp, err := c.client.GetCertificateAuthority(ctx, &pb.GetCertificateAuthorityRequest{
		Name: name,
	})
	if err != nil {
		return nil, errors.Wrap(err, "cloudCAS GetCertificateAuthority failed")
	}
	if len(resp.PemCaCertificates) == 0 {
		return nil, errors.New("cloudCAS GetCertificateAuthority: PemCACertificate should not be empty")
	}

	// Last certificate in the chain is the root.
	root, err := parseCertificate(resp.PemCaCertificates[len(resp.PemCaCertificates)-1])
	if err != nil {
		return nil, err
	}

	return &apiv1.GetCertificateAuthorityResponse{
		RootCertificate: root,
	}, nil
}

// CreateCertificate signs a new certificate using Google Cloud CAS.
func (c *CloudCAS) CreateCertificate(req *apiv1.CreateCertificateRequest) (*apiv1.CreateCertificateResponse, error) {
	switch {
	case req.Template == nil:
		return nil, errors.New("createCertificateRequest `template` cannot be nil")
	case req.Lifetime == 0:
		return nil, errors.New("createCertificateRequest `lifetime` cannot be 0")
	}

	cert, chain, err := c.createCertificate(req.Template, req.Lifetime, req.RequestID)
	if err != nil {
		return nil, err
	}

	return &apiv1.CreateCertificateResponse{
		Certificate:      cert,
		CertificateChain: chain,
	}, nil
}

// RenewCertificate renews the given certificate using Google Cloud CAS.
// Google's CAS does not support the renew operation, so this method uses
// CreateCertificate.
func (c *CloudCAS) RenewCertificate(req *apiv1.RenewCertificateRequest) (*apiv1.RenewCertificateResponse, error) {
	switch {
	case req.Template == nil:
		return nil, errors.New("renewCertificateRequest `template` cannot be nil")
	case req.Lifetime == 0:
		return nil, errors.New("renewCertificateRequest `lifetime` cannot be 0")
	}

	cert, chain, err := c.createCertificate(req.Template, req.Lifetime, req.RequestID)
	if err != nil {
		return nil, err
	}

	return &apiv1.RenewCertificateResponse{
		Certificate:      cert,
		CertificateChain: chain,
	}, nil
}

// RevokeCertificate a certificate using Google Cloud CAS.
func (c *CloudCAS) RevokeCertificate(req *apiv1.RevokeCertificateRequest) (*apiv1.RevokeCertificateResponse, error) {
	reason, ok := revocationCodeMap[req.ReasonCode]
	switch {
	case !ok:
		return nil, errors.Errorf("revokeCertificate 'reasonCode=%d' is invalid or not supported", req.ReasonCode)
	case req.Certificate == nil:
		return nil, errors.New("revokeCertificateRequest `certificate` cannot be nil")
	}

	ext, ok := apiv1.FindCertificateAuthorityExtension(req.Certificate)
	if !ok {
		return nil, errors.New("error revoking certificate: certificate authority extension was not found")
	}

	var cae apiv1.CertificateAuthorityExtension
	if _, err := asn1.Unmarshal(ext.Value, &cae); err != nil {
		return nil, errors.Wrap(err, "error unmarshaling certificate authority extension")
	}

	ctx, cancel := defaultContext()
	defer cancel()

	certpb, err := c.client.RevokeCertificate(ctx, &pb.RevokeCertificateRequest{
		Name:      c.certificateAuthority + "/certificates/" + cae.CertificateID,
		Reason:    reason,
		RequestId: req.RequestID,
	})
	if err != nil {
		return nil, errors.Wrap(err, "cloudCAS RevokeCertificate failed")
	}

	cert, chain, err := getCertificateAndChain(certpb)
	if err != nil {
		return nil, err
	}

	return &apiv1.RevokeCertificateResponse{
		Certificate:      cert,
		CertificateChain: chain,
	}, nil
}

func (c *CloudCAS) createCertificate(tpl *x509.Certificate, lifetime time.Duration, requestID string) (*x509.Certificate, []*x509.Certificate, error) {
	// Removes the CAS extension if it exists.
	apiv1.RemoveCertificateAuthorityExtension(tpl)

	// Create new CAS extension with the certificate id.
	id, err := createCertificateID()
	if err != nil {
		return nil, nil, err
	}
	casExtension, err := apiv1.CreateCertificateAuthorityExtension(apiv1.CloudCAS, id)
	if err != nil {
		return nil, nil, err
	}
	tpl.ExtraExtensions = append(tpl.ExtraExtensions, casExtension)

	// Create and submit certificate
	certConfig, err := createCertificateConfig(tpl)
	if err != nil {
		return nil, nil, err
	}

	ctx, cancel := defaultContext()
	defer cancel()

	cert, err := c.client.CreateCertificate(ctx, &pb.CreateCertificateRequest{
		Parent:        c.certificateAuthority,
		CertificateId: id,
		Certificate: &pb.Certificate{
			CertificateConfig: certConfig,
			Lifetime:          durationpb.New(lifetime),
			Labels:            map[string]string{},
		},
		RequestId: requestID,
	})
	if err != nil {
		return nil, nil, errors.Wrap(err, "cloudCAS CreateCertificate failed")
	}

	// Return certificate and certificate chain
	return getCertificateAndChain(cert)
}

func defaultContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 15*time.Second)
}

func createCertificateID() (string, error) {
	id, err := uuid.NewRandomFromReader(rand.Reader)
	if err != nil {
		return "", errors.Wrap(err, "error creating certificate id")
	}
	return id.String(), nil
}

func parseCertificate(pemCert string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemCert))
	if block == nil {
		return nil, errors.New("error decoding certificate: not a valid PEM encoded block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing certificate")
	}
	return cert, nil
}

func getCertificateAndChain(certpb *pb.Certificate) (*x509.Certificate, []*x509.Certificate, error) {
	cert, err := parseCertificate(certpb.PemCertificate)
	if err != nil {
		return nil, nil, err
	}

	pemChain := certpb.PemCertificateChain[:len(certpb.PemCertificateChain)-1]
	chain := make([]*x509.Certificate, len(pemChain))
	for i := range pemChain {
		chain[i], err = parseCertificate(pemChain[i])
		if err != nil {
			return nil, nil, err
		}
	}

	return cert, chain, nil

}
