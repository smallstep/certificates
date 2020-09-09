package cloudcas

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	privateca "cloud.google.com/go/security/privateca/apiv1beta1"
	"github.com/pkg/errors"
	"github.com/smallstep/certificates/cas/apiv1"
	privatecapb "google.golang.org/genproto/googleapis/cloud/security/privateca/v1beta1"
	durationpb "google.golang.org/protobuf/types/known/durationpb"
)

func init() {
	apiv1.Register(apiv1.CloudCAS, func(ctx context.Context, opts apiv1.Options) (apiv1.CertificateAuthorityService, error) {
		return New(ctx, opts)
	})
}

// CloudCAS implements a Certificate Authority Service using Google Cloud CAS.
type CloudCAS struct {
	client               *privateca.CertificateAuthorityClient
	certificateAuthority string
}

type caClient interface{}

// New creates a new CertificateAuthorityService implementation using Google
// Cloud CAS.
func New(ctx context.Context, opts apiv1.Options) (*CloudCAS, error) {
	client, err := privateca.NewCertificateAuthorityClient(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "error creating client")
	}

	return &CloudCAS{
		client:               client,
		certificateAuthority: "",
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

	certConfig, err := createCertificateConfig(req.Template)
	if err != nil {
		return nil, err
	}

	ctx, cancel := defaultContext()
	defer cancel()

	certpb, err := c.client.CreateCertificate(ctx, &privatecapb.CreateCertificateRequest{
		Parent:        c.certificateAuthority,
		CertificateId: "",
		Certificate: &privatecapb.Certificate{
			CertificateConfig: certConfig,
			Lifetime:          durationpb.New(req.Lifetime),
			Labels:            map[string]string{},
		},
		RequestId: req.RequestID,
	})
	if err != nil {
		return nil, errors.Wrap(err, "cloudCAS CreateCertificate failed")
	}

	cert, err := parseCertificate(certpb.PemCertificate)
	if err != nil {
		return nil, err
	}

	return &apiv1.CreateCertificateResponse{
		Certificate: cert,
	}, nil
}

func (c *CloudCAS) RenewCertificate(req *apiv1.RenewCertificateRequest) (*apiv1.RenewCertificateResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

// RevokeCertificate a certificate using Google Cloud CAS.
func (c *CloudCAS) RevokeCertificate(req *apiv1.RevokeCertificateRequest) (*apiv1.RevokeCertificateResponse, error) {

	return nil, fmt.Errorf("not implemented")
}

func defaultContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 15*time.Second)
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
