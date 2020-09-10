package cloudcas

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	privateca "cloud.google.com/go/security/privateca/apiv1beta1"
	"github.com/google/uuid"
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

func debug(v interface{}) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}

var (
	stepOIDRoot                 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64}
	stepOIDCertificateAuthority = append(asn1.ObjectIdentifier(nil), append(stepOIDRoot, 2)...)
)

// CloudCAS implements a Certificate Authority Service using Google Cloud CAS.
type CloudCAS struct {
	client               *privateca.CertificateAuthorityClient
	certificateAuthority string
}

type caClient interface{}

// New creates a new CertificateAuthorityService implementation using Google
// Cloud CAS.
func New(ctx context.Context, opts apiv1.Options) (*CloudCAS, error) {
	var cloudOpts []option.ClientOption
	if opts.CredentialsFile != "" {
		cloudOpts = append(cloudOpts, option.WithCredentialsFile(opts.CredentialsFile))
	}

	client, err := privateca.NewCertificateAuthorityClient(ctx, cloudOpts...)
	if err != nil {
		return nil, errors.Wrap(err, "error creating client")
	}

	return &CloudCAS{
		client:               client,
		certificateAuthority: "projects/smallstep-cas-test/locations/us-west1/certificateAuthorities/Smallstep-Test-Intermediate-CA",
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
		return nil, errors.New("renewCertificate `template` cannot be nil")
	case req.Lifetime == 0:
		return nil, errors.New("renewCertificate `lifetime` cannot be 0")
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
	if req.Certificate == nil {
		return nil, errors.New("revokeCertificate `certificate` cannot be nil")
	}

	ext, ok := apiv1.FindCertificateAuthorityExtension(req.Certificate)
	if !ok {
		return nil, errors.New("error revoking certificate: certificate authority extension was not found")
	}

	var cae apiv1.CertificateAuthorityExtension
	if _, err := asn1.Unmarshal(ext.Value, &ext); err != nil {
		return nil, errors.Wrap(err, "error unmarshaling certificate authority extension")
	}

	ctx, cancel := defaultContext()
	defer cancel()

	certpb, err := c.client.RevokeCertificate(ctx, &pb.RevokeCertificateRequest{
		Name:   c.certificateAuthority + "/certificates/" + cae.CertificateID,
		Reason: pb.RevocationReason_REVOCATION_REASON_UNSPECIFIED,
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
	id, err := uuid.NewRandom()
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
