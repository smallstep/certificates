package adcscas

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math"
	"os"
	"strings"
	"time"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wcce"
	"github.com/oiweiwei/go-msrpc/msrpc/epm/epm/v3"
	"github.com/oiweiwei/go-msrpc/msrpc/icpr/icertpassage/v0"
	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
	"github.com/oiweiwei/go-msrpc/text/encoding/utf16le"
	"github.com/pkg/errors"
	"github.com/smallstep/certificates/cas/apiv1"
)

func init() {
	apiv1.Register(apiv1.ADCSCAS, func(ctx context.Context, opts apiv1.Options) (apiv1.CertificateAuthorityService, error) {
		return New(ctx, opts)
	})
}

var now = time.Now

type ADCSOptions struct {
	ServerAddr string `json:"serverAddr"`
	AuthUser   string `json:"authUser"`
	AuthPass   string `json:"authPass"`

	RootCAPath         string `json:"rootCAPath"`
	IntermediateCAPath string `json:"intermediateCAPath"`

	CAName              string            `json:"caName"`
	DefaultTemplateName string            `json:"defaultTemplateName"`
	TemplateMap         map[string]string `json:"templateMap"`
}

// ADCSCAS implements a Certificate Authority Service using Active Directory Certificate Services
type ADCSCAS struct {
	Config                   ADCSOptions
	rpcOptions               []dcerpc.Option
	securityContext          context.Context
	rootCertificate          *x509.Certificate
	intermediateCertificates []*x509.Certificate
	pkiTargetName            string
}

// New creates a new CertificateAuthorityService implementation using Active Directory Certificate Services
func New(ctx context.Context, opts apiv1.Options) (*ADCSCAS, error) {
	var adcsConfig ADCSOptions

	err := json.Unmarshal(opts.Config, &adcsConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding adcsCAS config: %w", err)
	}

	targetName := strings.ToUpper(strings.SplitN(adcsConfig.ServerAddr, ".", 1)[0])

	securityContext := gssapi.NewSecurityContext(ctx)

	cred := credential.NewFromPassword(adcsConfig.AuthUser, adcsConfig.AuthPass)

	rpcOptions := []dcerpc.Option{
		dcerpc.WithMechanism(ssp.NTLM),
		dcerpc.WithCredentials(cred),
		epm.EndpointMapper(
			securityContext,
			adcsConfig.ServerAddr,
		),
	}

	var rootCACertificate *x509.Certificate
	var intermediateCABundle []*x509.Certificate

	if adcsConfig.RootCAPath != "" {
		rootPEM, err := os.ReadFile(adcsConfig.RootCAPath)
		if err != nil {
			return nil, err
		}

		rootBytes, _ := pem.Decode(rootPEM)
		rootCACertificate, err = x509.ParseCertificate(rootBytes.Bytes)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("ADCS CAS requires rootCAPath to be set")
	}

	if adcsConfig.IntermediateCAPath != "" {
		pemFile, err := os.ReadFile(adcsConfig.IntermediateCAPath)
		if err != nil {
			return nil, err
		}

		for pemBlock, remainingPEM := pem.Decode(pemFile); pemBlock != nil; pemBlock, remainingPEM = pem.Decode(remainingPEM) {
			if pemBlock.Type == "CERTIFICATE" {
				intermediateCA, err := x509.ParseCertificate(pemBlock.Bytes)
				if err != nil {
					return nil, fmt.Errorf("error parsing intermediate certificate: %w", err)
				}

				intermediateCABundle = append(intermediateCABundle, intermediateCA)
			}
		}
	} else {
		return nil, errors.New("ADCS CAS requires intermediateCAPath to be set")
	}

	return &ADCSCAS{
		Config:                   adcsConfig,
		rpcOptions:               rpcOptions,
		rootCertificate:          rootCACertificate,
		intermediateCertificates: intermediateCABundle,
		securityContext:          securityContext,
		pkiTargetName:            targetName,
	}, nil
}

// Type returns the type of this CertificateAuthorityService.
func (c *ADCSCAS) Type() apiv1.Type {
	return apiv1.ADCSCAS
}

// CreateCertificate signs a new certificate using ADCS.
func (c *ADCSCAS) CreateCertificate(req *apiv1.CreateCertificateRequest) (*apiv1.CreateCertificateResponse, error) {
	switch {
	case req.Template == nil:
		return nil, errors.New("createCertificateRequest `template` cannot be nil")
	case req.Lifetime == 0:
		return nil, errors.New("createCertificateRequest `lifetime` cannot be 0")
	}

	t := now()

	// Provisioners can also set specific values.
	if req.Template.NotBefore.IsZero() {
		req.Template.NotBefore = t.Add(-1 * req.Backdate)
	}
	if req.Template.NotAfter.IsZero() {
		req.Template.NotAfter = t.Add(req.Lifetime)
	}

	// find a suitable template name
	var certificateTemplate = c.Config.DefaultTemplateName
	if c.Config.TemplateMap != nil {
		certificateTemplate, _ = c.Config.TemplateMap[req.Provisioner.Name]
	}

	icc, err := dcerpc.Dial(c.securityContext, c.Config.ServerAddr, c.rpcOptions...)
	if err != nil {
		return nil, fmt.Errorf("error dialing %v: %w", c.Config.ServerAddr, err)
	}

	defer icc.Close(c.securityContext)

	icpClient, err := icertpassage.NewCertPassageClient(
		c.securityContext,
		icc,
		dcerpc.WithTargetName(fmt.Sprintf("host/%s", c.pkiTargetName)),
		dcerpc.WithSeal(),
		dcerpc.WithSecurityLevel(dcerpc.AuthLevelPktPrivacy),
	)
	if err != nil {
		return nil, err
	}

	encodedAttribs, err := utf16le.Encode(fmt.Sprintf("CertificateTemplate:%s\n", certificateTemplate) + string(rune(0)))
	if err != nil {
		return nil, err
	}

	if len(encodedAttribs) >= math.MaxUint32 {
		return nil, errors.New("certificateTemplate contains too many attribs")
	}

	if len(req.CSR.Raw) >= math.MaxUint32 {
		return nil, errors.New("csr too long for request")
	}

	icpReq := icertpassage.CertServerRequestRequest{
		Flags:     0,
		Authority: c.Config.CAName,
		RequestID: 0,
		Attributes: &wcce.CertTransportBlob{
			Length: uint32(len(encodedAttribs)), //nolint:gosec // disable G115
			Buffer: encodedAttribs,
		},
		Request: &wcce.CertTransportBlob{
			Length: uint32(len(req.CSR.Raw)), //nolint:gosec // disable G115
			Buffer: req.CSR.Raw,
		},
	}

	certResponse, err := icpClient.CertServerRequest(c.securityContext, &icpReq)

	if err != nil {
		return nil, err
	}

	switch certResponse.Disposition {
	case 3:
		issuedCert, err := x509.ParseCertificate(certResponse.EncodedCert.Buffer)
		if err != nil {
			return nil, fmt.Errorf("error parsing returned certificate: %w", err)
		}
		return &apiv1.CreateCertificateResponse{
			Certificate:      issuedCert,
			CertificateChain: c.intermediateCertificates,
		}, nil
	case 5:
		return nil, errors.New("CertServerRequest Pending Approval")
	default:
		msg, err := utf16le.Decode(certResponse.DispositionMessage.Buffer)
		if err != nil {
			return nil, errors.New("Error decoding error message from ADCS: " + err.Error())
		}
		return nil, errors.New(msg)
	}
}

// RenewCertificate signs the given certificate template. In ADCSCAS this is not implemented.
func (c *ADCSCAS) RenewCertificate(req *apiv1.RenewCertificateRequest) (*apiv1.RenewCertificateResponse, error) {
	return nil, apiv1.NotImplementedError{Message: "adcsCAS does not support renewals"}
}

// RevokeCertificate revokes the given certificate. In ADCSCAS this
// is not implemented, but it is possible to send a revocation request using the icertadmind service:
//
//	https://github.com/oiweiwei/go-msrpc/blob/60ff6238355b5e7d1ff8f86a3d80ec7b0b523fb3/msrpc/dcom/csra/icertadmind/v0/v0.go#L83
func (c *ADCSCAS) RevokeCertificate(req *apiv1.RevokeCertificateRequest) (*apiv1.RevokeCertificateResponse, error) {
	return nil, apiv1.NotImplementedError{Message: "adcsCAS does not support revocation"}
}

func (c *ADCSCAS) GetCertificateAuthority(*apiv1.GetCertificateAuthorityRequest) (*apiv1.GetCertificateAuthorityResponse, error) {
	return &apiv1.GetCertificateAuthorityResponse{
		RootCertificate:          c.rootCertificate,
		IntermediateCertificates: c.intermediateCertificates,
	}, nil
}
