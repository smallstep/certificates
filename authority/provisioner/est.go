package provisioner

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/pkg/errors"

	"github.com/smallstep/certificates/internal/httptransport"
	"github.com/smallstep/linkedca"
)

// EST is the EST provisioner type, an entity that can authorize the EST flow.
type EST struct {
	*base
	ID                            string   `json:"-"`
	Type                          string   `json:"type"`
	Name                          string   `json:"name"`
	EnableTLSClientCertificate    *bool    `json:"enableTlsClientCertificate,omitempty"`
	ForwardedTLSClientCertHeader  string   `json:"forwardedTlsClientCertHeader,omitempty"`
	EnableHTTPBasicAuth           *bool    `json:"enableHTTPBasicAuth,omitempty"`
	BasicAuthUsername             string   `json:"basicAuthUsername,omitempty"`
	BasicAuthPassword             string   `json:"basicAuthPassword,omitempty"`
	ClientCertificateRoots        []byte   `json:"clientCertificateRoots,omitempty"`
	ForceCN                       bool     `json:"forceCN,omitempty"`
	IncludeRoot                   bool     `json:"includeRoot,omitempty"`
	ExcludeIntermediate           bool     `json:"excludeIntermediate,omitempty"`
	MinimumPublicKeyLength        int      `json:"minimumPublicKeyLength,omitempty"`
	CSRAttrs                      []byte   `json:"csrAttrs,omitempty"`
	Options                       *Options `json:"options,omitempty"`
	Claims                        *Claims  `json:"claims,omitempty"`
	ctl                           *Controller
	signer                        crypto.Signer
	signerCertificate             *x509.Certificate
	challengeValidationController *challengeValidationController
	notificationController        *notificationController
	clientCertificateRootPool     *x509.CertPool
}

// GetID returns the provisioner unique identifier.
func (s *EST) GetID() string {
	if s.ID != "" {
		return s.ID
	}
	return s.GetIDForToken()
}

// GetIDForToken returns an identifier that will be used to load the provisioner from a token.
func (s *EST) GetIDForToken() string {
	return "est/" + s.Name
}

// GetName returns the name of the provisioner.
func (s *EST) GetName() string {
	return s.Name
}

// GetType returns the type of provisioner.
func (s *EST) GetType() Type {
	return TypeEST
}

// GetEncryptedKey returns the base provisioner encrypted key if it's defined.
func (s *EST) GetEncryptedKey() (string, string, bool) {
	return "", "", false
}

// GetTokenID returns the identifier of the token. This provisioner does not support tokens.
func (s *EST) GetTokenID(string) (string, error) {
	return "", ErrTokenFlowNotSupported
}

// GetOptions returns the configured provisioner options.
func (s *EST) GetOptions() *Options {
	return s.Options
}

// DefaultTLSCertDuration returns the default TLS cert duration enforced by the provisioner.
func (s *EST) DefaultTLSCertDuration() time.Duration {
	return s.ctl.Claimer.DefaultTLSCertDuration()
}

// newChallengeValidationController creates a new challengeValidationController
// that performs challenge validation through webhooks.
func newESTChallengeValidationController(client HTTPClient, tw httptransport.Wrapper, webhooks []*Webhook) *challengeValidationController {
	estHooks := []*Webhook{}
	for _, wh := range webhooks {
		// if wh.Kind != linkedca.Webhook_ESTCHALLENGE.String() {
		if wh.Kind != "ESTCHALLENGE" {
			continue
		}
		estHooks = append(estHooks, wh)
	}
	return &challengeValidationController{
		client:        client,
		wrapTransport: tw,
		webhooks:      estHooks,
	}
}

// Init initializes and validates the fields of an EST type.
func (s *EST) Init(config Config) (err error) {
	switch {
	case s.Type == "":
		return errors.New("provisioner type cannot be empty")
	case s.Name == "":
		return errors.New("provisioner name cannot be empty")
	}

	if s.MinimumPublicKeyLength == 0 {
		s.MinimumPublicKeyLength = 2048
	}
	if s.MinimumPublicKeyLength%8 != 0 {
		return errors.Errorf("%d bits is not exactly divisible by 8", s.MinimumPublicKeyLength)
	}

	// Prepare the EST challenge validator
	s.challengeValidationController = newESTChallengeValidationController(
		config.WebhookClient,
		config.WrapTransport,
		s.GetOptions().GetWebhooks(),
	)

	// Prepare the EST notification controller
	s.notificationController = newNotificationController(
		config.WebhookClient,
		config.WrapTransport,
		s.GetOptions().GetWebhooks(),
	)

	if err := s.parseClientCertificateRoots(); err != nil {
		return err
	}

	if err := s.normalizeAuthConfig(); err != nil {
		return err
	}

	s.ctl, err = NewController(s, s.Claims, config, s.Options)
	return err
}

// AuthorizeSign does not do any verification; main validation is in the EST protocol.
func (s *EST) AuthorizeSign(context.Context, string) ([]SignOption, error) {
	return []SignOption{
		s,
		newProvisionerExtensionOption(TypeEST, s.Name, "").WithControllerOptions(s.ctl),
		newForceCNOption(s.ForceCN),
		profileDefaultDuration(s.ctl.Claimer.DefaultTLSCertDuration()),
		newPublicKeyMinimumLengthValidator(s.MinimumPublicKeyLength),
		newValidityValidator(s.ctl.Claimer.MinTLSCertDuration(), s.ctl.Claimer.MaxTLSCertDuration()),
		newX509NamePolicyValidator(s.ctl.getPolicy().getX509()),
		s.ctl.newWebhookController(nil, linkedca.Webhook_X509),
	}, nil
}

// ShouldIncludeRootInChain indicates if the CA should return its root in the chain.
func (s *EST) ShouldIncludeRootInChain() bool {
	return s.IncludeRoot
}

// ShouldIncludeIntermediateInChain indicates if the CA should include the intermediate CA certificate.
func (s *EST) ShouldIncludeIntermediateInChain() bool {
	return !s.ExcludeIntermediate
}

// GetSigner returns the provisioner specific signer, used to sign EST responses.
func (s *EST) GetSigner() (*x509.Certificate, crypto.Signer) {
	return s.signerCertificate, s.signer
}

// GetCSRAttributes returns the CSR attributes to signal to clients.
func (s *EST) GetCSRAttributes(context.Context) ([]byte, error) {
	return s.CSRAttrs, nil
}

func (s *EST) NotifySuccess(ctx context.Context, csr *x509.CertificateRequest, cert *x509.Certificate, transactionID string) error {
	if s.notificationController == nil {
		return fmt.Errorf("provisioner %q wasn't initialized", s.Name)
	}
	return s.notificationController.Success(ctx, csr, cert, transactionID)
}

func (s *EST) NotifyFailure(ctx context.Context, csr *x509.CertificateRequest, transactionID string, errorCode int, errorDescription string) error {
	if s.notificationController == nil {
		return fmt.Errorf("provisioner %q wasn't initialized", s.Name)
	}
	return s.notificationController.Failure(ctx, csr, transactionID, errorCode, errorDescription)
}
