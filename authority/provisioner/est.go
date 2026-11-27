package provisioner

import (
	"context"
	"crypto"
	"crypto/x509"
	"time"

	"github.com/pkg/errors"

	"github.com/smallstep/linkedca"

	"github.com/smallstep/certificates/authority/provisioner/est"

	"github.com/smallstep/certificates/internal/httptransport"
)

// EST is the EST provisioner type, an entity that can authorize the EST flow.
type EST struct {
	*base
	ID   string `json:"-"`
	Type string `json:"type"`
	Name string `json:"name"`

	ForceCN                bool `json:"forceCN,omitempty"`
	MinimumPublicKeyLength int  `json:"minimumPublicKeyLength,omitempty"`

	// Authentication configures accepted client authentication. At
	// least one method is required; RFC 7030 3.2.3 permits requiring
	// HTTP authentication in addition to TLS client authentication.
	Authentication est.Authentication `json:"authentication"`

	// Operations enables EST operations. Defaults to cacerts,
	// csrattrs, simpleenroll and simplereenroll.
	Operations []est.Operation `json:"operations,omitempty"`

	CACerts       est.CACerts        `json:"cacerts,omitempty"`
	CSRAttributes *est.CSRAttributes `json:"csrAttributes,omitempty"`

	// ProofOfPossession controls tls-unique identity/PoP linking
	// (RFC 7030 3.5): disabled | optional | required.
	ProofOfPossession est.PoPMode `json:"proofOfPossession,omitempty"`

	DummyBool   *bool
	DummyString string

	// EnableTLSClientCertificate   *bool  `json:"enableTlsClientCertificate,omitempty"`
	// ForwardedTLSClientCertHeader string `json:"forwardedTlsClientCertHeader,omitempty"`
	// EnableHTTPBasicAuth          *bool  `json:"enableHTTPBasicAuth,omitempty"`
	// BasicAuthUsername            string `json:"basicAuthUsername,omitempty"`
	// BasicAuthPassword            string `json:"basicAuthPassword,omitempty"`
	// ClientCertificateRoots       []byte `json:"clientCertificateRoots,omitempty"`

	Options *Options `json:"options,omitempty"`
	Claims  *Claims  `json:"claims,omitempty"`

	ctl                           *Controller
	signer                        crypto.Signer
	signerCertificate             *x509.Certificate
	challengeValidationController *challengeValidationController
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
		if wh.Kind != linkedca.Webhook_ESTCHALLENGE.String() {
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

	// if err := s.parseClientCertificateRoots(); err != nil {
	// 	return err
	// }

	// if err := s.normalizeAuthConfig(); err != nil {
	// 	return err
	// }

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

// GetCSRAttributes returns the CSR attributes to signal to clients.
func (s *EST) GetCSRAttributes(context.Context) ([]byte, error) {
	return nil, nil // TODO(hs): refactor
}
