package provisioner

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"time"

	"github.com/pkg/errors"

	"go.step.sm/linkedca"

	"github.com/smallstep/certificates/webhook"
)

// SCEP is the SCEP provisioner type, an entity that can authorize the
// SCEP provisioning flow
type SCEP struct {
	*base
	ID                string   `json:"-"`
	Type              string   `json:"type"`
	Name              string   `json:"name"`
	ForceCN           bool     `json:"forceCN,omitempty"`
	ChallengePassword string   `json:"challenge,omitempty"`
	Capabilities      []string `json:"capabilities,omitempty"`

	// IncludeRoot makes the provisioner return the CA root in addition to the
	// intermediate in the GetCACerts response
	IncludeRoot bool `json:"includeRoot,omitempty"`

	// MinimumPublicKeyLength is the minimum length for public keys in CSRs
	MinimumPublicKeyLength int `json:"minimumPublicKeyLength,omitempty"`

	// Numerical identifier for the ContentEncryptionAlgorithm as defined in github.com/mozilla-services/pkcs7
	// at https://github.com/mozilla-services/pkcs7/blob/33d05740a3526e382af6395d3513e73d4e66d1cb/encrypt.go#L63
	// Defaults to 0, being DES-CBC
	EncryptionAlgorithmIdentifier int      `json:"encryptionAlgorithmIdentifier,omitempty"`
	Options                       *Options `json:"options,omitempty"`
	Claims                        *Claims  `json:"claims,omitempty"`
	ctl                           *Controller
	encryptionAlgorithm           int
	challengeValidationController *challengeValidationController
}

// GetID returns the provisioner unique identifier.
func (s *SCEP) GetID() string {
	if s.ID != "" {
		return s.ID
	}
	return s.GetIDForToken()
}

// GetIDForToken returns an identifier that will be used to load the provisioner
// from a token.
func (s *SCEP) GetIDForToken() string {
	return "scep/" + s.Name
}

// GetName returns the name of the provisioner.
func (s *SCEP) GetName() string {
	return s.Name
}

// GetType returns the type of provisioner.
func (s *SCEP) GetType() Type {
	return TypeSCEP
}

// GetEncryptedKey returns the base provisioner encrypted key if it's defined.
func (s *SCEP) GetEncryptedKey() (string, string, bool) {
	return "", "", false
}

// GetTokenID returns the identifier of the token.
func (s *SCEP) GetTokenID(string) (string, error) {
	return "", errors.New("scep provisioner does not implement GetTokenID")
}

// GetOptions returns the configured provisioner options.
func (s *SCEP) GetOptions() *Options {
	return s.Options
}

// DefaultTLSCertDuration returns the default TLS cert duration enforced by
// the provisioner.
func (s *SCEP) DefaultTLSCertDuration() time.Duration {
	return s.ctl.Claimer.DefaultTLSCertDuration()
}

type challengeValidationController struct {
	client   *http.Client
	webhooks []*Webhook
}

// newChallengeValidationController creates a new challengeValidationController
// that performs challenge validation through webhooks.
func newChallengeValidationController(client *http.Client, webhooks []*Webhook) *challengeValidationController {
	scepHooks := []*Webhook{}
	for _, wh := range webhooks {
		if wh.Kind != linkedca.Webhook_SCEPCHALLENGE.String() {
			continue
		}
		if !isCertTypeOK(wh) {
			continue
		}
		scepHooks = append(scepHooks, wh)
	}
	return &challengeValidationController{
		client:   client,
		webhooks: scepHooks,
	}
}

var (
	ErrSCEPChallengeInvalid = errors.New("webhook server did not allow request")
)

// Validate executes zero or more configured webhooks to
// validate the SCEP challenge. If at least one of them indicates
// the challenge value is accepted, validation succeeds. In
// that case, the other webhooks will be skipped. If none of
// the webhooks indicates the value of the challenge was accepted,
// an error is returned.
func (c *challengeValidationController) Validate(ctx context.Context, challenge, transactionID string) error {
	for _, wh := range c.webhooks {
		req := &webhook.RequestBody{
			SCEPChallenge:     challenge,
			SCEPTransactionID: transactionID,
		}
		resp, err := wh.DoWithContext(ctx, c.client, req, nil) // TODO(hs): support templated URL? Requires some refactoring
		if err != nil {
			return fmt.Errorf("failed executing webhook request: %w", err)
		}
		if resp.Allow {
			return nil // return early when response is positive
		}
	}

	return ErrSCEPChallengeInvalid
}

// isCertTypeOK returns whether or not the webhook can be used
// with the SCEP challenge validation webhook controller.
func isCertTypeOK(wh *Webhook) bool {
	if wh.CertType == linkedca.Webhook_ALL.String() || wh.CertType == "" {
		return true
	}
	return linkedca.Webhook_X509.String() == wh.CertType
}

// Init initializes and validates the fields of a SCEP type.
func (s *SCEP) Init(config Config) (err error) {
	switch {
	case s.Type == "":
		return errors.New("provisioner type cannot be empty")
	case s.Name == "":
		return errors.New("provisioner name cannot be empty")
	}

	// Default to 2048 bits minimum public key length (for CSRs) if not set
	if s.MinimumPublicKeyLength == 0 {
		s.MinimumPublicKeyLength = 2048
	}

	if s.MinimumPublicKeyLength%8 != 0 {
		return errors.Errorf("%d bits is not exactly divisible by 8", s.MinimumPublicKeyLength)
	}

	s.encryptionAlgorithm = s.EncryptionAlgorithmIdentifier // TODO(hs): we might want to upgrade the default security to AES-CBC?
	if s.encryptionAlgorithm < 0 || s.encryptionAlgorithm > 4 {
		return errors.New("only encryption algorithm identifiers from 0 to 4 are valid")
	}

	s.challengeValidationController = newChallengeValidationController(
		config.WebhookClient,
		s.GetOptions().GetWebhooks(),
	)

	// TODO: add other, SCEP specific, options?

	s.ctl, err = NewController(s, s.Claims, config, s.Options)
	return
}

// AuthorizeSign does not do any verification, because all verification is handled
// in the SCEP protocol. This method returns a list of modifiers / constraints
// on the resulting certificate.
func (s *SCEP) AuthorizeSign(context.Context, string) ([]SignOption, error) {
	return []SignOption{
		s,
		// modifiers / withOptions
		newProvisionerExtensionOption(TypeSCEP, s.Name, ""),
		newForceCNOption(s.ForceCN),
		profileDefaultDuration(s.ctl.Claimer.DefaultTLSCertDuration()),
		// validators
		newPublicKeyMinimumLengthValidator(s.MinimumPublicKeyLength),
		newValidityValidator(s.ctl.Claimer.MinTLSCertDuration(), s.ctl.Claimer.MaxTLSCertDuration()),
		newX509NamePolicyValidator(s.ctl.getPolicy().getX509()),
		s.ctl.newWebhookController(nil, linkedca.Webhook_X509),
	}, nil
}

// GetCapabilities returns the CA capabilities
func (s *SCEP) GetCapabilities() []string {
	return s.Capabilities
}

// ShouldIncludeRootInChain indicates if the CA should
// return its intermediate, which is currently used for
// both signing and decryption, as well as the root in
// its chain.
func (s *SCEP) ShouldIncludeRootInChain() bool {
	return s.IncludeRoot
}

// GetContentEncryptionAlgorithm returns the numeric identifier
// for the pkcs7 package encryption algorithm to use.
func (s *SCEP) GetContentEncryptionAlgorithm() int {
	return s.encryptionAlgorithm
}

// ValidateChallenge validates the provided challenge. It starts by
// selecting the validation method to use, then performs validation
// according to that method.
func (s *SCEP) ValidateChallenge(ctx context.Context, challenge, transactionID string) error {
	if s.challengeValidationController == nil {
		return fmt.Errorf("provisioner %q wasn't initialized", s.Name)
	}
	switch s.selectValidationMethod() {
	case validationMethodWebhook:
		return s.challengeValidationController.Validate(ctx, challenge, transactionID)
	default:
		if subtle.ConstantTimeCompare([]byte(s.ChallengePassword), []byte(challenge)) == 0 {
			return errors.New("invalid challenge password provided")
		}
		return nil
	}
}

type validationMethod string

const (
	validationMethodNone    validationMethod = "none"
	validationMethodStatic  validationMethod = "static"
	validationMethodWebhook validationMethod = "webhook"
)

// selectValidationMethod returns the method to validate SCEP
// challenges. If a webhook is configured with kind `SCEPCHALLENGE`,
// the webhook method will be used. If a challenge password is set,
// the static method is used. It will default to the `none` method.
func (s *SCEP) selectValidationMethod() validationMethod {
	if len(s.challengeValidationController.webhooks) > 0 {
		return validationMethodWebhook
	}
	if s.ChallengePassword != "" {
		return validationMethodStatic
	}
	return validationMethodNone
}
