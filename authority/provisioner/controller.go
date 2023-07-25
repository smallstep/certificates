package provisioner

import (
	"context"
	"crypto/x509"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/errs"
	"github.com/smallstep/certificates/webhook"
	"go.step.sm/linkedca"
	"golang.org/x/crypto/ssh"
)

// Controller wraps a provisioner with other attributes useful in callback
// functions.
type Controller struct {
	Interface
	Audiences             *Audiences
	Claimer               *Claimer
	IdentityFunc          GetIdentityFunc
	AuthorizeRenewFunc    AuthorizeRenewFunc
	AuthorizeSSHRenewFunc AuthorizeSSHRenewFunc
	policy                *policyEngine
	webhookClient         *http.Client
	webhooks              []*Webhook
}

// NewController initializes a new provisioner controller.
func NewController(p Interface, claims *Claims, config Config, options *Options) (*Controller, error) {
	claimer, err := NewClaimer(claims, config.Claims)
	if err != nil {
		return nil, err
	}
	policy, err := newPolicyEngine(options)
	if err != nil {
		return nil, err
	}
	return &Controller{
		Interface:             p,
		Audiences:             &config.Audiences,
		Claimer:               claimer,
		IdentityFunc:          config.GetIdentityFunc,
		AuthorizeRenewFunc:    config.AuthorizeRenewFunc,
		AuthorizeSSHRenewFunc: config.AuthorizeSSHRenewFunc,
		policy:                policy,
		webhookClient:         config.WebhookClient,
		webhooks:              options.GetWebhooks(),
	}, nil
}

// GetIdentity returns the identity for a given email.
func (c *Controller) GetIdentity(ctx context.Context, email string) (*Identity, error) {
	if c.IdentityFunc != nil {
		return c.IdentityFunc(ctx, c.Interface, email)
	}
	return DefaultIdentityFunc(ctx, c.Interface, email)
}

// AuthorizeRenew returns nil if the given cert can be renewed, returns an error
// otherwise.
func (c *Controller) AuthorizeRenew(ctx context.Context, cert *x509.Certificate) error {
	if c.AuthorizeRenewFunc != nil {
		return c.AuthorizeRenewFunc(ctx, c, cert)
	}
	return DefaultAuthorizeRenew(ctx, c, cert)
}

// AuthorizeSSHRenew returns nil if the given cert can be renewed, returns an
// error otherwise.
func (c *Controller) AuthorizeSSHRenew(ctx context.Context, cert *ssh.Certificate) error {
	if c.AuthorizeSSHRenewFunc != nil {
		return c.AuthorizeSSHRenewFunc(ctx, c, cert)
	}
	return DefaultAuthorizeSSHRenew(ctx, c, cert)
}

func (c *Controller) newWebhookController(templateData WebhookSetter, certType linkedca.Webhook_CertType, opts ...webhook.RequestBodyOption) *WebhookController {
	client := c.webhookClient
	if client == nil {
		client = http.DefaultClient
	}
	return &WebhookController{
		TemplateData: templateData,
		client:       client,
		webhooks:     c.webhooks,
		certType:     certType,
		options:      opts,
	}
}

// Identity is the type representing an externally supplied identity that is used
// by provisioners to populate certificate fields.
type Identity struct {
	Usernames   []string `json:"usernames"`
	Permissions `json:"permissions"`
}

// GetIdentityFunc is a function that returns an identity.
type GetIdentityFunc func(ctx context.Context, p Interface, email string) (*Identity, error)

// AuthorizeRenewFunc is a function that returns nil if the renewal of a
// certificate is enabled.
type AuthorizeRenewFunc func(ctx context.Context, p *Controller, cert *x509.Certificate) error

// AuthorizeSSHRenewFunc is a function that returns nil if the renewal of the
// given SSH certificate is enabled.
type AuthorizeSSHRenewFunc func(ctx context.Context, p *Controller, cert *ssh.Certificate) error

// DefaultIdentityFunc return a default identity depending on the provisioner
// type. For OIDC email is always present and the usernames might
// contain empty strings.
func DefaultIdentityFunc(_ context.Context, p Interface, email string) (*Identity, error) {
	switch k := p.(type) {
	case *OIDC:
		// OIDC principals would be:
		//   ~~1. Preferred usernames.~~ Note: Under discussion, currently disabled
		//   2. Sanitized local.
		//   3. Raw local (if different).
		//   4. Email address.
		name := SanitizeSSHUserPrincipal(email)
		usernames := []string{name}
		if i := strings.LastIndex(email, "@"); i >= 0 {
			usernames = append(usernames, email[:i])
		}
		usernames = append(usernames, email)
		return &Identity{
			// Remove duplicated and empty usernames.
			Usernames: SanitizeStringSlices(usernames),
		}, nil
	default:
		return nil, errors.Errorf("provisioner type '%T' not supported by identity function", k)
	}
}

// DefaultAuthorizeRenew is the default implementation of AuthorizeRenew. It
// will return an error if the provisioner has the renewal disabled, if the
// certificate is not yet valid or if the certificate is expired and renew after
// expiry is disabled.
func DefaultAuthorizeRenew(_ context.Context, p *Controller, cert *x509.Certificate) error {
	if p.Claimer.IsDisableRenewal() {
		return errs.Unauthorized("renew is disabled for provisioner '%s'", p.GetName())
	}

	now := time.Now().Truncate(time.Second)
	if now.Before(cert.NotBefore) {
		return errs.Unauthorized("certificate is not yet valid" + " " + now.UTC().Format(time.RFC3339Nano) + " vs " + cert.NotBefore.Format(time.RFC3339Nano))
	}
	if now.After(cert.NotAfter) && !p.Claimer.AllowRenewalAfterExpiry() {
		// return a custom 401 Unauthorized error with a clearer message for the client
		// TODO(hs): these errors likely need to be refactored as a whole; HTTP status codes shouldn't be in this layer.
		return errs.New(http.StatusUnauthorized, "The request lacked necessary authorization to be completed: certificate expired on %s", cert.NotAfter)
	}

	return nil
}

// DefaultAuthorizeSSHRenew is the default implementation of AuthorizeSSHRenew. It
// will return an error if the provisioner has the renewal disabled, if the
// certificate is not yet valid or if the certificate is expired and renew after
// expiry is disabled.
func DefaultAuthorizeSSHRenew(_ context.Context, p *Controller, cert *ssh.Certificate) error {
	if p.Claimer.IsDisableRenewal() {
		return errs.Unauthorized("renew is disabled for provisioner '%s'", p.GetName())
	}

	unixNow := time.Now().Unix()
	if after := int64(cert.ValidAfter); after < 0 || unixNow < int64(cert.ValidAfter) {
		return errs.Unauthorized("certificate is not yet valid")
	}
	if before := int64(cert.ValidBefore); cert.ValidBefore != uint64(ssh.CertTimeInfinity) && (unixNow >= before || before < 0) && !p.Claimer.AllowRenewalAfterExpiry() {
		return errs.Unauthorized("certificate has expired")
	}

	return nil
}

// SanitizeStringSlices removes duplicated an empty strings.
func SanitizeStringSlices(original []string) []string {
	output := []string{}
	seen := make(map[string]struct{})
	for _, entry := range original {
		if entry == "" {
			continue
		}
		if _, value := seen[entry]; !value {
			seen[entry] = struct{}{}
			output = append(output, entry)
		}
	}
	return output
}

// SanitizeSSHUserPrincipal grabs an email or a string with the format
// local@domain and returns a sanitized version of the local, valid to be used
// as a user name. If the email starts with a letter between a and z, the
// resulting string will match the regular expression `^[a-z][-a-z0-9_]*$`.
func SanitizeSSHUserPrincipal(email string) string {
	if i := strings.LastIndex(email, "@"); i >= 0 {
		email = email[:i]
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '-':
			return '-'
		case r == '.': // drop dots
			return -1
		default:
			return '_'
		}
	}, strings.ToLower(email))
}

func (c *Controller) getPolicy() *policyEngine {
	if c == nil {
		return nil
	}
	return c.policy
}
