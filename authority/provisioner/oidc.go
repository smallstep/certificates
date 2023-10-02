package provisioner

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/pkg/errors"

	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/sshutil"
	"go.step.sm/crypto/x509util"
	"go.step.sm/linkedca"

	"github.com/smallstep/certificates/errs"
)

// openIDConfiguration contains the necessary properties in the
// `/.well-known/openid-configuration` document.
type openIDConfiguration struct {
	Issuer    string `json:"issuer"`
	JWKSetURI string `json:"jwks_uri"`
}

// Validate validates the values in a well-known OpenID configuration endpoint.
func (c openIDConfiguration) Validate() error {
	switch {
	case c.Issuer == "":
		return errors.New("issuer cannot be empty")
	case c.JWKSetURI == "":
		return errors.New("jwks_uri cannot be empty")
	default:
		return nil
	}
}

// openIDPayload represents the fields on the id_token JWT payload.
type openIDPayload struct {
	jose.Claims
	AtHash          string   `json:"at_hash"`
	AuthorizedParty string   `json:"azp"`
	Email           string   `json:"email"`
	EmailVerified   bool     `json:"email_verified"`
	Hd              string   `json:"hd"`
	Nonce           string   `json:"nonce"`
	Groups          []string `json:"groups"`
}

func (o *openIDPayload) IsAdmin(admins []string) bool {
	if o.Email != "" {
		email := sanitizeEmail(o.Email)
		for _, e := range admins {
			if email == sanitizeEmail(e) {
				return true
			}
		}
	}

	// The groups and emails can be in the same array for now, but consider
	// making a specialized option later.
	for _, name := range o.Groups {
		for _, admin := range admins {
			if name == admin {
				return true
			}
		}
	}

	return false
}

// OIDC represents an OAuth 2.0 OpenID Connect provider.
//
// ClientSecret is mandatory, but it can be an empty string.
type OIDC struct {
	*base
	ID                    string   `json:"-"`
	Type                  string   `json:"type"`
	Name                  string   `json:"name"`
	ClientID              string   `json:"clientID"`
	ClientSecret          string   `json:"clientSecret"`
	ConfigurationEndpoint string   `json:"configurationEndpoint"`
	TenantID              string   `json:"tenantID,omitempty"`
	Admins                []string `json:"admins,omitempty"`
	Domains               []string `json:"domains,omitempty"`
	Groups                []string `json:"groups,omitempty"`
	ListenAddress         string   `json:"listenAddress,omitempty"`
	Claims                *Claims  `json:"claims,omitempty"`
	Options               *Options `json:"options,omitempty"`
	configuration         openIDConfiguration
	keyStore              *keyStore
	ctl                   *Controller
}

func sanitizeEmail(email string) string {
	if i := strings.LastIndex(email, "@"); i >= 0 {
		email = email[:i] + strings.ToLower(email[i:])
	}
	return email
}

// GetID returns the provisioner unique identifier, the OIDC provisioner the
// uses the clientID for this.
func (o *OIDC) GetID() string {
	if o.ID != "" {
		return o.ID
	}
	return o.GetIDForToken()
}

// GetIDForToken returns an identifier that will be used to load the provisioner
// from a token.
func (o *OIDC) GetIDForToken() string {
	return o.ClientID
}

// GetTokenID returns the provisioner unique identifier, the OIDC provisioner the
// uses the clientID for this.
func (o *OIDC) GetTokenID(ott string) (string, error) {
	// Validate payload
	token, err := jose.ParseSigned(ott)
	if err != nil {
		return "", errors.Wrap(err, "error parsing token")
	}

	// Get claims w/out verification. We need to look up the provisioner
	// key in order to verify the claims and we need the issuer from the claims
	// before we can look up the provisioner.
	var claims openIDPayload
	if err = token.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return "", errors.Wrap(err, "error verifying claims")
	}
	return claims.Nonce, nil
}

// GetName returns the name of the provisioner.
func (o *OIDC) GetName() string {
	return o.Name
}

// GetType returns the type of provisioner.
func (o *OIDC) GetType() Type {
	return TypeOIDC
}

// GetEncryptedKey is not available in an OIDC provisioner.
func (o *OIDC) GetEncryptedKey() (kid, key string, ok bool) {
	return "", "", false
}

// Init validates and initializes the OIDC provider.
func (o *OIDC) Init(config Config) (err error) {
	switch {
	case o.Type == "":
		return errors.New("type cannot be empty")
	case o.Name == "":
		return errors.New("name cannot be empty")
	case o.ClientID == "":
		return errors.New("clientID cannot be empty")
	case o.ConfigurationEndpoint == "":
		return errors.New("configurationEndpoint cannot be empty")
	}

	// Validate listenAddress if given
	if o.ListenAddress != "" {
		if _, _, err := net.SplitHostPort(o.ListenAddress); err != nil {
			return errors.Wrap(err, "error parsing listenAddress")
		}
	}

	// Decode and validate openid-configuration endpoint
	u, err := url.Parse(o.ConfigurationEndpoint)
	if err != nil {
		return errors.Wrapf(err, "error parsing %s", o.ConfigurationEndpoint)
	}
	if !strings.Contains(u.Path, "/.well-known/openid-configuration") {
		u.Path = path.Join(u.Path, "/.well-known/openid-configuration")
	}
	if err := getAndDecode(u.String(), &o.configuration); err != nil {
		return err
	}
	if err := o.configuration.Validate(); err != nil {
		return errors.Wrapf(err, "error parsing %s", o.ConfigurationEndpoint)
	}
	// Replace {tenantid} with the configured one
	if o.TenantID != "" {
		o.configuration.Issuer = strings.ReplaceAll(o.configuration.Issuer, "{tenantid}", o.TenantID)
	}
	// Get JWK key set
	o.keyStore, err = newKeyStore(o.configuration.JWKSetURI)
	if err != nil {
		return err
	}

	o.ctl, err = NewController(o, o.Claims, config, o.Options)
	return
}

// ValidatePayload validates the given token payload.
func (o *OIDC) ValidatePayload(p openIDPayload) error {
	// According to "rfc7519 JSON Web Token" acceptable skew should be no more
	// than a few minutes.
	if err := p.ValidateWithLeeway(jose.Expected{
		Issuer:   o.configuration.Issuer,
		Audience: jose.Audience{o.ClientID},
		Time:     time.Now().UTC(),
	}, time.Minute); err != nil {
		return errs.Wrap(http.StatusUnauthorized, err, "validatePayload: failed to validate oidc token payload")
	}

	// Validate azp if present
	if p.AuthorizedParty != "" && p.AuthorizedParty != o.ClientID {
		return errs.Unauthorized("validatePayload: failed to validate oidc token payload: invalid azp")
	}

	// Validate domains (case-insensitive)
	if p.Email != "" && len(o.Domains) > 0 && !p.IsAdmin(o.Admins) {
		email := sanitizeEmail(p.Email)
		var found bool
		for _, d := range o.Domains {
			if strings.HasSuffix(email, "@"+strings.ToLower(d)) {
				found = true
				break
			}
		}
		if !found {
			return errs.Unauthorized("validatePayload: failed to validate oidc token payload: email %q is not allowed", p.Email)
		}
	}

	// Filter by oidc group claim
	if len(o.Groups) > 0 {
		var found bool
		for _, group := range o.Groups {
			for _, g := range p.Groups {
				if g == group {
					found = true
					break
				}
			}
		}
		if !found {
			return errs.Unauthorized("validatePayload: oidc token payload validation failed: invalid group")
		}
	}

	return nil
}

// authorizeToken applies the most common provisioner authorization claims,
// leaving the rest to context specific methods.
func (o *OIDC) authorizeToken(token string) (*openIDPayload, error) {
	jwt, err := jose.ParseSigned(token)
	if err != nil {
		return nil, errs.Wrap(http.StatusUnauthorized, err,
			"oidc.AuthorizeToken; error parsing oidc token")
	}

	// Parse claims to get the kid
	var claims openIDPayload
	if err := jwt.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, errs.Wrap(http.StatusUnauthorized, err,
			"oidc.AuthorizeToken; error parsing oidc token claims")
	}

	found := false
	kid := jwt.Headers[0].KeyID
	keys := o.keyStore.Get(kid)
	for _, key := range keys {
		if err := jwt.Claims(key, &claims); err == nil {
			found = true
			break
		}
	}
	if !found {
		return nil, errs.Unauthorized("oidc.AuthorizeToken; cannot validate oidc token")
	}

	if err := o.ValidatePayload(claims); err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "oidc.AuthorizeToken")
	}

	return &claims, nil
}

// AuthorizeRevoke returns an error if the provisioner does not have rights to
// revoke the certificate with serial number in the `sub` property.
// Only tokens generated by an admin have the right to revoke a certificate.
func (o *OIDC) AuthorizeRevoke(_ context.Context, token string) error {
	claims, err := o.authorizeToken(token)
	if err != nil {
		return errs.Wrap(http.StatusInternalServerError, err, "oidc.AuthorizeRevoke")
	}

	// Only admins can revoke certificates.
	if claims.IsAdmin(o.Admins) {
		return nil
	}

	return errs.Unauthorized("oidc.AuthorizeRevoke; cannot revoke with non-admin oidc token")
}

// AuthorizeSign validates the given token.
func (o *OIDC) AuthorizeSign(_ context.Context, token string) ([]SignOption, error) {
	claims, err := o.authorizeToken(token)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "oidc.AuthorizeSign")
	}

	// Certificate templates
	sans := []string{}
	if claims.Email != "" {
		sans = append(sans, claims.Email)
	}

	// Add uri SAN with iss#sub if issuer is a URL with schema.
	//
	// According to https://openid.net/specs/openid-connect-core-1_0.html the
	// iss value is a case sensitive URL using the https scheme that contains
	// scheme, host, and optionally, port number and path components and no
	// query or fragment components.
	if iss, err := url.Parse(claims.Issuer); err == nil && iss.Scheme != "" {
		iss.Fragment = claims.Subject
		sans = append(sans, iss.String())
	}

	data := x509util.CreateTemplateData(claims.Subject, sans)
	if v, err := unsafeParseSigned(token); err == nil {
		data.SetToken(v)
	}

	// Use the default template unless no-templates are configured and email is
	// an admin, in that case we will use the CR template.
	defaultTemplate := x509util.DefaultLeafTemplate
	if !o.Options.GetX509Options().HasTemplate() && claims.IsAdmin(o.Admins) {
		defaultTemplate = x509util.DefaultAdminLeafTemplate
	}

	templateOptions, err := CustomTemplateOptions(o.Options, data, defaultTemplate)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "oidc.AuthorizeSign")
	}

	return []SignOption{
		o,
		templateOptions,
		// modifiers / withOptions
		newProvisionerExtensionOption(TypeOIDC, o.Name, o.ClientID).WithControllerOptions(o.ctl),
		profileDefaultDuration(o.ctl.Claimer.DefaultTLSCertDuration()),
		// validators
		defaultPublicKeyValidator{},
		newValidityValidator(o.ctl.Claimer.MinTLSCertDuration(), o.ctl.Claimer.MaxTLSCertDuration()),
		newX509NamePolicyValidator(o.ctl.getPolicy().getX509()),
		// webhooks
		o.ctl.newWebhookController(data, linkedca.Webhook_X509),
	}, nil
}

// AuthorizeRenew returns an error if the renewal is disabled.
// NOTE: This method does not actually validate the certificate or check it's
// revocation status. Just confirms that the provisioner that created the
// certificate was configured to allow renewals.
func (o *OIDC) AuthorizeRenew(ctx context.Context, cert *x509.Certificate) error {
	return o.ctl.AuthorizeRenew(ctx, cert)
}

// AuthorizeSSHSign returns the list of SignOption for a SignSSH request.
func (o *OIDC) AuthorizeSSHSign(ctx context.Context, token string) ([]SignOption, error) {
	if !o.ctl.Claimer.IsSSHCAEnabled() {
		return nil, errs.Unauthorized("oidc.AuthorizeSSHSign; sshCA is disabled for oidc provisioner '%s'", o.GetName())
	}
	claims, err := o.authorizeToken(token)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "oidc.AuthorizeSSHSign")
	}

	if claims.Subject == "" {
		return nil, errs.Unauthorized("oidc.AuthorizeSSHSign: failed to validate oidc token payload: subject not found")
	}

	var data sshutil.TemplateData
	if claims.Email == "" {
		// If email is empty, use the Subject claim instead to create minimal
		// data for the template to use.
		data = sshutil.CreateTemplateData(sshutil.UserCert, claims.Subject, nil)
		if v, err := unsafeParseSigned(token); err == nil {
			data.SetToken(v)
		}
	} else {
		// Get the identity using either the default identityFunc or one injected
		// externally. Note that the PreferredUsername might be empty.
		// TBD: Would preferred_username present a safety issue here?
		iden, err := o.ctl.GetIdentity(ctx, claims.Email)
		if err != nil {
			return nil, errs.Wrap(http.StatusInternalServerError, err, "oidc.AuthorizeSSHSign")
		}

		// Certificate templates.
		data = sshutil.CreateTemplateData(sshutil.UserCert, claims.Email, iden.Usernames)
		if v, err := unsafeParseSigned(token); err == nil {
			data.SetToken(v)
		}
		// Add custom extensions added in the identity function.
		for k, v := range iden.Permissions.Extensions {
			data.AddExtension(k, v)
		}
		// Add custom critical options added in the identity function.
		for k, v := range iden.Permissions.CriticalOptions {
			data.AddCriticalOption(k, v)
		}
	}

	// Use the default template unless no-templates are configured and email is
	// an admin, in that case we will use the parameters in the request.
	isAdmin := claims.IsAdmin(o.Admins)
	defaultTemplate := sshutil.DefaultTemplate
	if isAdmin && !o.Options.GetSSHOptions().HasTemplate() {
		defaultTemplate = sshutil.DefaultAdminTemplate
	}

	templateOptions, err := CustomSSHTemplateOptions(o.Options, data, defaultTemplate)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "jwk.AuthorizeSign")
	}
	signOptions := []SignOption{templateOptions}

	// Admin users can use any principal, and can sign user and host certificates.
	// Non-admin users can only use principals returned by the identityFunc, and
	// can only sign user certificates.
	if isAdmin {
		signOptions = append(signOptions, &sshCertOptionsRequireValidator{
			CertType:   true,
			KeyID:      true,
			Principals: true,
		})
	} else {
		signOptions = append(signOptions, sshCertOptionsValidator(SignSSHOptions{
			CertType: SSHUserCert,
		}))
	}

	return append(signOptions,
		o,
		// Set the validity bounds if not set.
		&sshDefaultDuration{o.ctl.Claimer},
		// Validate public key
		&sshDefaultPublicKeyValidator{},
		// Validate the validity period.
		&sshCertValidityValidator{o.ctl.Claimer},
		// Require all the fields in the SSH certificate
		&sshCertDefaultValidator{},
		// Ensure that all principal names are allowed
		newSSHNamePolicyValidator(o.ctl.getPolicy().getSSHHost(), o.ctl.getPolicy().getSSHUser()),
		// Call webhooks
		o.ctl.newWebhookController(data, linkedca.Webhook_SSH),
	), nil
}

// AuthorizeSSHRevoke returns nil if the token is valid, false otherwise.
func (o *OIDC) AuthorizeSSHRevoke(_ context.Context, token string) error {
	claims, err := o.authorizeToken(token)
	if err != nil {
		return errs.Wrap(http.StatusInternalServerError, err, "oidc.AuthorizeSSHRevoke")
	}

	// Only admins can revoke certificates.
	if claims.IsAdmin(o.Admins) {
		return nil
	}

	return errs.Unauthorized("oidc.AuthorizeSSHRevoke; cannot revoke with non-admin oidc token")
}

func getAndDecode(uri string, v interface{}) error {
	resp, err := http.Get(uri) //nolint:gosec // openid-configuration uri
	if err != nil {
		return errors.Wrapf(err, "failed to connect to %s", uri)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		return errors.Wrapf(err, "error reading %s", uri)
	}
	return nil
}
