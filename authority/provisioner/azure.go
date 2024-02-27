package provisioner

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/errors"

	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/sshutil"
	"go.step.sm/crypto/x509util"
	"go.step.sm/linkedca"

	"github.com/smallstep/certificates/errs"
	"github.com/smallstep/certificates/webhook"
)

// azureOIDCBaseURL is the base discovery url for Microsoft Azure tokens.
const azureOIDCBaseURL = "https://login.microsoftonline.com"

//nolint:gosec // azureIdentityTokenURL is the URL to get the identity token for an instance.
const azureIdentityTokenURL = "http://169.254.169.254/metadata/identity/oauth2/token"

const azureIdentityTokenAPIVersion = "2018-02-01"

// azureInstanceComputeURL is the URL to get the instance compute metadata.
const azureInstanceComputeURL = "http://169.254.169.254/metadata/instance/compute/azEnvironment"

// azureDefaultAudience is the default audience used.
const azureDefaultAudience = "https://management.azure.com/"

// azureXMSMirIDRegExp is the regular expression used to parse the xms_mirid claim.
// Using case insensitive as resourceGroups appears as resourcegroups.
var azureXMSMirIDRegExp = regexp.MustCompile(`(?i)^/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft.(Compute/virtualMachines|ManagedIdentity/userAssignedIdentities)/([^/]+)$`)

// azureEnvironments is the list of all Azure environments.
var azureEnvironments = map[string]string{
	"AzurePublicCloud":       "https://management.azure.com/",
	"AzureCloud":             "https://management.azure.com/",
	"AzureUSGovernmentCloud": "https://management.usgovcloudapi.net/",
	"AzureUSGovernment":      "https://management.usgovcloudapi.net/",
	"AzureChinaCloud":        "https://management.chinacloudapi.cn/",
	"AzureGermanCloud":       "https://management.microsoftazure.de/",
}

type azureConfig struct {
	oidcDiscoveryURL   string
	identityTokenURL   string
	instanceComputeURL string
}

func newAzureConfig(tenantID string) *azureConfig {
	return &azureConfig{
		oidcDiscoveryURL:   azureOIDCBaseURL + "/" + tenantID + "/.well-known/openid-configuration",
		identityTokenURL:   azureIdentityTokenURL,
		instanceComputeURL: azureInstanceComputeURL,
	}
}

type azureIdentityToken struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ClientID     string `json:"client_id"`
	ExpiresIn    int64  `json:"expires_in,string"`
	ExpiresOn    int64  `json:"expires_on,string"`
	ExtExpiresIn int64  `json:"ext_expires_in,string"`
	NotBefore    int64  `json:"not_before,string"`
	Resource     string `json:"resource"`
	TokenType    string `json:"token_type"`
}

type azurePayload struct {
	jose.Claims
	AppID            string `json:"appid"`
	AppIDAcr         string `json:"appidacr"`
	IdentityProvider string `json:"idp"`
	ObjectID         string `json:"oid"`
	TenantID         string `json:"tid"`
	Version          string `json:"ver"`
	XMSMirID         string `json:"xms_mirid"`
}

// Azure is the provisioner that supports identity tokens created from the
// Microsoft Azure Instance Metadata service.
//
// The default audience is "https://management.azure.com/".
//
// If DisableCustomSANs is true, only the internal DNS and IP will be added as a
// SAN. By default it will accept any SAN in the CSR.
//
// If DisableTrustOnFirstUse is true, multiple sign request for this provisioner
// with the same instance will be accepted. By default only the first request
// will be accepted.
//
// Microsoft Azure identity docs are available at
// https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/how-to-use-vm-token
// and https://docs.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service
type Azure struct {
	*base
	ID                     string   `json:"-"`
	Type                   string   `json:"type"`
	Name                   string   `json:"name"`
	TenantID               string   `json:"tenantID"`
	ResourceGroups         []string `json:"resourceGroups"`
	SubscriptionIDs        []string `json:"subscriptionIDs"`
	ObjectIDs              []string `json:"objectIDs"`
	Audience               string   `json:"audience,omitempty"`
	DisableCustomSANs      bool     `json:"disableCustomSANs"`
	DisableTrustOnFirstUse bool     `json:"disableTrustOnFirstUse"`
	Claims                 *Claims  `json:"claims,omitempty"`
	Options                *Options `json:"options,omitempty"`
	config                 *azureConfig
	oidcConfig             openIDConfiguration
	keyStore               *keyStore
	ctl                    *Controller
	environment            string
}

// GetID returns the provisioner unique identifier.
func (p *Azure) GetID() string {
	if p.ID != "" {
		return p.ID
	}
	return p.GetIDForToken()
}

// GetIDForToken returns an identifier that will be used to load the provisioner
// from a token.
func (p *Azure) GetIDForToken() string {
	return p.TenantID
}

// GetTokenID returns the identifier of the token. The default value for Azure
// the SHA256 of "xms_mirid", but if DisableTrustOnFirstUse is set to true, then
// it will be the token kid.
func (p *Azure) GetTokenID(token string) (string, error) {
	jwt, err := jose.ParseSigned(token)
	if err != nil {
		return "", errors.Wrap(err, "error parsing token")
	}

	// Get claims w/out verification. We need to look up the provisioner
	// key in order to verify the claims and we need the issuer from the claims
	// before we can look up the provisioner.
	var claims azurePayload
	if err = jwt.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return "", errors.Wrap(err, "error verifying claims")
	}

	// If TOFU is disabled then allow token re-use. Azure caches the token for
	// 24h and without allowing the re-use we cannot use it twice.
	if p.DisableTrustOnFirstUse {
		return "", ErrAllowTokenReuse
	}

	sum := sha256.Sum256([]byte(claims.XMSMirID))
	return strings.ToLower(hex.EncodeToString(sum[:])), nil
}

// GetName returns the name of the provisioner.
func (p *Azure) GetName() string {
	return p.Name
}

// GetType returns the type of provisioner.
func (p *Azure) GetType() Type {
	return TypeAzure
}

// GetEncryptedKey is not available in an Azure provisioner.
func (p *Azure) GetEncryptedKey() (kid, key string, ok bool) {
	return "", "", false
}

// GetIdentityToken retrieves from the metadata service the identity token and
// returns it.
func (p *Azure) GetIdentityToken(subject, caURL string) (string, error) {
	_, _ = subject, caURL // unused input

	// Initialize the config if this method is used from the cli.
	p.assertConfig()

	// default to AzurePublicCloud to keep existing behavior
	identityTokenResource := azureEnvironments["AzurePublicCloud"]

	var err error
	p.environment, err = p.getAzureEnvironment()
	if err != nil {
		return "", errors.Wrap(err, "error getting azure environment")
	}

	if resource, ok := azureEnvironments[p.environment]; ok {
		identityTokenResource = resource
	}

	req, err := http.NewRequest("GET", p.config.identityTokenURL, http.NoBody)
	if err != nil {
		return "", errors.Wrap(err, "error creating request")
	}
	req.Header.Set("Metadata", "true")

	query := req.URL.Query()
	query.Add("resource", identityTokenResource)
	query.Add("api-version", azureIdentityTokenAPIVersion)
	req.URL.RawQuery = query.Encode()

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "error getting identity token, are you in a Azure VM?")
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errors.Wrap(err, "error reading identity token response")
	}
	if resp.StatusCode >= 400 {
		return "", errors.Errorf("error getting identity token: status=%d, response=%s", resp.StatusCode, b)
	}

	var identityToken azureIdentityToken
	if err := json.Unmarshal(b, &identityToken); err != nil {
		return "", errors.Wrap(err, "error unmarshaling identity token response")
	}

	return identityToken.AccessToken, nil
}

// Init validates and initializes the Azure provisioner.
func (p *Azure) Init(config Config) (err error) {
	switch {
	case p.Type == "":
		return errors.New("provisioner type cannot be empty")
	case p.Name == "":
		return errors.New("provisioner name cannot be empty")
	case p.TenantID == "":
		return errors.New("provisioner tenantId cannot be empty")
	case p.Audience == "": // use default audience
		p.Audience = azureDefaultAudience
	}

	// Initialize config
	p.assertConfig()

	// Decode and validate openid-configuration endpoint
	if err = getAndDecode(p.config.oidcDiscoveryURL, &p.oidcConfig); err != nil {
		return
	}
	if err := p.oidcConfig.Validate(); err != nil {
		return errors.Wrapf(err, "error parsing %s", p.config.oidcDiscoveryURL)
	}
	// Get JWK key set
	if p.keyStore, err = newKeyStore(p.oidcConfig.JWKSetURI); err != nil {
		return
	}

	p.ctl, err = NewController(p, p.Claims, config, p.Options)
	return
}

// authorizeToken returns the claims, name, group, subscription, identityObjectID, error.
func (p *Azure) authorizeToken(token string) (*azurePayload, string, string, string, string, error) {
	jwt, err := jose.ParseSigned(token)
	if err != nil {
		return nil, "", "", "", "", errs.Wrap(http.StatusUnauthorized, err, "azure.authorizeToken; error parsing azure token")
	}
	if len(jwt.Headers) == 0 {
		return nil, "", "", "", "", errs.Unauthorized("azure.authorizeToken; azure token missing header")
	}

	var found bool
	var claims azurePayload
	keys := p.keyStore.Get(jwt.Headers[0].KeyID)
	for _, key := range keys {
		if err := jwt.Claims(key.Public(), &claims); err == nil {
			found = true
			break
		}
	}
	if !found {
		return nil, "", "", "", "", errs.Unauthorized("azure.authorizeToken; cannot validate azure token")
	}

	if err := claims.ValidateWithLeeway(jose.Expected{
		Audience: []string{p.Audience},
		Issuer:   p.oidcConfig.Issuer,
		Time:     time.Now(),
	}, 1*time.Minute); err != nil {
		return nil, "", "", "", "", errs.Wrap(http.StatusUnauthorized, err, "azure.authorizeToken; failed to validate azure token payload")
	}

	// Validate TenantID
	if claims.TenantID != p.TenantID {
		return nil, "", "", "", "", errs.Unauthorized("azure.authorizeToken; azure token validation failed - invalid tenant id claim (tid)")
	}

	re := azureXMSMirIDRegExp.FindStringSubmatch(claims.XMSMirID)
	if len(re) != 5 {
		return nil, "", "", "", "", errs.Unauthorized("azure.authorizeToken; error parsing xms_mirid claim - %s", claims.XMSMirID)
	}

	var subscription, group, name string
	identityObjectID := claims.ObjectID
	subscription, group, name = re[1], re[2], re[4]

	return &claims, name, group, subscription, identityObjectID, nil
}

// AuthorizeSign validates the given token and returns the sign options that
// will be used on certificate creation.
func (p *Azure) AuthorizeSign(ctx context.Context, token string) ([]SignOption, error) {
	_, name, group, subscription, identityObjectID, err := p.authorizeToken(token)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "azure.AuthorizeSign")
	}

	// Filter by resource group
	if len(p.ResourceGroups) > 0 {
		var found bool
		for _, g := range p.ResourceGroups {
			if g == group {
				found = true
				break
			}
		}
		if !found {
			return nil, errs.Unauthorized("azure.AuthorizeSign; azure token validation failed - invalid resource group")
		}
	}

	// Filter by subscription id
	if len(p.SubscriptionIDs) > 0 {
		var found bool
		for _, s := range p.SubscriptionIDs {
			if s == subscription {
				found = true
				break
			}
		}
		if !found {
			return nil, errs.Unauthorized("azure.AuthorizeSign; azure token validation failed - invalid subscription id")
		}
	}

	// Filter by Azure AD identity object id
	if len(p.ObjectIDs) > 0 {
		var found bool
		for _, i := range p.ObjectIDs {
			if i == identityObjectID {
				found = true
				break
			}
		}
		if !found {
			return nil, errs.Unauthorized("azure.AuthorizeSign; azure token validation failed - invalid identity object id")
		}
	}

	// Template options
	data := x509util.NewTemplateData()
	data.SetCommonName(name)
	if v, err := unsafeParseSigned(token); err == nil {
		data.SetToken(v)
	}

	// Enforce known common name and default DNS if configured.
	// By default we'll accept the CN and SANs in the CSR.
	// There's no way to trust them other than TOFU.
	var so []SignOption
	if p.DisableCustomSANs {
		// name will work only inside the virtual network
		so = append(so,
			commonNameValidator(name),
			dnsNamesValidator([]string{name}),
			ipAddressesValidator(nil),
			emailAddressesValidator(nil),
			newURIsValidator(ctx, nil),
		)

		// Enforce SANs in the template.
		data.SetSANs([]string{name})
	}

	templateOptions, err := CustomTemplateOptions(p.Options, data, x509util.DefaultIIDLeafTemplate)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "aws.AuthorizeSign")
	}

	return append(so,
		p,
		templateOptions,
		// modifiers / withOptions
		newProvisionerExtensionOption(TypeAzure, p.Name, p.TenantID).WithControllerOptions(p.ctl),
		profileDefaultDuration(p.ctl.Claimer.DefaultTLSCertDuration()),
		// validators
		defaultPublicKeyValidator{},
		newValidityValidator(p.ctl.Claimer.MinTLSCertDuration(), p.ctl.Claimer.MaxTLSCertDuration()),
		newX509NamePolicyValidator(p.ctl.getPolicy().getX509()),
		p.ctl.newWebhookController(
			data,
			linkedca.Webhook_X509,
			webhook.WithAuthorizationPrincipal(identityObjectID),
		),
	), nil
}

// AuthorizeRenew returns an error if the renewal is disabled.
// NOTE: This method does not actually validate the certificate or check it's
// revocation status. Just confirms that the provisioner that created the
// certificate was configured to allow renewals.
func (p *Azure) AuthorizeRenew(ctx context.Context, cert *x509.Certificate) error {
	return p.ctl.AuthorizeRenew(ctx, cert)
}

// AuthorizeSSHSign returns the list of SignOption for a SignSSH request.
func (p *Azure) AuthorizeSSHSign(_ context.Context, token string) ([]SignOption, error) {
	if !p.ctl.Claimer.IsSSHCAEnabled() {
		return nil, errs.Unauthorized("azure.AuthorizeSSHSign; sshCA is disabled for provisioner '%s'", p.GetName())
	}

	_, name, _, _, identityObjectID, err := p.authorizeToken(token)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "azure.AuthorizeSSHSign")
	}

	signOptions := []SignOption{}

	// Enforce host certificate.
	defaults := SignSSHOptions{
		CertType: SSHHostCert,
	}

	// Validated principals.
	principals := []string{name}

	// Only enforce known principals if disable custom sans is true.
	if p.DisableCustomSANs {
		defaults.Principals = principals
	} else {
		// Check that at least one principal is sent in the request.
		signOptions = append(signOptions, &sshCertOptionsRequireValidator{
			Principals: true,
		})
	}

	// Certificate templates.
	data := sshutil.CreateTemplateData(sshutil.HostCert, name, principals)
	if v, err := unsafeParseSigned(token); err == nil {
		data.SetToken(v)
	}

	templateOptions, err := CustomSSHTemplateOptions(p.Options, data, sshutil.DefaultIIDTemplate)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "azure.AuthorizeSSHSign")
	}
	signOptions = append(signOptions, templateOptions)

	return append(signOptions,
		p,
		// Validate user SignSSHOptions.
		sshCertOptionsValidator(defaults),
		// Set the validity bounds if not set.
		&sshDefaultDuration{p.ctl.Claimer},
		// Validate public key
		&sshDefaultPublicKeyValidator{},
		// Validate the validity period.
		&sshCertValidityValidator{p.ctl.Claimer},
		// Require all the fields in the SSH certificate
		&sshCertDefaultValidator{},
		// Ensure that all principal names are allowed
		newSSHNamePolicyValidator(p.ctl.getPolicy().getSSHHost(), nil),
		// Call webhooks
		p.ctl.newWebhookController(
			data,
			linkedca.Webhook_SSH,
			webhook.WithAuthorizationPrincipal(identityObjectID),
		),
	), nil
}

// assertConfig initializes the config if it has not been initialized
func (p *Azure) assertConfig() {
	if p.config == nil {
		p.config = newAzureConfig(p.TenantID)
	}
}

// getAzureEnvironment returns the Azure environment for the current instance
func (p *Azure) getAzureEnvironment() (string, error) {
	if p.environment != "" {
		return p.environment, nil
	}

	req, err := http.NewRequest("GET", p.config.instanceComputeURL, http.NoBody)
	if err != nil {
		return "", errors.Wrap(err, "error creating request")
	}
	req.Header.Add("Metadata", "True")

	query := req.URL.Query()
	query.Add("format", "text")
	query.Add("api-version", "2021-02-01")
	req.URL.RawQuery = query.Encode()

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "error getting azure instance environment, are you in a Azure VM?")
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errors.Wrap(err, "error reading azure environment response")
	}
	if resp.StatusCode >= 400 {
		return "", errors.Errorf("error getting azure environment: status=%d, response=%s", resp.StatusCode, b)
	}

	return string(b), nil
}
