package provisioner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

// gcpCertsURL is the url that serves Google OAuth2 public keys.
const gcpCertsURL = "https://www.googleapis.com/oauth2/v3/certs"

// gcpIdentityURL is the base url for the identity document in GCP.
const gcpIdentityURL = "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity"

// gcpPayload extends jwt.Claims with custom GCP attributes.
type gcpPayload struct {
	jose.Claims
	AuthorizedParty string           `json:"azp"`
	Email           string           `json:"email"`
	EmailVerified   bool             `json:"email_verified"`
	Google          gcpGooglePayload `json:"google"`
}

type gcpGooglePayload struct {
	ComputeEngine gcpComputeEnginePayload `json:"compute_engine"`
}

type gcpComputeEnginePayload struct {
	InstanceID                string            `json:"instance_id"`
	InstanceName              string            `json:"instance_name"`
	InstanceCreationTimestamp *jose.NumericDate `json:"instance_creation_timestamp"`
	ProjectID                 string            `json:"project_id"`
	ProjectNumber             int64             `json:"project_number"`
	Zone                      string            `json:"zone"`
	LicenseID                 []string          `json:"license_id"`
}

type gcpConfig struct {
	CertsURL    string
	IdentityURL string
}

func newGCPConfig() *gcpConfig {
	return &gcpConfig{
		CertsURL:    gcpCertsURL,
		IdentityURL: gcpIdentityURL,
	}
}

// GCP is the provisioner that supports identity tokens created by the Google
// Cloud Platform metadata API.
//
// If DisableCustomSANs is true, only the internal DNS and IP will be added as a
// SAN. By default it will accept any SAN in the CSR.
//
// If DisableTrustOnFirstUse is true, multiple sign request for this provisioner
// with the same instance will be accepted. By default only the first request
// will be accepted.
//
// If InstanceAge is set, only the instances with an instance_creation_timestamp
// within the given period will be accepted.
//
// Google Identity docs are available at
// https://cloud.google.com/compute/docs/instances/verifying-instance-identity
type GCP struct {
	*base
	ID                     string   `json:"-"`
	Type                   string   `json:"type"`
	Name                   string   `json:"name"`
	ServiceAccounts        []string `json:"serviceAccounts"`
	ProjectIDs             []string `json:"projectIDs"`
	DisableCustomSANs      bool     `json:"disableCustomSANs"`
	DisableTrustOnFirstUse bool     `json:"disableTrustOnFirstUse"`
	InstanceAge            Duration `json:"instanceAge,omitempty"`
	Claims                 *Claims  `json:"claims,omitempty"`
	Options                *Options `json:"options,omitempty"`
	config                 *gcpConfig
	keyStore               *keyStore
	ctl                    *Controller
}

// GetID returns the provisioner unique identifier. The name should uniquely
// identify any GCP provisioner.
func (p *GCP) GetID() string {
	if p.ID != "" {
		return p.ID
	}
	return p.GetIDForToken()
}

// GetIDForToken returns an identifier that will be used to load the provisioner
// from a token.
func (p *GCP) GetIDForToken() string {
	return "gcp/" + p.Name
}

// GetTokenID returns the identifier of the token. The default value for GCP the
// SHA256 of "provisioner_id.instance_id", but if DisableTrustOnFirstUse is set
// to true, then it will be the SHA256 of the token.
func (p *GCP) GetTokenID(token string) (string, error) {
	jwt, err := jose.ParseSigned(token)
	if err != nil {
		return "", errors.Wrap(err, "error parsing token")
	}

	// If TOFU is disabled create an ID for the token, so it cannot be reused.
	if p.DisableTrustOnFirstUse {
		sum := sha256.Sum256([]byte(token))
		return strings.ToLower(hex.EncodeToString(sum[:])), nil
	}

	// Get claims w/out verification.
	var claims gcpPayload
	if err = jwt.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return "", errors.Wrap(err, "error verifying claims")
	}

	// Create unique ID for Trust On First Use (TOFU). Only the first instance
	// per provisioner is allowed as we don't have a way to trust the given
	// sans.
	unique := fmt.Sprintf("%s.%s", p.GetIDForToken(), claims.Google.ComputeEngine.InstanceID)
	sum := sha256.Sum256([]byte(unique))
	return strings.ToLower(hex.EncodeToString(sum[:])), nil
}

// GetName returns the name of the provisioner.
func (p *GCP) GetName() string {
	return p.Name
}

// GetType returns the type of provisioner.
func (p *GCP) GetType() Type {
	return TypeGCP
}

// GetEncryptedKey is not available in a GCP provisioner.
func (p *GCP) GetEncryptedKey() (kid, key string, ok bool) {
	return "", "", false
}

// GetIdentityURL returns the url that generates the GCP token.
func (p *GCP) GetIdentityURL(audience string) string {
	// Initialize config if required
	p.assertConfig()

	q := url.Values{}
	q.Add("audience", audience)
	q.Add("format", "full")
	q.Add("licenses", "FALSE")
	return fmt.Sprintf("%s?%s", p.config.IdentityURL, q.Encode())
}

// GetIdentityToken does an HTTP request to the identity url.
func (p *GCP) GetIdentityToken(subject, caURL string) (string, error) {
	_ = subject // unused input

	audience, err := generateSignAudience(caURL, p.GetIDForToken())
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("GET", p.GetIdentityURL(audience), http.NoBody)
	if err != nil {
		return "", errors.Wrap(err, "error creating identity request")
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "error doing identity request, are you in a GCP VM?")
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errors.Wrap(err, "error on identity request")
	}
	if resp.StatusCode >= 400 {
		return "", errors.Errorf("error on identity request: status=%d, response=%s", resp.StatusCode, b)
	}
	return string(bytes.TrimSpace(b)), nil
}

// Init validates and initializes the GCP provisioner.
func (p *GCP) Init(config Config) (err error) {
	switch {
	case p.Type == "":
		return errors.New("provisioner type cannot be empty")
	case p.Name == "":
		return errors.New("provisioner name cannot be empty")
	case p.InstanceAge.Value() < 0:
		return errors.New("provisioner instanceAge cannot be negative")
	}

	// Initialize config
	p.assertConfig()

	// Initialize key store
	if p.keyStore, err = newKeyStore(p.config.CertsURL); err != nil {
		return
	}

	config.Audiences = config.Audiences.WithFragment(p.GetIDForToken())
	p.ctl, err = NewController(p, p.Claims, config, p.Options)
	return
}

// AuthorizeSign validates the given token and returns the sign options that
// will be used on certificate creation.
func (p *GCP) AuthorizeSign(ctx context.Context, token string) ([]SignOption, error) {
	claims, err := p.authorizeToken(token)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "gcp.AuthorizeSign")
	}

	ce := claims.Google.ComputeEngine

	// Template options
	data := x509util.NewTemplateData()
	data.SetCommonName(ce.InstanceName)
	if v, err := unsafeParseSigned(token); err == nil {
		data.SetToken(v)
	}

	// Enforce known common name and default DNS if configured.
	// By default we we'll accept the CN and SANs in the CSR.
	// There's no way to trust them other than TOFU.
	var so []SignOption
	if p.DisableCustomSANs {
		dnsName1 := fmt.Sprintf("%s.c.%s.internal", ce.InstanceName, ce.ProjectID)
		dnsName2 := fmt.Sprintf("%s.%s.c.%s.internal", ce.InstanceName, ce.Zone, ce.ProjectID)
		so = append(so,
			commonNameSliceValidator([]string{
				ce.InstanceName, ce.InstanceID, dnsName1, dnsName2,
			}),
			dnsNamesValidator([]string{
				dnsName1, dnsName2,
			}),
			ipAddressesValidator(nil),
			emailAddressesValidator(nil),
			newURIsValidator(ctx, nil),
		)

		// Template SANs
		data.SetSANs([]string{dnsName1, dnsName2})
	}

	templateOptions, err := CustomTemplateOptions(p.Options, data, x509util.DefaultIIDLeafTemplate)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "gcp.AuthorizeSign")
	}

	return append(so,
		p,
		templateOptions,
		// modifiers / withOptions
		newProvisionerExtensionOption(TypeGCP, p.Name, claims.Subject, "InstanceID", ce.InstanceID, "InstanceName", ce.InstanceName).WithControllerOptions(p.ctl),
		profileDefaultDuration(p.ctl.Claimer.DefaultTLSCertDuration()),
		// validators
		defaultPublicKeyValidator{},
		newValidityValidator(p.ctl.Claimer.MinTLSCertDuration(), p.ctl.Claimer.MaxTLSCertDuration()),
		newX509NamePolicyValidator(p.ctl.getPolicy().getX509()),
		p.ctl.newWebhookController(
			data,
			linkedca.Webhook_X509,
			webhook.WithAuthorizationPrincipal(ce.InstanceID),
		),
	), nil
}

// AuthorizeRenew returns an error if the renewal is disabled.
func (p *GCP) AuthorizeRenew(ctx context.Context, cert *x509.Certificate) error {
	return p.ctl.AuthorizeRenew(ctx, cert)
}

// assertConfig initializes the config if it has not been initialized.
func (p *GCP) assertConfig() {
	if p.config == nil {
		p.config = newGCPConfig()
	}
}

// authorizeToken performs common jwt authorization actions and returns the
// claims for case specific downstream parsing.
// e.g. a Sign request will auth/validate different fields than a Revoke request.
func (p *GCP) authorizeToken(token string) (*gcpPayload, error) {
	jwt, err := jose.ParseSigned(token)
	if err != nil {
		return nil, errs.Wrap(http.StatusUnauthorized, err, "gcp.authorizeToken; error parsing gcp token")
	}
	if len(jwt.Headers) == 0 {
		return nil, errs.Unauthorized("gcp.authorizeToken; error parsing gcp token - header is missing")
	}

	var found bool
	var claims gcpPayload
	kid := jwt.Headers[0].KeyID
	keys := p.keyStore.Get(kid)
	for _, key := range keys {
		if err := jwt.Claims(key.Public(), &claims); err == nil {
			found = true
			break
		}
	}
	if !found {
		return nil, errs.Unauthorized("gcp.authorizeToken; failed to validate gcp token payload - cannot find key for kid %s", kid)
	}

	// According to "rfc7519 JSON Web Token" acceptable skew should be no
	// more than a few minutes.
	now := time.Now().UTC()
	if err = claims.ValidateWithLeeway(jose.Expected{
		Issuer: "https://accounts.google.com",
		Time:   now,
	}, time.Minute); err != nil {
		return nil, errs.Wrap(http.StatusUnauthorized, err, "gcp.authorizeToken; invalid gcp token payload")
	}

	// validate audiences with the defaults
	if !matchesAudience(claims.Audience, p.ctl.Audiences.Sign) {
		return nil, errs.Unauthorized("gcp.authorizeToken; invalid gcp token - invalid audience claim (aud)")
	}

	// validate subject (service account)
	if len(p.ServiceAccounts) > 0 {
		var found bool
		for _, sa := range p.ServiceAccounts {
			if sa == claims.Subject || sa == claims.Email {
				found = true
				break
			}
		}
		if !found {
			return nil, errs.Unauthorized("gcp.authorizeToken; invalid gcp token - invalid subject claim")
		}
	}

	// validate projects
	if len(p.ProjectIDs) > 0 {
		var found bool
		for _, pi := range p.ProjectIDs {
			if pi == claims.Google.ComputeEngine.ProjectID {
				found = true
				break
			}
		}
		if !found {
			return nil, errs.Unauthorized("gcp.authorizeToken; invalid gcp token - invalid project id")
		}
	}

	// validate instance age
	if d := p.InstanceAge.Value(); d > 0 {
		if now.Sub(claims.Google.ComputeEngine.InstanceCreationTimestamp.Time()) > d {
			return nil, errs.Unauthorized("gcp.authorizeToken; token google.compute_engine.instance_creation_timestamp is too old")
		}
	}

	switch {
	case claims.Google.ComputeEngine.InstanceID == "":
		return nil, errs.Unauthorized("gcp.authorizeToken; gcp token google.compute_engine.instance_id cannot be empty")
	case claims.Google.ComputeEngine.InstanceName == "":
		return nil, errs.Unauthorized("gcp.authorizeToken; gcp token google.compute_engine.instance_name cannot be empty")
	case claims.Google.ComputeEngine.ProjectID == "":
		return nil, errs.Unauthorized("gcp.authorizeToken; gcp token google.compute_engine.project_id cannot be empty")
	case claims.Google.ComputeEngine.Zone == "":
		return nil, errs.Unauthorized("gcp.authorizeToken; gcp token google.compute_engine.zone cannot be empty")
	}

	return &claims, nil
}

// AuthorizeSSHSign returns the list of SignOption for a SignSSH request.
func (p *GCP) AuthorizeSSHSign(_ context.Context, token string) ([]SignOption, error) {
	if !p.ctl.Claimer.IsSSHCAEnabled() {
		return nil, errs.Unauthorized("gcp.AuthorizeSSHSign; sshCA is disabled for gcp provisioner '%s'", p.GetName())
	}
	claims, err := p.authorizeToken(token)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "gcp.AuthorizeSSHSign")
	}

	ce := claims.Google.ComputeEngine
	signOptions := []SignOption{}

	// Enforce host certificate.
	defaults := SignSSHOptions{
		CertType: SSHHostCert,
	}

	// Validated principals.
	principals := []string{
		fmt.Sprintf("%s.c.%s.internal", ce.InstanceName, ce.ProjectID),
		fmt.Sprintf("%s.%s.c.%s.internal", ce.InstanceName, ce.Zone, ce.ProjectID),
	}

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
	data := sshutil.CreateTemplateData(sshutil.HostCert, ce.InstanceName, principals)
	if v, err := unsafeParseSigned(token); err == nil {
		data.SetToken(v)
	}

	templateOptions, err := CustomSSHTemplateOptions(p.Options, data, sshutil.DefaultIIDTemplate)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "gcp.AuthorizeSSHSign")
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
			webhook.WithAuthorizationPrincipal(ce.InstanceID),
		),
	), nil
}
