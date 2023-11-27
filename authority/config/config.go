package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/pkg/errors"

	kms "go.step.sm/crypto/kms/apiv1"
	"go.step.sm/linkedca"

	"github.com/smallstep/certificates/authority/policy"
	"github.com/smallstep/certificates/authority/provisioner"
	cas "github.com/smallstep/certificates/cas/apiv1"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/certificates/templates"
)

const (
	legacyAuthority = "step-certificate-authority"
)

var (
	// DefaultBackdate length of time to backdate certificates to avoid
	// clock skew validation issues.
	DefaultBackdate = time.Minute
	// DefaultDisableRenewal disables renewals per provisioner.
	DefaultDisableRenewal = false
	// DefaultAllowRenewalAfterExpiry allows renewals even if the certificate is
	// expired.
	DefaultAllowRenewalAfterExpiry = false
	// DefaultEnableSSHCA enable SSH CA features per provisioner or globally
	// for all provisioners.
	DefaultEnableSSHCA = false
	// DefaultDisableSmallstepExtensions is the default value for the
	// DisableSmallstepExtensions provisioner claim.
	DefaultDisableSmallstepExtensions = false
	// DefaultCRLCacheDuration is the default cache duration for the CRL.
	DefaultCRLCacheDuration = &provisioner.Duration{Duration: 24 * time.Hour}
	// DefaultCRLExpiredDuration is the default duration in which expired
	// certificates will remain in the CRL after expiration.
	DefaultCRLExpiredDuration = time.Hour
	// GlobalProvisionerClaims is the default duration that expired certificates
	// remain in the CRL after expiration.
	GlobalProvisionerClaims = provisioner.Claims{
		MinTLSDur:                  &provisioner.Duration{Duration: 5 * time.Minute}, // TLS certs
		MaxTLSDur:                  &provisioner.Duration{Duration: 24 * time.Hour},
		DefaultTLSDur:              &provisioner.Duration{Duration: 24 * time.Hour},
		MinUserSSHDur:              &provisioner.Duration{Duration: 5 * time.Minute}, // User SSH certs
		MaxUserSSHDur:              &provisioner.Duration{Duration: 24 * time.Hour},
		DefaultUserSSHDur:          &provisioner.Duration{Duration: 16 * time.Hour},
		MinHostSSHDur:              &provisioner.Duration{Duration: 5 * time.Minute}, // Host SSH certs
		MaxHostSSHDur:              &provisioner.Duration{Duration: 30 * 24 * time.Hour},
		DefaultHostSSHDur:          &provisioner.Duration{Duration: 30 * 24 * time.Hour},
		EnableSSHCA:                &DefaultEnableSSHCA,
		DisableRenewal:             &DefaultDisableRenewal,
		AllowRenewalAfterExpiry:    &DefaultAllowRenewalAfterExpiry,
		DisableSmallstepExtensions: &DefaultDisableSmallstepExtensions,
	}
)

// Config represents the CA configuration and it's mapped to a JSON object.
type Config struct {
	Root             multiString          `json:"root"`
	FederatedRoots   []string             `json:"federatedRoots"`
	IntermediateCert string               `json:"crt"`
	IntermediateKey  string               `json:"key"`
	Address          string               `json:"address"`
	InsecureAddress  string               `json:"insecureAddress"`
	DNSNames         []string             `json:"dnsNames"`
	KMS              *kms.Options         `json:"kms,omitempty"`
	SSH              *SSHConfig           `json:"ssh,omitempty"`
	Logger           json.RawMessage      `json:"logger,omitempty"`
	DB               *db.Config           `json:"db,omitempty"`
	Monitoring       json.RawMessage      `json:"monitoring,omitempty"`
	AuthorityConfig  *AuthConfig          `json:"authority,omitempty"`
	TLS              *TLSOptions          `json:"tls,omitempty"`
	Password         string               `json:"password,omitempty"`
	Templates        *templates.Templates `json:"templates,omitempty"`
	CommonName       string               `json:"commonName,omitempty"`
	CRL              *CRLConfig           `json:"crl,omitempty"`
	SkipValidation   bool                 `json:"-"`

	// Keeps record of the filename the Config is read from
	loadedFromFilepath string
}

// CRLConfig represents config options for CRL generation
type CRLConfig struct {
	Enabled          bool                  `json:"enabled"`
	GenerateOnRevoke bool                  `json:"generateOnRevoke,omitempty"`
	CacheDuration    *provisioner.Duration `json:"cacheDuration,omitempty"`
	RenewPeriod      *provisioner.Duration `json:"renewPeriod,omitempty"`
	IDPurl           string                `json:"idpURL,omitempty"`
}

// IsEnabled returns if the CRL is enabled.
func (c *CRLConfig) IsEnabled() bool {
	return c != nil && c.Enabled
}

// Validate validates the CRL configuration.
func (c *CRLConfig) Validate() error {
	if c == nil {
		return nil
	}

	if c.CacheDuration != nil && c.CacheDuration.Duration < 0 {
		return errors.New("crl.cacheDuration must be greater than or equal to 0")
	}

	if c.RenewPeriod != nil && c.RenewPeriod.Duration < 0 {
		return errors.New("crl.renewPeriod must be greater than or equal to 0")
	}

	if c.RenewPeriod != nil && c.CacheDuration != nil &&
		c.RenewPeriod.Duration > c.CacheDuration.Duration {
		return errors.New("crl.cacheDuration must be greater than or equal to crl.renewPeriod")
	}

	return nil
}

// TickerDuration the renewal ticker duration. This is set by renewPeriod, of it
// is not set is ~2/3 of cacheDuration.
func (c *CRLConfig) TickerDuration() time.Duration {
	if !c.IsEnabled() {
		return 0
	}

	if c.RenewPeriod != nil && c.RenewPeriod.Duration > 0 {
		return c.RenewPeriod.Duration
	}

	return (c.CacheDuration.Duration / 3) * 2
}

// ASN1DN contains ASN1.DN attributes that are used in Subject and Issuer
// x509 Certificate blocks.
type ASN1DN struct {
	Country            string `json:"country,omitempty"`
	Organization       string `json:"organization,omitempty"`
	OrganizationalUnit string `json:"organizationalUnit,omitempty"`
	Locality           string `json:"locality,omitempty"`
	Province           string `json:"province,omitempty"`
	StreetAddress      string `json:"streetAddress,omitempty"`
	SerialNumber       string `json:"serialNumber,omitempty"`
	CommonName         string `json:"commonName,omitempty"`
}

// AuthConfig represents the configuration options for the authority. An
// underlaying registration authority can also be configured using the
// cas.Options.
type AuthConfig struct {
	*cas.Options
	AuthorityID          string                `json:"authorityId,omitempty"`
	DeploymentType       string                `json:"deploymentType,omitempty"`
	Provisioners         provisioner.List      `json:"provisioners,omitempty"`
	Admins               []*linkedca.Admin     `json:"-"`
	Template             *ASN1DN               `json:"template,omitempty"`
	Claims               *provisioner.Claims   `json:"claims,omitempty"`
	Policy               *policy.Options       `json:"policy,omitempty"`
	DisableIssuedAtCheck bool                  `json:"disableIssuedAtCheck,omitempty"`
	Backdate             *provisioner.Duration `json:"backdate,omitempty"`
	EnableAdmin          bool                  `json:"enableAdmin,omitempty"`
	DisableGetSSHHosts   bool                  `json:"disableGetSSHHosts,omitempty"`
}

// init initializes the required fields in the AuthConfig if they are not
// provided.
func (c *AuthConfig) init() {
	if c.Provisioners == nil {
		c.Provisioners = provisioner.List{}
	}
	if c.Template == nil {
		c.Template = &ASN1DN{}
	}
	if c.Backdate == nil {
		c.Backdate = &provisioner.Duration{
			Duration: DefaultBackdate,
		}
	}
}

// Validate validates the authority configuration.
func (c *AuthConfig) Validate(provisioner.Audiences) error {
	if c == nil {
		return errors.New("authority cannot be undefined")
	}

	// Initialize required fields.
	c.init()

	// Check that only one K8sSA is enabled
	var k8sCount int
	for _, p := range c.Provisioners {
		if p.GetType() == provisioner.TypeK8sSA {
			k8sCount++
		}
	}
	if k8sCount > 1 {
		return errors.New("cannot have more than one kubernetes service account provisioner")
	}

	if c.Backdate.Duration < 0 {
		return errors.New("authority.backdate cannot be less than 0")
	}

	return nil
}

// LoadConfiguration parses the given filename in JSON format and returns the
// configuration struct.
func LoadConfiguration(filename string) (*Config, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, errors.Wrapf(err, "error opening %s", filename)
	}
	defer f.Close()

	var c Config
	if err := json.NewDecoder(f).Decode(&c); err != nil {
		return nil, errors.Wrapf(err, "error parsing %s", filename)
	}

	// store filename that was read to populate Config
	c.loadedFromFilepath = filename

	// initialize the Config
	c.Init()

	return &c, nil
}

// Init initializes the minimal configuration required to create an authority. This
// is mainly used on embedded authorities.
func (c *Config) Init() {
	if c.DNSNames == nil {
		c.DNSNames = []string{"localhost", "127.0.0.1", "::1"}
	}
	if c.TLS == nil {
		c.TLS = &DefaultTLSOptions
	}
	if c.AuthorityConfig == nil {
		c.AuthorityConfig = &AuthConfig{}
	}
	if c.CommonName == "" {
		c.CommonName = "Step Online CA"
	}
	if c.CRL != nil && c.CRL.Enabled && c.CRL.CacheDuration == nil {
		c.CRL.CacheDuration = DefaultCRLCacheDuration
	}
	c.AuthorityConfig.init()
}

// Save saves the configuration to the given filename.
func (c *Config) Save(filename string) error {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetIndent("", "\t")
	if err := enc.Encode(c); err != nil {
		return fmt.Errorf("error encoding configuration: %w", err)
	}
	if err := os.WriteFile(filename, b.Bytes(), 0600); err != nil {
		return fmt.Errorf("error writing %q: %w", filename, err)
	}
	return nil
}

// Commit saves the current configuration to the same
// file it was initially loaded from.
//
// TODO(hs): rename Save() to WriteTo() and replace this
// with Save()? Or is Commit clear enough.
func (c *Config) Commit() error {
	if !c.WasLoadedFromFile() {
		return errors.New("cannot commit configuration if not loaded from file")
	}
	return c.Save(c.loadedFromFilepath)
}

// WasLoadedFromFile returns whether or not the Config was
// loaded from a file.
func (c *Config) WasLoadedFromFile() bool {
	return c.loadedFromFilepath != ""
}

// Filepath returns the path to the file the Config was
// loaded from.
func (c *Config) Filepath() string {
	return c.loadedFromFilepath
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	switch {
	case c.SkipValidation:
		return nil
	case c.Address == "":
		return errors.New("address cannot be empty")
	case len(c.DNSNames) == 0:
		return errors.New("dnsNames cannot be empty")
	case c.AuthorityConfig == nil:
		return errors.New("authority cannot be nil")
	}

	// Options holds the RA/CAS configuration.
	ra := c.AuthorityConfig.Options
	// The default RA/CAS requires root, crt and key.
	if ra.Is(cas.SoftCAS) {
		switch {
		case c.Root.HasEmpties():
			return errors.New("root cannot be empty")
		case c.IntermediateCert == "":
			return errors.New("crt cannot be empty")
		case c.IntermediateKey == "":
			return errors.New("key cannot be empty")
		}
	}

	// Validate address (a port is required)
	if _, _, err := net.SplitHostPort(c.Address); err != nil {
		return errors.Errorf("invalid address %s", c.Address)
	}

	if c.TLS == nil {
		c.TLS = &DefaultTLSOptions
	} else {
		if len(c.TLS.CipherSuites) == 0 {
			c.TLS.CipherSuites = DefaultTLSOptions.CipherSuites
		}
		if c.TLS.MaxVersion == 0 {
			c.TLS.MaxVersion = DefaultTLSOptions.MaxVersion
		}
		if c.TLS.MinVersion == 0 {
			c.TLS.MinVersion = DefaultTLSOptions.MinVersion
		}
		if c.TLS.MinVersion > c.TLS.MaxVersion {
			return errors.New("tls minVersion cannot exceed tls maxVersion")
		}
		c.TLS.Renegotiation = c.TLS.Renegotiation || DefaultTLSOptions.Renegotiation
	}

	// Validate KMS options, nil is ok.
	if err := c.KMS.Validate(); err != nil {
		return err
	}

	// Validate RA/CAS options, nil is ok.
	if err := ra.Validate(); err != nil {
		return err
	}

	// Validate ssh: nil is ok
	if err := c.SSH.Validate(); err != nil {
		return err
	}

	// Validate templates: nil is ok
	if err := c.Templates.Validate(); err != nil {
		return err
	}

	// Validate crl config: nil is ok
	if err := c.CRL.Validate(); err != nil {
		return err
	}

	return c.AuthorityConfig.Validate(c.GetAudiences())
}

// GetAudiences returns the legacy and possible urls without the ports that will
// be used as the default provisioner audiences. The CA might have proxies in
// front so we cannot rely on the port.
func (c *Config) GetAudiences() provisioner.Audiences {
	audiences := provisioner.Audiences{
		Sign:      []string{legacyAuthority},
		Revoke:    []string{legacyAuthority},
		SSHSign:   []string{},
		SSHRevoke: []string{},
		SSHRenew:  []string{},
	}

	for _, name := range c.DNSNames {
		hostname := toHostname(name)
		audiences.Sign = append(audiences.Sign,
			fmt.Sprintf("https://%s/1.0/sign", hostname),
			fmt.Sprintf("https://%s/sign", hostname),
			fmt.Sprintf("https://%s/1.0/ssh/sign", hostname),
			fmt.Sprintf("https://%s/ssh/sign", hostname))
		audiences.Renew = append(audiences.Renew,
			fmt.Sprintf("https://%s/1.0/renew", hostname),
			fmt.Sprintf("https://%s/renew", hostname))
		audiences.Revoke = append(audiences.Revoke,
			fmt.Sprintf("https://%s/1.0/revoke", hostname),
			fmt.Sprintf("https://%s/revoke", hostname))
		audiences.SSHSign = append(audiences.SSHSign,
			fmt.Sprintf("https://%s/1.0/ssh/sign", hostname),
			fmt.Sprintf("https://%s/ssh/sign", hostname),
			fmt.Sprintf("https://%s/1.0/sign", hostname),
			fmt.Sprintf("https://%s/sign", hostname))
		audiences.SSHRevoke = append(audiences.SSHRevoke,
			fmt.Sprintf("https://%s/1.0/ssh/revoke", hostname),
			fmt.Sprintf("https://%s/ssh/revoke", hostname))
		audiences.SSHRenew = append(audiences.SSHRenew,
			fmt.Sprintf("https://%s/1.0/ssh/renew", hostname),
			fmt.Sprintf("https://%s/ssh/renew", hostname))
		audiences.SSHRekey = append(audiences.SSHRekey,
			fmt.Sprintf("https://%s/1.0/ssh/rekey", hostname),
			fmt.Sprintf("https://%s/ssh/rekey", hostname))
	}

	return audiences
}

// Audience returns the list of audiences for a given path.
func (c *Config) Audience(path string) []string {
	audiences := make([]string, len(c.DNSNames)+1)
	for i, name := range c.DNSNames {
		hostname := toHostname(name)
		audiences[i] = "https://" + hostname + path
	}
	// For backward compatibility
	audiences[len(c.DNSNames)] = path
	return audiences
}

func toHostname(name string) string {
	// ensure an IPv6 address is represented with square brackets when used as hostname
	if ip := net.ParseIP(name); ip != nil && ip.To4() == nil {
		name = "[" + name + "]"
	}
	return name
}
