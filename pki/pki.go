package pki

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/admin"
	admindb "github.com/smallstep/certificates/authority/admin/db/nosql"
	authconfig "github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/cas"
	"github.com/smallstep/certificates/cas/apiv1"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/nosql"
	"go.step.sm/cli-utils/config"
	"go.step.sm/cli-utils/errs"
	"go.step.sm/cli-utils/fileutil"
	"go.step.sm/cli-utils/ui"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/linkedca"
	"golang.org/x/crypto/ssh"
)

// DeploymentType defines witch type of deployment a user is initializing
type DeploymentType int

const (
	// StandaloneDeployment is a deployment where all the components like keys,
	// provisioners, admins, certificates and others are managed by the user.
	StandaloneDeployment DeploymentType = iota
	// LinkedDeployment is a deployment where the keys are managed by the user,
	// but provisioners, admins and the record of certificates are managed in
	// the cloud.
	LinkedDeployment
	// HostedDeployment is a deployment where all the components are managed in
	// the cloud by smallstep.com/certificate-manager.
	HostedDeployment
)

const (
	// ConfigPath is the directory name under the step path where the configuration
	// files will be stored.
	configPath = "config"
	// PublicPath is the directory name under the step path where the public keys
	// will be stored.
	publicPath = "certs"
	// PublicPath is the directory name under the step path where the private keys
	// will be stored.
	privatePath = "secrets"
	// DBPath is the directory name under the step path where the private keys
	// will be stored.
	dbPath = "db"
	// templatesPath is the directory to store templates
	templatesPath = "templates"
)

// GetDBPath returns the path where the file-system persistence is stored
// based on the STEPPATH environment variable.
func GetDBPath() string {
	return filepath.Join(config.StepPath(), dbPath)
}

// GetConfigPath returns the directory where the configuration files are stored
// based on the STEPPATH environment variable.
func GetConfigPath() string {
	return filepath.Join(config.StepPath(), configPath)
}

// GetPublicPath returns the directory where the public keys are stored based on
// the STEPPATH environment variable.
func GetPublicPath() string {
	return filepath.Join(config.StepPath(), publicPath)
}

// GetSecretsPath returns the directory where the private keys are stored based
// on the STEPPATH environment variable.
func GetSecretsPath() string {
	return filepath.Join(config.StepPath(), privatePath)
}

// GetRootCAPath returns the path where the root CA is stored based on the
// STEPPATH environment variable.
func GetRootCAPath() string {
	return filepath.Join(config.StepPath(), publicPath, "root_ca.crt")
}

// GetOTTKeyPath returns the path where the one-time token key is stored based
// on the STEPPATH environment variable.
func GetOTTKeyPath() string {
	return filepath.Join(config.StepPath(), privatePath, "ott_key")
}

// GetTemplatesPath returns the path where the templates are stored.
func GetTemplatesPath() string {
	return filepath.Join(config.StepPath(), templatesPath)
}

// GetProvisioners returns the map of provisioners on the given CA.
func GetProvisioners(caURL, rootFile string) (provisioner.List, error) {
	if len(rootFile) == 0 {
		rootFile = GetRootCAPath()
	}
	client, err := ca.NewClient(caURL, ca.WithRootFile(rootFile))
	if err != nil {
		return nil, err
	}
	cursor := ""
	provisioners := provisioner.List{}
	for {
		resp, err := client.Provisioners(ca.WithProvisionerCursor(cursor), ca.WithProvisionerLimit(100))
		if err != nil {
			return nil, err
		}
		provisioners = append(provisioners, resp.Provisioners...)
		if resp.NextCursor == "" {
			return provisioners, nil
		}
		cursor = resp.NextCursor
	}
}

// GetProvisionerKey returns the encrypted provisioner key with the for the
// given kid.
func GetProvisionerKey(caURL, rootFile, kid string) (string, error) {
	if len(rootFile) == 0 {
		rootFile = GetRootCAPath()
	}
	client, err := ca.NewClient(caURL, ca.WithRootFile(rootFile))
	if err != nil {
		return "", err
	}
	resp, err := client.ProvisionerKey(kid)
	if err != nil {
		return "", err
	}
	return resp.Key, nil
}

type options struct {
	address        string
	caURL          string
	dnsNames       []string
	provisioner    string
	enableACME     bool
	enableSSH      bool
	enableAdmin    bool
	noDB           bool
	deploymentType DeploymentType
}

// PKIOption is the type of a configuration option on the pki constructor.
type PKIOption func(o *options)

// WithAddress sets the listen address of step-ca.
func WithAddress(s string) PKIOption {
	return func(o *options) {
		o.address = s
	}
}

// WithCaUrl sets the default ca-url of step-ca.
func WithCaUrl(s string) PKIOption {
	return func(o *options) {
		o.caURL = s
	}
}

// WithDNSNames sets the SANs of step-ca.
func WithDNSNames(s []string) PKIOption {
	return func(o *options) {
		o.dnsNames = s
	}
}

// WithProvisioner defines the name of the default provisioner.
func WithProvisioner(s string) PKIOption {
	return func(o *options) {
		o.provisioner = s
	}
}

// WithACME enables acme provisioner in step-ca.
func WithACME() PKIOption {
	return func(o *options) {
		o.enableACME = true
	}
}

// WithSSH enables ssh in step-ca.
func WithSSH() PKIOption {
	return func(o *options) {
		o.enableSSH = true
	}
}

// WithAdmin enables the admin api in step-ca.
func WithAdmin() PKIOption {
	return func(o *options) {
		o.enableAdmin = true
	}
}

// WithNoDB disables the db in step-ca.
func WithNoDB() PKIOption {
	return func(o *options) {
		o.noDB = true
	}
}

// WithDeploymentType defines the deployment type of step-ca.
func WithDeploymentType(dt DeploymentType) PKIOption {
	return func(o *options) {
		o.deploymentType = dt
	}
}

// PKI represents the Public Key Infrastructure used by a certificate authority.
type PKI struct {
	casOptions                     apiv1.Options
	caService                      apiv1.CertificateAuthorityService
	caCreator                      apiv1.CertificateAuthorityCreator
	root, rootKey, rootFingerprint string
	intermediate, intermediateKey  string
	sshHostPubKey, sshHostKey      string
	sshUserPubKey, sshUserKey      string
	config, defaults               string
	ottPublicKey                   *jose.JSONWebKey
	ottPrivateKey                  *jose.JSONWebEncryption
	options                        *options
}

// New creates a new PKI configuration.
func New(o apiv1.Options, opts ...PKIOption) (*PKI, error) {
	caService, err := cas.New(context.Background(), o)
	if err != nil {
		return nil, err
	}

	var caCreator apiv1.CertificateAuthorityCreator
	if o.IsCreator {
		creator, ok := caService.(apiv1.CertificateAuthorityCreator)
		if !ok {
			return nil, errors.Errorf("cas type '%s' does not implements CertificateAuthorityCreator", o.Type)
		}
		caCreator = creator
	}

	public := GetPublicPath()
	private := GetSecretsPath()
	config := GetConfigPath()

	// Create directories
	dirs := []string{public, private, config, GetTemplatesPath()}
	for _, name := range dirs {
		if _, err := os.Stat(name); os.IsNotExist(err) {
			if err = os.MkdirAll(name, 0700); err != nil {
				return nil, errs.FileError(err, name)
			}
		}
	}

	// get absolute path for dir/name
	getPath := func(dir string, name string) (string, error) {
		s, err := filepath.Abs(filepath.Join(dir, name))
		return s, errors.Wrapf(err, "error getting absolute path for %s", name)
	}

	p := &PKI{
		casOptions: o,
		caCreator:  caCreator,
		caService:  caService,
		options: &options{
			provisioner: "step-cli",
			address:     "127.0.0.1:9000",
			dnsNames:    []string{"127.0.0.1"},
		},
	}
	for _, fn := range opts {
		fn(p.options)
	}

	if p.root, err = getPath(public, "root_ca.crt"); err != nil {
		return nil, err
	}
	if p.rootKey, err = getPath(private, "root_ca_key"); err != nil {
		return nil, err
	}
	if p.intermediate, err = getPath(public, "intermediate_ca.crt"); err != nil {
		return nil, err
	}
	if p.intermediateKey, err = getPath(private, "intermediate_ca_key"); err != nil {
		return nil, err
	}
	if p.sshHostPubKey, err = getPath(public, "ssh_host_ca_key.pub"); err != nil {
		return nil, err
	}
	if p.sshUserPubKey, err = getPath(public, "ssh_user_ca_key.pub"); err != nil {
		return nil, err
	}
	if p.sshHostKey, err = getPath(private, "ssh_host_ca_key"); err != nil {
		return nil, err
	}
	if p.sshUserKey, err = getPath(private, "ssh_user_ca_key"); err != nil {
		return nil, err
	}
	if len(config) > 0 {
		if p.config, err = getPath(config, "ca.json"); err != nil {
			return nil, err
		}
		if p.defaults, err = getPath(config, "defaults.json"); err != nil {
			return nil, err
		}
	}

	return p, nil
}

// GetCAConfigPath returns the path of the CA configuration file.
func (p *PKI) GetCAConfigPath() string {
	return p.config
}

// GetRootFingerprint returns the root fingerprint.
func (p *PKI) GetRootFingerprint() string {
	return p.rootFingerprint
}

// SetProvisioner sets the provisioner name of the OTT keys.
//
// Deprecated: this method is deprecated in favor of WithProvisioner.
func (p *PKI) SetProvisioner(s string) {
	p.options.provisioner = s
}

// SetAddress sets the listening address of the CA.
//
// Deprecated: this method is deprecated in favor of WithAddress.
func (p *PKI) SetAddress(s string) {
	p.options.address = s
}

// SetDNSNames sets the dns names of the CA.
//
// Deprecated: this method is deprecated in favor of WithDNSNames.
func (p *PKI) SetDNSNames(s []string) {
	p.options.dnsNames = s
}

// SetCAURL sets the ca-url to use in the defaults.json.
//
// Deprecated: this method is deprecated in favor of WithCaUrl.
func (p *PKI) SetCAURL(s string) {
	p.options.caURL = s
}

// GenerateKeyPairs generates the key pairs used by the certificate authority.
func (p *PKI) GenerateKeyPairs(pass []byte) error {
	var err error
	// Create OTT key pair, the user doesn't need to know about this.
	p.ottPublicKey, p.ottPrivateKey, err = jose.GenerateDefaultKeyPair(pass)
	if err != nil {
		return err
	}

	return nil
}

// GenerateRootCertificate generates a root certificate with the given name
// and using the default key type.
func (p *PKI) GenerateRootCertificate(name, org, resource string, pass []byte) (*apiv1.CreateCertificateAuthorityResponse, error) {
	resp, err := p.caCreator.CreateCertificateAuthority(&apiv1.CreateCertificateAuthorityRequest{
		Name:      resource + "-Root-CA",
		Type:      apiv1.RootCA,
		Lifetime:  10 * 365 * 24 * time.Hour,
		CreateKey: nil, // use default
		Template: &x509.Certificate{
			Subject: pkix.Name{
				CommonName:   name + " Root CA",
				Organization: []string{org},
			},
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
			MaxPathLen:            1,
			MaxPathLenZero:        false,
		},
	})
	if err != nil {
		return nil, err
	}

	// PrivateKey will only be set if we have access to it (SoftCAS).
	if err := p.WriteRootCertificate(resp.Certificate, resp.PrivateKey, pass); err != nil {
		return nil, err
	}

	return resp, nil
}

// GenerateIntermediateCertificate generates an intermediate certificate with
// the given name and using the default key type.
func (p *PKI) GenerateIntermediateCertificate(name, org, resource string, parent *apiv1.CreateCertificateAuthorityResponse, pass []byte) error {
	resp, err := p.caCreator.CreateCertificateAuthority(&apiv1.CreateCertificateAuthorityRequest{
		Name:      resource + "-Intermediate-CA",
		Type:      apiv1.IntermediateCA,
		Lifetime:  10 * 365 * 24 * time.Hour,
		CreateKey: nil, // use default
		Template: &x509.Certificate{
			Subject: pkix.Name{
				CommonName:   name + " Intermediate CA",
				Organization: []string{org},
			},
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
			MaxPathLen:            0,
			MaxPathLenZero:        true,
		},
		Parent: parent,
	})
	if err != nil {
		return err
	}

	p.casOptions.CertificateAuthority = resp.Name
	return p.WriteIntermediateCertificate(resp.Certificate, resp.PrivateKey, pass)
}

// WriteRootCertificate writes to disk the given certificate and key.
func (p *PKI) WriteRootCertificate(rootCrt *x509.Certificate, rootKey interface{}, pass []byte) error {
	if err := fileutil.WriteFile(p.root, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: rootCrt.Raw,
	}), 0600); err != nil {
		return err
	}

	if rootKey != nil {
		_, err := pemutil.Serialize(rootKey, pemutil.WithPassword(pass), pemutil.ToFile(p.rootKey, 0600))
		if err != nil {
			return err
		}
	}

	sum := sha256.Sum256(rootCrt.Raw)
	p.rootFingerprint = strings.ToLower(hex.EncodeToString(sum[:]))

	return nil
}

// WriteIntermediateCertificate writes to disk the given certificate and key.
func (p *PKI) WriteIntermediateCertificate(crt *x509.Certificate, key interface{}, pass []byte) error {
	if err := fileutil.WriteFile(p.intermediate, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: crt.Raw,
	}), 0600); err != nil {
		return err
	}
	if key != nil {
		_, err := pemutil.Serialize(key, pemutil.WithPassword(pass), pemutil.ToFile(p.intermediateKey, 0600))
		if err != nil {
			return err
		}
	}
	return nil
}

// CreateCertificateAuthorityResponse returns a
// CreateCertificateAuthorityResponse that can be used as a parent of a
// CreateCertificateAuthority request.
func (p *PKI) CreateCertificateAuthorityResponse(cert *x509.Certificate, key crypto.PrivateKey) *apiv1.CreateCertificateAuthorityResponse {
	signer, _ := key.(crypto.Signer)
	return &apiv1.CreateCertificateAuthorityResponse{
		Certificate: cert,
		PrivateKey:  key,
		Signer:      signer,
	}
}

// GetCertificateAuthority attempts to load the certificate authority from the
// RA.
func (p *PKI) GetCertificateAuthority() error {
	srv, ok := p.caService.(apiv1.CertificateAuthorityGetter)
	if !ok {
		return nil
	}

	resp, err := srv.GetCertificateAuthority(&apiv1.GetCertificateAuthorityRequest{
		Name: p.casOptions.CertificateAuthority,
	})
	if err != nil {
		return err
	}

	if err := p.WriteRootCertificate(resp.RootCertificate, nil, nil); err != nil {
		return err
	}

	// Issuer is in the RA
	p.intermediate = ""
	p.intermediateKey = ""

	return nil
}

// GenerateSSHSigningKeys generates and encrypts a private key used for signing
// SSH user certificates and a private key used for signing host certificates.
func (p *PKI) GenerateSSHSigningKeys(password []byte) error {
	var pubNames = []string{p.sshHostPubKey, p.sshUserPubKey}
	var privNames = []string{p.sshHostKey, p.sshUserKey}
	for i := 0; i < 2; i++ {
		pub, priv, err := keyutil.GenerateDefaultKeyPair()
		if err != nil {
			return err
		}
		if _, ok := priv.(crypto.Signer); !ok {
			return errors.Errorf("key of type %T is not a crypto.Signer", priv)
		}
		sshKey, err := ssh.NewPublicKey(pub)
		if err != nil {
			return errors.Wrapf(err, "error converting public key")
		}
		_, err = pemutil.Serialize(priv, pemutil.WithFilename(privNames[i]), pemutil.WithPassword(password))
		if err != nil {
			return err
		}
		if err = fileutil.WriteFile(pubNames[i], ssh.MarshalAuthorizedKey(sshKey), 0600); err != nil {
			return err
		}
	}
	p.options.enableSSH = true
	return nil
}

func (p *PKI) askFeedback() {
	ui.Println()
	ui.Printf("\033[1mFEEDBACK\033[0m %s %s\n",
		html.UnescapeString("&#"+strconv.Itoa(128525)+";"),
		html.UnescapeString("&#"+strconv.Itoa(127867)+";"))
	ui.Println("      The \033[1mstep\033[0m utility is not instrumented for usage statistics. It does not")
	ui.Println("      phone home. But your feedback is extremely valuable. Any information you")
	ui.Println("      can provide regarding how you’re using `step` helps. Please send us a")
	ui.Println("      sentence or two, good or bad: \033[1mfeedback@smallstep.com\033[0m or join")
	ui.Println("      \033[1mhttps://github.com/smallstep/certificates/discussions\033[0m and our Discord")
	ui.Println("      \033[1mhttps://bit.ly/step-discord\033[0m.")
}

// TellPKI outputs the locations of public and private keys generated
// generated for a new PKI. Generally this will consist of a root certificate
// and key and an intermediate certificate and key.
func (p *PKI) TellPKI() {
	p.tellPKI()
	p.askFeedback()
}

func (p *PKI) tellPKI() {
	ui.Println()
	if p.casOptions.Is(apiv1.SoftCAS) {
		ui.PrintSelected("Root certificate", p.root)
		ui.PrintSelected("Root private key", p.rootKey)
		ui.PrintSelected("Root fingerprint", p.rootFingerprint)
		ui.PrintSelected("Intermediate certificate", p.intermediate)
		ui.PrintSelected("Intermediate private key", p.intermediateKey)
	} else if p.rootFingerprint != "" {
		ui.PrintSelected("Root certificate", p.root)
		ui.PrintSelected("Root fingerprint", p.rootFingerprint)
	} else {
		ui.Printf(`{{ "%s" | red }} {{ "Root certificate:" | bold }} failed to retrieve it from RA`+"\n", ui.IconBad)
	}
	if p.options.enableSSH {
		ui.PrintSelected("SSH user root certificate", p.sshUserPubKey)
		ui.PrintSelected("SSH user root private key", p.sshUserKey)
		ui.PrintSelected("SSH host root certificate", p.sshHostPubKey)
		ui.PrintSelected("SSH host root private key", p.sshHostKey)
	}
}

type caDefaults struct {
	CAUrl       string `json:"ca-url"`
	CAConfig    string `json:"ca-config"`
	Fingerprint string `json:"fingerprint"`
	Root        string `json:"root"`
}

// Option is the type for modifiers over the auth config object.
type Option func(c *authconfig.Config) error

// WithDefaultDB is a configuration modifier that adds a default DB stanza to
// the authority config.
//
// Deprecated: this method is deprecated because this is the default behavior.
func WithDefaultDB() Option {
	return func(c *authconfig.Config) error {
		c.DB = &db.Config{
			Type:       "badger",
			DataSource: GetDBPath(),
		}
		return nil
	}
}

// WithoutDB is a configuration modifier that adds a default DB stanza to
// the authority config.
//
// De[recated: this method is deprecated in favor or WithNoDB.
func WithoutDB() Option {
	return func(c *authconfig.Config) error {
		c.DB = nil
		return nil
	}
}

// GenerateConfig returns the step certificates configuration.
func (p *PKI) GenerateConfig(opt ...Option) (*authconfig.Config, error) {
	var authorityOptions *apiv1.Options
	if !p.casOptions.Is(apiv1.SoftCAS) {
		authorityOptions = &p.casOptions
	}

	config := &authconfig.Config{
		Root:             []string{p.root},
		FederatedRoots:   []string{},
		IntermediateCert: p.intermediate,
		IntermediateKey:  p.intermediateKey,
		Address:          p.options.address,
		DNSNames:         p.options.dnsNames,
		Logger:           []byte(`{"format": "text"}`),
		DB: &db.Config{
			Type:       "badger",
			DataSource: GetDBPath(),
		},
		AuthorityConfig: &authconfig.AuthConfig{
			Options:              authorityOptions,
			DisableIssuedAtCheck: false,
			EnableAdmin:          false,
		},
		TLS:       &authconfig.DefaultTLSOptions,
		Templates: p.getTemplates(),
	}

	// On standalone deployments add the provisioners to either the ca.json or
	// the database.
	var provisioners []provisioner.Interface
	if p.options.deploymentType == StandaloneDeployment {
		key, err := p.ottPrivateKey.CompactSerialize()
		if err != nil {
			return nil, errors.Wrap(err, "error serializing private key")
		}

		prov := &provisioner.JWK{
			Name:         p.options.provisioner,
			Type:         "JWK",
			Key:          p.ottPublicKey,
			EncryptedKey: key,
		}
		provisioners = append(provisioners, prov)

		// Add default ACME provisioner if enabled
		if p.options.enableACME {
			provisioners = append(provisioners, &provisioner.ACME{
				Type: "ACME",
				Name: "acme",
			})
		}

		if p.options.enableSSH {
			enableSSHCA := true
			config.SSH = &authconfig.SSHConfig{
				HostKey: p.sshHostKey,
				UserKey: p.sshUserKey,
			}
			// Enable SSH authorization for default JWK provisioner
			prov.Claims = &provisioner.Claims{
				EnableSSHCA: &enableSSHCA,
			}

			// Add default SSHPOP provisioner
			provisioners = append(provisioners, &provisioner.SSHPOP{
				Type: "SSHPOP",
				Name: "sshpop",
				Claims: &provisioner.Claims{
					EnableSSHCA: &enableSSHCA,
				},
			})
		}
	}

	// Apply configuration modifiers
	for _, o := range opt {
		if err := o(config); err != nil {
			return nil, err
		}
	}

	// Set authority.enableAdmin to true
	if p.options.enableAdmin {
		config.AuthorityConfig.EnableAdmin = true
	}

	if p.options.deploymentType == StandaloneDeployment {
		if !config.AuthorityConfig.EnableAdmin {
			config.AuthorityConfig.Provisioners = provisioners
		} else {
			db, err := db.New(config.DB)
			if err != nil {
				return nil, err
			}
			adminDB, err := admindb.New(db.(nosql.DB), admin.DefaultAuthorityID)
			if err != nil {
				return nil, err
			}
			// Add all the provisioners to the db.
			var adminID string
			for i, p := range provisioners {
				prov, err := authority.ProvisionerToLinkedca(p)
				if err != nil {
					return nil, err
				}
				if err := adminDB.CreateProvisioner(context.Background(), prov); err != nil {
					return nil, err
				}
				if i == 0 {
					adminID = prov.Id
				}
			}
			// Add the first provisioner as an admin.
			if err := adminDB.CreateAdmin(context.Background(), &linkedca.Admin{
				AuthorityId:   admin.DefaultAuthorityID,
				Subject:       "step",
				Type:          linkedca.Admin_SUPER_ADMIN,
				ProvisionerId: adminID,
			}); err != nil {
				return nil, err
			}
		}
	}

	return config, nil
}

// Save stores the pki on a json file that will be used as the certificate
// authority configuration.
func (p *PKI) Save(opt ...Option) error {
	p.tellPKI()

	// Generate and write ca.json
	config, err := p.GenerateConfig(opt...)
	if err != nil {
		return err
	}

	b, err := json.MarshalIndent(config, "", "\t")
	if err != nil {
		return errors.Wrapf(err, "error marshaling %s", p.config)
	}
	if err = fileutil.WriteFile(p.config, b, 0644); err != nil {
		return errs.FileError(err, p.config)
	}

	// Generate the CA URL.
	if p.options.caURL == "" {
		p.options.caURL = p.options.dnsNames[0]
		_, port, err := net.SplitHostPort(p.options.address)
		if err != nil {
			return errors.Wrapf(err, "error parsing %s", p.options.address)
		}
		if port == "443" {
			p.options.caURL = fmt.Sprintf("https://%s", p.options.caURL)
		} else {
			p.options.caURL = fmt.Sprintf("https://%s:%s", p.options.caURL, port)
		}
	}

	// Generate and write defaults.json
	defaults := &caDefaults{
		Root:        p.root,
		CAConfig:    p.config,
		CAUrl:       p.options.caURL,
		Fingerprint: p.rootFingerprint,
	}
	b, err = json.MarshalIndent(defaults, "", "\t")
	if err != nil {
		return errors.Wrapf(err, "error marshaling %s", p.defaults)
	}
	if err = fileutil.WriteFile(p.defaults, b, 0644); err != nil {
		return errs.FileError(err, p.defaults)
	}

	// Generate and write templates
	if err := generateTemplates(config.Templates); err != nil {
		return err
	}

	if config.DB != nil {
		ui.PrintSelected("Database folder", config.DB.DataSource)
	}
	if config.Templates != nil {
		ui.PrintSelected("Templates folder", GetTemplatesPath())
	}

	ui.PrintSelected("Default configuration", p.defaults)
	ui.PrintSelected("Certificate Authority configuration", p.config)
	ui.Println()
	if p.casOptions.Is(apiv1.SoftCAS) {
		ui.Println("Your PKI is ready to go. To generate certificates for individual services see 'step help ca'.")
	} else {
		ui.Println("Your registration authority is ready to go. To generate certificates for individual services see 'step help ca'.")
	}

	p.askFeedback()

	return nil
}
