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
	"net"
	"os"
	"path/filepath"
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
	"go.step.sm/cli-utils/errs"
	"go.step.sm/cli-utils/fileutil"
	"go.step.sm/cli-utils/step"
	"go.step.sm/cli-utils/ui"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/kms"
	kmsapi "go.step.sm/crypto/kms/apiv1"
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

// String returns the string version of the deployment type.
func (d DeploymentType) String() string {
	switch d {
	case StandaloneDeployment:
		return "standalone"
	case LinkedDeployment:
		return "linked"
	case HostedDeployment:
		return "hosted"
	default:
		return "unknown"
	}
}

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
// based on the $(step path).
func GetDBPath() string {
	return filepath.Join(step.Path(), dbPath)
}

// GetConfigPath returns the directory where the configuration files are stored
// based on the $(step path).
func GetConfigPath() string {
	return filepath.Join(step.Path(), configPath)
}

// GetProfileConfigPath returns the directory where the profile configuration
// files are stored based on the $(step path).
func GetProfileConfigPath() string {
	return filepath.Join(step.ProfilePath(), configPath)
}

// GetPublicPath returns the directory where the public keys are stored based on
// the $(step path).
func GetPublicPath() string {
	return filepath.Join(step.Path(), publicPath)
}

// GetSecretsPath returns the directory where the private keys are stored based
// on the $(step path).
func GetSecretsPath() string {
	return filepath.Join(step.Path(), privatePath)
}

// GetRootCAPath returns the path where the root CA is stored based on the
// $(step path).
func GetRootCAPath() string {
	return filepath.Join(step.Path(), publicPath, "root_ca.crt")
}

// GetOTTKeyPath returns the path where the one-time token key is stored based
// on the $(step path).
func GetOTTKeyPath() string {
	return filepath.Join(step.Path(), privatePath, "ott_key")
}

// GetTemplatesPath returns the path where the templates are stored.
func GetTemplatesPath() string {
	return filepath.Join(step.Path(), templatesPath)
}

// GetProvisioners returns the map of provisioners on the given CA.
func GetProvisioners(caURL, rootFile string) (provisioner.List, error) {
	if rootFile == "" {
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
	if rootFile == "" {
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
	provisioner        string
	superAdminSubject  string
	pkiOnly            bool
	enableACME         bool
	enableSSH          bool
	enableAdmin        bool
	noDB               bool
	isHelm             bool
	deploymentType     DeploymentType
	rootKeyURI         string
	intermediateKeyURI string
	hostKeyURI         string
	userKeyURI         string
}

// Option is the type of a configuration option on the pki constructor.
type Option func(p *PKI)

// WithAddress sets the listen address of step-ca.
func WithAddress(s string) Option {
	return func(p *PKI) {
		p.Address = s
	}
}

// WithCaURL sets the default ca-url of step-ca.
func WithCaURL(s string) Option {
	return func(p *PKI) {
		p.Defaults.CaUrl = s
	}
}

// WithDNSNames sets the SANs of step-ca.
func WithDNSNames(s []string) Option {
	return func(p *PKI) {
		p.DnsNames = s
	}
}

// WithProvisioner defines the name of the default provisioner.
func WithProvisioner(s string) Option {
	return func(p *PKI) {
		p.options.provisioner = s
	}
}

// WithSuperAdminSubject defines the subject of the first
// super admin for use with the Admin API. The admin will belong
// to the first JWK provisioner.
func WithSuperAdminSubject(s string) Option {
	return func(p *PKI) {
		p.options.superAdminSubject = s
	}
}

// WithPKIOnly will only generate the PKI without the step-ca config files.
func WithPKIOnly() Option {
	return func(p *PKI) {
		p.options.pkiOnly = true
	}
}

// WithACME enables acme provisioner in step-ca.
func WithACME() Option {
	return func(p *PKI) {
		p.options.enableACME = true
	}
}

// WithSSH enables ssh in step-ca.
func WithSSH() Option {
	return func(p *PKI) {
		p.options.enableSSH = true
	}
}

// WithAdmin enables the admin api in step-ca.
func WithAdmin() Option {
	return func(p *PKI) {
		p.options.enableAdmin = true
	}
}

// WithNoDB disables the db in step-ca.
func WithNoDB() Option {
	return func(p *PKI) {
		p.options.noDB = true
	}
}

// WithHelm configures the pki to create a helm values.yaml.
func WithHelm() Option {
	return func(p *PKI) {
		p.options.isHelm = true
	}
}

// WithDeploymentType defines the deployment type of step-ca.
func WithDeploymentType(dt DeploymentType) Option {
	return func(p *PKI) {
		p.options.deploymentType = dt
	}
}

// WithKMS enables the kms with the given name.
func WithKMS(name string) Option {
	return func(p *PKI) {
		typ := linkedca.KMS_Type_value[strings.ToUpper(name)]
		p.Configuration.Kms = &linkedca.KMS{
			Type: linkedca.KMS_Type(typ),
		}
	}
}

// WithKeyURIs defines the key uris for X.509 and SSH keys.
func WithKeyURIs(rootKey, intermediateKey, hostKey, userKey string) Option {
	return func(p *PKI) {
		p.options.rootKeyURI = rootKey
		p.options.intermediateKeyURI = intermediateKey
		p.options.hostKeyURI = hostKey
		p.options.userKeyURI = userKey
	}
}

// PKI represents the Public Key Infrastructure used by a certificate authority.
type PKI struct {
	linkedca.Configuration
	Defaults        linkedca.Defaults
	casOptions      apiv1.Options
	caService       apiv1.CertificateAuthorityService
	caCreator       apiv1.CertificateAuthorityCreator
	keyManager      kmsapi.KeyManager
	config          string
	defaults        string
	profileDefaults string
	ottPublicKey    *jose.JSONWebKey
	ottPrivateKey   *jose.JSONWebEncryption
	options         *options
}

// New creates a new PKI configuration.
func New(o apiv1.Options, opts ...Option) (*PKI, error) {
	// TODO(hs): invoking `New` with a context active will use values from
	// that CA context while generating the context. Thay may or may not
	// be fully expected and/or what we want. Check that.
	currentCtx := step.Contexts().GetCurrent()
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

	// get absolute path for dir/name
	getPath := func(dir string, name string) (string, error) {
		s, err := filepath.Abs(filepath.Join(dir, name))
		return s, errors.Wrapf(err, "error getting absolute path for %s", name)
	}

	p := &PKI{
		Configuration: linkedca.Configuration{
			Address:   "127.0.0.1:9000",
			DnsNames:  []string{"127.0.0.1"},
			Ssh:       &linkedca.SSH{},
			Authority: &linkedca.Authority{},
			Files:     make(map[string][]byte),
		},
		casOptions: o,
		caService:  caService,
		caCreator:  caCreator,
		keyManager: o.KeyManager,
		options: &options{
			provisioner: "step-cli",
		},
	}
	for _, fn := range opts {
		fn(p)
	}

	// Use default key manager
	if p.keyManager == nil {
		p.keyManager = kms.Default
	}

	// Use /home/step as the step path in helm configurations.
	// Use the current step path when creating pki in files.
	var public, private, cfg string
	if p.options.isHelm {
		public = "/home/step/certs"
		private = "/home/step/secrets"
		cfg = "/home/step/config"
	} else {
		public = GetPublicPath()
		private = GetSecretsPath()
		cfg = GetConfigPath()
		// Create directories
		dirs := []string{public, private, cfg, GetTemplatesPath()}
		if currentCtx != nil {
			dirs = append(dirs, GetProfileConfigPath())
		}
		for _, name := range dirs {
			if _, err := os.Stat(name); os.IsNotExist(err) {
				if err = os.MkdirAll(name, 0700); err != nil {
					return nil, errs.FileError(err, name)
				}
			}
		}
	}

	if p.Defaults.CaUrl == "" {
		p.Defaults.CaUrl = p.DnsNames[0]
		_, port, err := net.SplitHostPort(p.Address)
		if err != nil {
			return nil, errors.Wrapf(err, "error parsing %s", p.Address)
		}
		// On k8s we usually access through a service, and this is configured on
		// port 443 by default.
		if port == "443" || p.options.isHelm {
			p.Defaults.CaUrl = fmt.Sprintf("https://%s", p.Defaults.CaUrl)
		} else {
			p.Defaults.CaUrl = fmt.Sprintf("https://%s", net.JoinHostPort(p.Defaults.CaUrl, port))
		}
	}

	root, err := getPath(public, "root_ca.crt")
	if err != nil {
		return nil, err
	}
	rootKey, err := getPath(private, "root_ca_key")
	if err != nil {
		return nil, err
	}
	p.Root = []string{root}
	p.RootKey = []string{rootKey}
	p.Defaults.Root = root

	if p.Intermediate, err = getPath(public, "intermediate_ca.crt"); err != nil {
		return nil, err
	}
	if p.IntermediateKey, err = getPath(private, "intermediate_ca_key"); err != nil {
		return nil, err
	}
	if p.Ssh.HostPublicKey, err = getPath(public, "ssh_host_ca_key.pub"); err != nil {
		return nil, err
	}
	if p.Ssh.UserPublicKey, err = getPath(public, "ssh_user_ca_key.pub"); err != nil {
		return nil, err
	}
	if p.Ssh.HostKey, err = getPath(private, "ssh_host_ca_key"); err != nil {
		return nil, err
	}
	if p.Ssh.UserKey, err = getPath(private, "ssh_user_ca_key"); err != nil {
		return nil, err
	}
	if p.defaults, err = getPath(cfg, "defaults.json"); err != nil {
		return nil, err
	}
	if currentCtx != nil {
		p.profileDefaults = currentCtx.ProfileDefaultsFile()
	}

	if p.config, err = getPath(cfg, "ca.json"); err != nil {
		return nil, err
	}
	p.Defaults.CaConfig = p.config

	return p, nil
}

// GetCAConfigPath returns the path of the CA configuration file.
func (p *PKI) GetCAConfigPath() string {
	return p.config
}

// GetRootFingerprint returns the root fingerprint.
func (p *PKI) GetRootFingerprint() string {
	return p.Defaults.Fingerprint
}

// GenerateKeyPairs generates the key pairs used by the certificate authority.
func (p *PKI) GenerateKeyPairs(pass []byte) error {
	var err error
	// Create OTT key pair, the user doesn't need to know about this.
	p.ottPublicKey, p.ottPrivateKey, err = jose.GenerateDefaultKeyPair(pass)
	if err != nil {
		return err
	}

	var claims *linkedca.Claims
	if p.options.enableSSH {
		claims = &linkedca.Claims{
			Ssh: &linkedca.SSHClaims{
				Enabled: true,
			},
		}
	}

	// Add JWK provisioner to the configuration.
	publicKey, err := json.Marshal(p.ottPublicKey)
	if err != nil {
		return errors.Wrap(err, "error marshaling public key")
	}
	encryptedKey, err := p.ottPrivateKey.CompactSerialize()
	if err != nil {
		return errors.Wrap(err, "error serializing private key")
	}
	p.Authority.Provisioners = append(p.Authority.Provisioners, &linkedca.Provisioner{
		Type:   linkedca.Provisioner_JWK,
		Name:   p.options.provisioner,
		Claims: claims,
		Details: &linkedca.ProvisionerDetails{
			Data: &linkedca.ProvisionerDetails_JWK{
				JWK: &linkedca.JWKProvisioner{
					PublicKey:           publicKey,
					EncryptedPrivateKey: []byte(encryptedKey),
				},
			},
		},
	})

	return nil
}

// GenerateRootCertificate generates a root certificate with the given name
// and using the default key type.
func (p *PKI) GenerateRootCertificate(name, org, resource string, pass []byte) (*apiv1.CreateCertificateAuthorityResponse, error) {
	if uri := p.options.rootKeyURI; uri != "" {
		p.RootKey[0] = uri
	}

	resp, err := p.caCreator.CreateCertificateAuthority(&apiv1.CreateCertificateAuthorityRequest{
		Name:     resource + "-Root-CA",
		Type:     apiv1.RootCA,
		Lifetime: 10 * 365 * 24 * time.Hour,
		CreateKey: &apiv1.CreateKeyRequest{
			Name:               p.RootKey[0],
			SignatureAlgorithm: kmsapi.UnspecifiedSignAlgorithm,
		},
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

	// Replace key name with the one from the key manager if available. On
	// softcas this will be the original filename, on any other kms will be the
	// uri to the key.
	if resp.KeyName != "" {
		p.RootKey[0] = resp.KeyName
	}

	// PrivateKey will only be set if we have access to it (SoftCAS).
	if err := p.WriteRootCertificate(resp.Certificate, resp.PrivateKey, pass); err != nil {
		return nil, err
	}

	return resp, nil
}

// WriteRootCertificate writes to the buffer the given certificate and key if given.
func (p *PKI) WriteRootCertificate(rootCrt *x509.Certificate, rootKey interface{}, pass []byte) error {
	p.Files[p.Root[0]] = encodeCertificate(rootCrt)
	if rootKey != nil {
		var err error
		p.Files[p.RootKey[0]], err = encodePrivateKey(rootKey, pass)
		if err != nil {
			return err
		}
	}
	sum := sha256.Sum256(rootCrt.Raw)
	p.Defaults.Fingerprint = strings.ToLower(hex.EncodeToString(sum[:]))
	return nil
}

// GenerateIntermediateCertificate generates an intermediate certificate with
// the given name and using the default key type.
func (p *PKI) GenerateIntermediateCertificate(name, org, resource string, parent *apiv1.CreateCertificateAuthorityResponse, pass []byte) error {
	if uri := p.options.intermediateKeyURI; uri != "" {
		p.IntermediateKey = uri
	}

	resp, err := p.caCreator.CreateCertificateAuthority(&apiv1.CreateCertificateAuthorityRequest{
		Name:     resource + "-Intermediate-CA",
		Type:     apiv1.IntermediateCA,
		Lifetime: 10 * 365 * 24 * time.Hour,
		CreateKey: &apiv1.CreateKeyRequest{
			Name:               p.IntermediateKey,
			SignatureAlgorithm: kmsapi.UnspecifiedSignAlgorithm,
		},
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
	p.Files[p.Intermediate] = encodeCertificate(resp.Certificate)

	// Replace the key name with the one from the key manager. On softcas this
	// will be the original filename, on any other kms will be the uri to the
	// key.
	if resp.KeyName != "" {
		p.IntermediateKey = resp.KeyName
	}

	// If a kms is used it will not have the private key
	if resp.PrivateKey != nil {
		p.Files[p.IntermediateKey], err = encodePrivateKey(resp.PrivateKey, pass)
	}

	return err
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
	p.Intermediate = ""
	p.IntermediateKey = ""

	return nil
}

// GenerateSSHSigningKeys generates and encrypts a private key used for signing
// SSH user certificates and a private key used for signing host certificates.
func (p *PKI) GenerateSSHSigningKeys(password []byte) error {
	// Enable SSH
	p.options.enableSSH = true // TODO(hs): change this function to not mutate configuration state

	// Create SSH key used to sign host certificates. Using
	// kmsapi.UnspecifiedSignAlgorithm will default to the default algorithm.
	name := p.Ssh.HostKey
	if uri := p.options.hostKeyURI; uri != "" {
		name = uri
	}
	resp, err := p.keyManager.CreateKey(&kmsapi.CreateKeyRequest{
		Name:               name,
		SignatureAlgorithm: kmsapi.UnspecifiedSignAlgorithm,
	})
	if err != nil {
		return err
	}
	sshKey, err := ssh.NewPublicKey(resp.PublicKey)
	if err != nil {
		return errors.Wrapf(err, "error converting public key")
	}
	p.Files[p.Ssh.HostPublicKey] = ssh.MarshalAuthorizedKey(sshKey)

	// On softkms we will have the private key
	if resp.PrivateKey != nil {
		p.Files[p.Ssh.HostKey], err = encodePrivateKey(resp.PrivateKey, password)
		if err != nil {
			return err
		}
	} else {
		p.Ssh.HostKey = resp.Name
	}

	// Create SSH key used to sign user certificates. Using
	// kmsapi.UnspecifiedSignAlgorithm will default to the default algorithm.
	name = p.Ssh.UserKey
	if uri := p.options.userKeyURI; uri != "" {
		name = uri
	}
	resp, err = p.keyManager.CreateKey(&kmsapi.CreateKeyRequest{
		Name:               name,
		SignatureAlgorithm: kmsapi.UnspecifiedSignAlgorithm,
	})
	if err != nil {
		return err
	}
	sshKey, err = ssh.NewPublicKey(resp.PublicKey)
	if err != nil {
		return errors.Wrapf(err, "error converting public key")
	}
	p.Files[p.Ssh.UserPublicKey] = ssh.MarshalAuthorizedKey(sshKey)

	// On softkms we will have the private key
	if resp.PrivateKey != nil {
		p.Files[p.Ssh.UserKey], err = encodePrivateKey(resp.PrivateKey, password)
		if err != nil {
			return err
		}
	} else {
		p.Ssh.UserKey = resp.Name
	}

	return nil
}

// WriteFiles writes on disk the previously generated files.
func (p *PKI) WriteFiles() error {
	for fn, b := range p.Files {
		if err := fileutil.WriteFile(fn, b, 0600); err != nil {
			return err
		}
	}
	return nil
}

func (p *PKI) askFeedback() {
	ui.Println()
	ui.Println("\033[1mFEEDBACK\033[0m 😍 🍻")
	ui.Println("  The \033[1mstep\033[0m utility is not instrumented for usage statistics. It does not phone")
	ui.Println("  home. But your feedback is extremely valuable. Any information you can provide")
	ui.Println("  regarding how you’re using `step` helps. Please send us a sentence or two,")
	ui.Println("  good or bad at \033[1mfeedback@smallstep.com\033[0m or join GitHub Discussions")
	ui.Println("  \033[1mhttps://github.com/smallstep/certificates/discussions\033[0m and our Discord ")
	ui.Println("  \033[1mhttps://u.step.sm/discord\033[0m.")

	if p.options.deploymentType == LinkedDeployment {
		ui.Println()
		ui.Println("\033[1mNEXT STEPS\033[0m")
		ui.Println("  1. Log in or create a Certificate Manager account at \033[1mhttps://u.step.sm/linked\033[0m")
		ui.Println("  2. Add a new authority and select \"Link a step-ca instance\"")
		ui.Println("  3. Follow instructions in browser to start `step-ca` using the `--token` flag")
		ui.Println()
	}
}

func (p *PKI) tellPKI() {
	ui.Println()
	switch {
	case p.casOptions.Is(apiv1.SoftCAS):
		ui.PrintSelected("Root certificate", p.Root[0])
		ui.PrintSelected("Root private key", p.RootKey[0])
		ui.PrintSelected("Root fingerprint", p.Defaults.Fingerprint)
		ui.PrintSelected("Intermediate certificate", p.Intermediate)
		ui.PrintSelected("Intermediate private key", p.IntermediateKey)
	case p.Defaults.Fingerprint != "":
		ui.PrintSelected("Root certificate", p.Root[0])
		ui.PrintSelected("Root fingerprint", p.Defaults.Fingerprint)
	default:
		ui.Printf(`{{ "%s" | red }} {{ "Root certificate:" | bold }} failed to retrieve it from RA`+"\n", ui.IconBad)
	}
	if p.options.enableSSH {
		ui.PrintSelected("SSH user public key", p.Ssh.UserPublicKey)
		ui.PrintSelected("SSH user private key", p.Ssh.UserKey)
		ui.PrintSelected("SSH host public key", p.Ssh.HostPublicKey)
		ui.PrintSelected("SSH host private key", p.Ssh.HostKey)
	}
}

type caDefaults struct {
	CAUrl       string `json:"ca-url"`
	CAConfig    string `json:"ca-config"`
	Fingerprint string `json:"fingerprint"`
	Root        string `json:"root"`
}

// ConfigOption is the type for modifiers over the auth config object.
type ConfigOption func(c *authconfig.Config) error

// GenerateConfig returns the step certificates configuration.
func (p *PKI) GenerateConfig(opt ...ConfigOption) (*authconfig.Config, error) {
	var authorityOptions *apiv1.Options
	if !p.casOptions.Is(apiv1.SoftCAS) {
		authorityOptions = &p.casOptions
	}

	cfg := &authconfig.Config{
		Root:             p.Root,
		FederatedRoots:   p.FederatedRoots,
		IntermediateCert: p.Intermediate,
		IntermediateKey:  p.IntermediateKey,
		Address:          p.Address,
		DNSNames:         p.DnsNames,
		Logger:           []byte(`{"format": "text"}`),
		DB: &db.Config{
			Type:       "badgerv2",
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

	// Add linked as a deployment type to detect it on start and provide a
	// message if the token is not given.
	if p.options.deploymentType == LinkedDeployment {
		cfg.AuthorityConfig.DeploymentType = LinkedDeployment.String()
	}

	// Enable KMS if necessary
	if p.Kms != nil {
		typ := strings.ToLower(p.Kms.Type.String())
		cfg.KMS = &kmsapi.Options{
			Type: kmsapi.Type(typ),
		}
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
			cfg.SSH = &authconfig.SSHConfig{
				HostKey: p.Ssh.HostKey,
				UserKey: p.Ssh.UserKey,
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
		if err := o(cfg); err != nil {
			return nil, err
		}
	}

	// Set authority.enableAdmin to true
	if p.options.enableAdmin {
		cfg.AuthorityConfig.EnableAdmin = true
	}

	if p.options.deploymentType == StandaloneDeployment {
		if !cfg.AuthorityConfig.EnableAdmin {
			cfg.AuthorityConfig.Provisioners = provisioners
		} else {
			// At this moment this code path is never used because `step ca
			// init` will always set enableAdmin to false for a standalone
			// deployment. Once we move `step beta` commands out of the beta we
			// should probably default to this route.
			//
			// Note that we might want to be able to define the database as a
			// flag in `step ca init` so we can write to the proper place.
			//
			// TODO(hs): the logic for creating the provisioners and the super admin
			// is similar to what's done when automatically migrating the provisioners.
			// This is related to the existing comment above. Refactor this to exist in
			// a single place and ensure it happens only once.
			_db, err := db.New(cfg.DB)
			if err != nil {
				return nil, err
			}
			adminDB, err := admindb.New(_db.(nosql.DB), admin.DefaultAuthorityID)
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
			superAdminSubject := "step"
			if p.options.superAdminSubject != "" {
				superAdminSubject = p.options.superAdminSubject
			}
			if err := adminDB.CreateAdmin(context.Background(), &linkedca.Admin{
				AuthorityId:   admin.DefaultAuthorityID,
				Subject:       superAdminSubject,
				Type:          linkedca.Admin_SUPER_ADMIN,
				ProvisionerId: adminID,
			}); err != nil {
				return nil, err
			}
		}
	}

	return cfg, nil
}

// Save stores the pki on a json file that will be used as the certificate
// authority configuration.
func (p *PKI) Save(opt ...ConfigOption) error {
	// Write generated files
	if err := p.WriteFiles(); err != nil {
		return err
	}

	// Display the files written
	p.tellPKI()

	// Generate and write ca.json
	if !p.options.pkiOnly {
		cfg, err := p.GenerateConfig(opt...)
		if err != nil {
			return err
		}

		b, err := json.MarshalIndent(cfg, "", "\t")
		if err != nil {
			return errors.Wrapf(err, "error marshaling %s", p.config)
		}
		if err = fileutil.WriteFile(p.config, b, 0644); err != nil {
			return errs.FileError(err, p.config)
		}

		// Generate and write defaults.json
		defaults := &caDefaults{
			Root:        p.Defaults.Root,
			CAConfig:    p.Defaults.CaConfig,
			CAUrl:       p.Defaults.CaUrl,
			Fingerprint: p.Defaults.Fingerprint,
		}
		b, err = json.MarshalIndent(defaults, "", "\t")
		if err != nil {
			return errors.Wrapf(err, "error marshaling %s", p.defaults)
		}
		if err = fileutil.WriteFile(p.defaults, b, 0644); err != nil {
			return errs.FileError(err, p.defaults)
		}
		// If we're using contexts then write a blank object to the default profile
		// configuration location.
		if p.profileDefaults != "" {
			if _, err := os.Stat(p.profileDefaults); os.IsNotExist(err) {
				// Write with 0600 to be consistent with directories structure.
				if err = fileutil.WriteFile(p.profileDefaults, []byte("{}"), 0600); err != nil {
					return errs.FileError(err, p.profileDefaults)
				}
			} else if err != nil {
				return errs.FileError(err, p.profileDefaults)
			}
		}

		// Generate and write templates
		if err := generateTemplates(cfg.Templates); err != nil {
			return err
		}

		if cfg.DB != nil {
			os.MkdirAll(cfg.DB.DataSource, 0700)
			ui.PrintSelected("Database folder", cfg.DB.DataSource)
		}
		if cfg.Templates != nil {
			ui.PrintSelected("Templates folder", GetTemplatesPath())
		}

		ui.PrintSelected("Default configuration", p.defaults)
		if p.profileDefaults != "" {
			ui.PrintSelected("Default profile configuration", p.profileDefaults)
		}
		ui.PrintSelected("Certificate Authority configuration", p.config)
		if cfg.AuthorityConfig.EnableAdmin && p.options.deploymentType != LinkedDeployment {
			// TODO(hs): we may want to get this information from the DB, because that's
			// where the admin and provisioner are stored in this case. Requires some
			// refactoring.
			superAdminSubject := "step"
			if p.options.superAdminSubject != "" {
				superAdminSubject = p.options.superAdminSubject
			}
			ui.PrintSelected("Admin provisioner", fmt.Sprintf("%s (JWK)", p.options.provisioner))
			ui.PrintSelected("Super admin subject", superAdminSubject)
		}

		if p.options.deploymentType != LinkedDeployment {
			ui.Println()
			if p.casOptions.Is(apiv1.SoftCAS) {
				ui.Println("Your PKI is ready to go. To generate certificates for individual services see 'step help ca'.")
			} else {
				ui.Println("Your registration authority is ready to go. To generate certificates for individual services see 'step help ca'.")
			}
		}
	}

	p.askFeedback()
	return nil
}

func encodeCertificate(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.Raw,
	})
}

func encodePrivateKey(key crypto.PrivateKey, pass []byte) ([]byte, error) {
	block, err := pemutil.Serialize(key, pemutil.WithPassword(pass))
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(block), nil
}
