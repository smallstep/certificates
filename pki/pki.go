package pki

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
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

	"golang.org/x/crypto/ssh"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/cli/config"
	"github.com/smallstep/cli/crypto/keys"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/crypto/tlsutil"
	"github.com/smallstep/cli/crypto/x509util"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
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

// PKI represents the Public Key Infrastructure used by a certificate authority.
type PKI struct {
	root, rootKey, rootFingerprint string
	intermediate, intermediateKey  string
	sshHostPubKey, sshHostKey      string
	sshUserPubKey, sshUserKey      string
	config, defaults               string
	ottPublicKey                   *jose.JSONWebKey
	ottPrivateKey                  *jose.JSONWebEncryption
	provisioner                    string
	address                        string
	dnsNames                       []string
	caURL                          string
	enableSSH                      bool
}

// New creates a new PKI configuration.
func New(public, private, config string) (*PKI, error) {
	if _, err := os.Stat(public); os.IsNotExist(err) {
		if err = os.MkdirAll(public, 0700); err != nil {
			return nil, errs.FileError(err, public)
		}
	}
	if _, err := os.Stat(private); os.IsNotExist(err) {
		if err = os.MkdirAll(private, 0700); err != nil {
			return nil, errs.FileError(err, private)
		}
	}
	if len(config) > 0 {
		if _, err := os.Stat(config); os.IsNotExist(err) {
			if err = os.MkdirAll(config, 0700); err != nil {
				return nil, errs.FileError(err, config)
			}
		}
	}

	// get absolute path for dir/name
	getPath := func(dir string, name string) (string, error) {
		s, err := filepath.Abs(filepath.Join(dir, name))
		return s, errors.Wrapf(err, "error getting absolute path for %s", name)
	}

	var err error
	p := &PKI{
		provisioner: "step-cli",
		address:     "127.0.0.1:9000",
		dnsNames:    []string{"127.0.0.1"},
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
	if p.sshHostPubKey, err = getPath(public, "ssh_host_key.pub"); err != nil {
		return nil, err
	}
	if p.sshUserPubKey, err = getPath(public, "ssh_user_key.pub"); err != nil {
		return nil, err
	}
	if p.sshHostKey, err = getPath(private, "ssh_host_key"); err != nil {
		return nil, err
	}
	if p.sshUserKey, err = getPath(private, "ssh_user_key"); err != nil {
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
func (p *PKI) SetProvisioner(s string) {
	p.provisioner = s
}

// SetAddress sets the listening address of the CA.
func (p *PKI) SetAddress(s string) {
	p.address = s
}

// SetDNSNames sets the dns names of the CA.
func (p *PKI) SetDNSNames(s []string) {
	p.dnsNames = s
}

// SetCAURL sets the ca-url to use in the defaults.json.
func (p *PKI) SetCAURL(s string) {
	p.caURL = s
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

// GenerateRootCertificate generates a root certificate with the given name.
func (p *PKI) GenerateRootCertificate(name string, pass []byte) (*x509.Certificate, interface{}, error) {
	rootProfile, err := x509util.NewRootProfile(name)
	if err != nil {
		return nil, nil, err
	}

	rootBytes, err := rootProfile.CreateWriteCertificate(p.root, p.rootKey, string(pass))
	if err != nil {
		return nil, nil, err
	}

	rootCrt, err := x509.ParseCertificate(rootBytes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "error parsing root certificate")
	}

	sum := sha256.Sum256(rootCrt.Raw)
	p.rootFingerprint = strings.ToLower(hex.EncodeToString(sum[:]))

	return rootCrt, rootProfile.SubjectPrivateKey(), nil
}

// WriteRootCertificate writes to disk the given certificate and key.
func (p *PKI) WriteRootCertificate(rootCrt *x509.Certificate, rootKey interface{}, pass []byte) error {
	if err := utils.WriteFile(p.root, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: rootCrt.Raw,
	}), 0600); err != nil {
		return err
	}

	_, err := pemutil.Serialize(rootKey, pemutil.WithPassword([]byte(pass)), pemutil.ToFile(p.rootKey, 0600))
	if err != nil {
		return err
	}
	return nil
}

// GenerateIntermediateCertificate generates an intermediate certificate with
// the given name.
func (p *PKI) GenerateIntermediateCertificate(name string, rootCrt *x509.Certificate, rootKey interface{}, pass []byte) error {
	interProfile, err := x509util.NewIntermediateProfile(name, rootCrt, rootKey)
	if err != nil {
		return err
	}
	_, err = interProfile.CreateWriteCertificate(p.intermediate, p.intermediateKey, string(pass))
	return err
}

// GenerateSSHSigningKeys generates and encrypts a private key used for signing
// SSH user certificates and a private key used for signing host certificates.
func (p *PKI) GenerateSSHSigningKeys(password []byte) error {
	var pubNames = []string{p.sshHostPubKey, p.sshUserPubKey}
	var privNames = []string{p.sshHostKey, p.sshUserKey}
	for i := 0; i < 2; i++ {
		pub, priv, err := keys.GenerateDefaultKeyPair()
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
		if err = utils.WriteFile(pubNames[i], ssh.MarshalAuthorizedKey(sshKey), 0600); err != nil {
			return err
		}
	}
	p.enableSSH = true
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
	ui.Println("      \033[1mhttps://gitter.im/smallstep/community\033[0m.")
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
	ui.PrintSelected("Root certificate", p.root)
	ui.PrintSelected("Root private key", p.rootKey)
	ui.PrintSelected("Root fingerprint", p.rootFingerprint)
	ui.PrintSelected("Intermediate certificate", p.intermediate)
	ui.PrintSelected("Intermediate private key", p.intermediateKey)
	if p.enableSSH {
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
type Option func(c *authority.Config) error

// WithDefaultDB is a configuration modifier that adds a default DB stanza to
// the authority config.
func WithDefaultDB() Option {
	return func(c *authority.Config) error {
		c.DB = &db.Config{
			Type:       "badger",
			DataSource: GetDBPath(),
		}
		return nil
	}
}

// WithoutDB is a configuration modifier that adds a default DB stanza to
// the authority config.
func WithoutDB() Option {
	return func(c *authority.Config) error {
		c.DB = nil
		return nil
	}
}

// GenerateConfig returns the step certificates configuration.
func (p *PKI) GenerateConfig(opt ...Option) (*authority.Config, error) {
	key, err := p.ottPrivateKey.CompactSerialize()
	if err != nil {
		return nil, errors.Wrap(err, "error serializing private key")
	}

	prov := &provisioner.JWK{
		Name:         p.provisioner,
		Type:         "JWK",
		Key:          p.ottPublicKey,
		EncryptedKey: key,
	}

	config := &authority.Config{
		Root:             []string{p.root},
		FederatedRoots:   []string{},
		IntermediateCert: p.intermediate,
		IntermediateKey:  p.intermediateKey,
		Address:          p.address,
		DNSNames:         p.dnsNames,
		Logger:           []byte(`{"format": "text"}`),
		DB: &db.Config{
			Type:       "badger",
			DataSource: GetDBPath(),
		},
		AuthorityConfig: &authority.AuthConfig{
			DisableIssuedAtCheck: false,
			Provisioners:         provisioner.List{prov},
		},
		TLS: &tlsutil.TLSOptions{
			MinVersion:    x509util.DefaultTLSMinVersion,
			MaxVersion:    x509util.DefaultTLSMaxVersion,
			Renegotiation: x509util.DefaultTLSRenegotiation,
			CipherSuites:  x509util.DefaultTLSCipherSuites,
		},
	}
	if p.enableSSH {
		enableSSHCA := true
		config.SSH = &authority.SSHConfig{
			HostKey: p.sshHostKey,
			UserKey: p.sshUserKey,
		}
		prov.Claims = &provisioner.Claims{
			EnableSSHCA: &enableSSHCA,
		}
	}

	// Apply configuration modifiers
	for _, o := range opt {
		if err = o(config); err != nil {
			return nil, err
		}
	}

	return config, nil
}

// Save stores the pki on a json file that will be used as the certificate
// authority configuration.
func (p *PKI) Save(opt ...Option) error {
	p.tellPKI()

	config, err := p.GenerateConfig(opt...)
	if err != nil {
		return err
	}

	b, err := json.MarshalIndent(config, "", "   ")
	if err != nil {
		return errors.Wrapf(err, "error marshaling %s", p.config)
	}
	if err = utils.WriteFile(p.config, b, 0666); err != nil {
		return errs.FileError(err, p.config)
	}

	// Generate the CA URL.
	if p.caURL == "" {
		p.caURL = p.dnsNames[0]
		var port string
		_, port, err = net.SplitHostPort(p.address)
		if err != nil {
			return errors.Wrapf(err, "error parsing %s", p.address)
		}
		if port == "443" {
			p.caURL = fmt.Sprintf("https://%s", p.caURL)
		} else {
			p.caURL = fmt.Sprintf("https://%s:%s", p.caURL, port)
		}
	}

	defaults := &caDefaults{
		Root:        p.root,
		CAConfig:    p.config,
		CAUrl:       p.caURL,
		Fingerprint: p.rootFingerprint,
	}
	b, err = json.MarshalIndent(defaults, "", "   ")
	if err != nil {
		return errors.Wrapf(err, "error marshaling %s", p.defaults)
	}
	if err = utils.WriteFile(p.defaults, b, 0666); err != nil {
		return errs.FileError(err, p.defaults)
	}

	ui.PrintSelected("Default configuration", p.defaults)
	ui.PrintSelected("Certificate Authority configuration", p.config)
	if config.DB != nil {
		ui.PrintSelected("Database", config.DB.DataSource)
	}
	ui.Println()
	ui.Println("Your PKI is ready to go. To generate certificates for individual services see 'step help ca'.")

	p.askFeedback()

	return nil
}
