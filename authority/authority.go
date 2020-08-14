package authority

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"log"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/certificates/kms"
	kmsapi "github.com/smallstep/certificates/kms/apiv1"
	"github.com/smallstep/certificates/templates"
	"go.step.sm/crypto/pemutil"
	"golang.org/x/crypto/ssh"
)

const (
	legacyAuthority = "step-certificate-authority"
)

// Authority implements the Certificate Authority internal interface.
type Authority struct {
	config       *Config
	keyManager   kms.KeyManager
	provisioners *provisioner.Collection
	db           db.AuthDB
	templates    *templates.Templates

	// X509 CA
	rootX509Certs      []*x509.Certificate
	federatedX509Certs []*x509.Certificate
	x509Signer         crypto.Signer
	x509Issuer         *x509.Certificate
	certificates       *sync.Map

	// SSH CA
	sshCAUserCertSignKey    ssh.Signer
	sshCAHostCertSignKey    ssh.Signer
	sshCAUserCerts          []ssh.PublicKey
	sshCAHostCerts          []ssh.PublicKey
	sshCAUserFederatedCerts []ssh.PublicKey
	sshCAHostFederatedCerts []ssh.PublicKey

	// Do not re-initialize
	initOnce  bool
	startTime time.Time

	// Custom functions
	sshBastionFunc   func(ctx context.Context, user, hostname string) (*Bastion, error)
	sshCheckHostFunc func(ctx context.Context, principal string, tok string, roots []*x509.Certificate) (bool, error)
	sshGetHostsFunc  func(ctx context.Context, cert *x509.Certificate) ([]Host, error)
	getIdentityFunc  provisioner.GetIdentityFunc
}

// New creates and initiates a new Authority type.
func New(config *Config, opts ...Option) (*Authority, error) {
	err := config.Validate()
	if err != nil {
		return nil, err
	}

	var a = &Authority{
		config:       config,
		certificates: new(sync.Map),
	}

	// Apply options.
	for _, fn := range opts {
		if err := fn(a); err != nil {
			return nil, err
		}
	}

	// Initialize authority from options or configuration.
	if err := a.init(); err != nil {
		return nil, err
	}

	return a, nil
}

// NewEmbedded initializes an authority that can be embedded in a different
// project without the limitations of the config.
func NewEmbedded(opts ...Option) (*Authority, error) {
	a := &Authority{
		config:       &Config{},
		certificates: new(sync.Map),
	}

	// Apply options.
	for _, fn := range opts {
		if err := fn(a); err != nil {
			return nil, err
		}
	}

	// Validate required options
	switch {
	case a.config == nil:
		return nil, errors.New("cannot create an authority without a configuration")
	case len(a.rootX509Certs) == 0 && a.config.Root.HasEmpties():
		return nil, errors.New("cannot create an authority without a root certificate")
	case a.x509Issuer == nil && a.config.IntermediateCert == "":
		return nil, errors.New("cannot create an authority without an issuer certificate")
	case a.x509Signer == nil && a.config.IntermediateKey == "":
		return nil, errors.New("cannot create an authority without an issuer signer")
	}

	// Initialize config required fields.
	a.config.init()

	// Initialize authority from options or configuration.
	if err := a.init(); err != nil {
		return nil, err
	}

	return a, nil
}

// init performs validation and initializes the fields of an Authority struct.
func (a *Authority) init() error {
	// Check if handler has already been validated/initialized.
	if a.initOnce {
		return nil
	}

	var err error

	// Initialize key manager if it has not been set in the options.
	if a.keyManager == nil {
		var options kmsapi.Options
		if a.config.KMS != nil {
			options = *a.config.KMS
		}
		a.keyManager, err = kms.New(context.Background(), options)
		if err != nil {
			return err
		}
	}

	// Initialize step-ca Database if it's not already initialized with WithDB.
	// If a.config.DB is nil then a simple, barebones in memory DB will be used.
	if a.db == nil {
		if a.db, err = db.New(a.config.DB); err != nil {
			return err
		}
	}

	// Read root certificates and store them in the certificates map.
	if len(a.rootX509Certs) == 0 {
		a.rootX509Certs = make([]*x509.Certificate, len(a.config.Root))
		for i, path := range a.config.Root {
			crt, err := pemutil.ReadCertificate(path)
			if err != nil {
				return err
			}
			a.rootX509Certs[i] = crt
		}
	}
	for _, crt := range a.rootX509Certs {
		sum := sha256.Sum256(crt.Raw)
		a.certificates.Store(hex.EncodeToString(sum[:]), crt)
	}

	// Read federated certificates and store them in the certificates map.
	if len(a.federatedX509Certs) == 0 {
		a.federatedX509Certs = make([]*x509.Certificate, len(a.config.FederatedRoots))
		for i, path := range a.config.FederatedRoots {
			crt, err := pemutil.ReadCertificate(path)
			if err != nil {
				return err
			}
			a.federatedX509Certs[i] = crt
		}
	}
	for _, crt := range a.federatedX509Certs {
		sum := sha256.Sum256(crt.Raw)
		a.certificates.Store(hex.EncodeToString(sum[:]), crt)
	}

	// Read intermediate and create X509 signer.
	if a.x509Signer == nil {
		crt, err := pemutil.ReadCertificate(a.config.IntermediateCert)
		if err != nil {
			return err
		}
		signer, err := a.keyManager.CreateSigner(&kmsapi.CreateSignerRequest{
			SigningKey: a.config.IntermediateKey,
			Password:   []byte(a.config.Password),
		})
		if err != nil {
			return err
		}
		a.x509Signer = signer
		a.x509Issuer = crt
	}

	// Decrypt and load SSH keys
	var tmplVars templates.Step
	if a.config.SSH != nil {
		if a.config.SSH.HostKey != "" {
			signer, err := a.keyManager.CreateSigner(&kmsapi.CreateSignerRequest{
				SigningKey: a.config.SSH.HostKey,
				Password:   []byte(a.config.Password),
			})
			if err != nil {
				return err
			}
			a.sshCAHostCertSignKey, err = ssh.NewSignerFromSigner(signer)
			if err != nil {
				return errors.Wrap(err, "error creating ssh signer")
			}
			// Append public key to list of host certs
			a.sshCAHostCerts = append(a.sshCAHostCerts, a.sshCAHostCertSignKey.PublicKey())
			a.sshCAHostFederatedCerts = append(a.sshCAHostFederatedCerts, a.sshCAHostCertSignKey.PublicKey())
		}
		if a.config.SSH.UserKey != "" {
			signer, err := a.keyManager.CreateSigner(&kmsapi.CreateSignerRequest{
				SigningKey: a.config.SSH.UserKey,
				Password:   []byte(a.config.Password),
			})
			if err != nil {
				return err
			}
			a.sshCAUserCertSignKey, err = ssh.NewSignerFromSigner(signer)
			if err != nil {
				return errors.Wrap(err, "error creating ssh signer")
			}
			// Append public key to list of user certs
			a.sshCAUserCerts = append(a.sshCAUserCerts, a.sshCAUserCertSignKey.PublicKey())
			a.sshCAUserFederatedCerts = append(a.sshCAUserFederatedCerts, a.sshCAUserCertSignKey.PublicKey())
		}

		// Append other public keys
		for _, key := range a.config.SSH.Keys {
			switch key.Type {
			case provisioner.SSHHostCert:
				if key.Federated {
					a.sshCAHostFederatedCerts = append(a.sshCAHostFederatedCerts, key.PublicKey())
				} else {
					a.sshCAHostCerts = append(a.sshCAHostCerts, key.PublicKey())
				}
			case provisioner.SSHUserCert:
				if key.Federated {
					a.sshCAUserFederatedCerts = append(a.sshCAUserFederatedCerts, key.PublicKey())
				} else {
					a.sshCAUserCerts = append(a.sshCAUserCerts, key.PublicKey())
				}
			default:
				return errors.Errorf("unsupported type %s", key.Type)
			}
		}

		// Configure template variables.
		tmplVars.SSH.HostKey = a.sshCAHostCertSignKey.PublicKey()
		tmplVars.SSH.UserKey = a.sshCAUserCertSignKey.PublicKey()
		// On the templates we skip the first one because there's a distinction
		// between the main key and federated keys.
		tmplVars.SSH.HostFederatedKeys = append(tmplVars.SSH.HostFederatedKeys, a.sshCAHostFederatedCerts[1:]...)
		tmplVars.SSH.UserFederatedKeys = append(tmplVars.SSH.UserFederatedKeys, a.sshCAUserFederatedCerts[1:]...)
	}

	// Merge global and configuration claims
	claimer, err := provisioner.NewClaimer(a.config.AuthorityConfig.Claims, globalProvisionerClaims)
	if err != nil {
		return err
	}
	// TODO: should we also be combining the ssh federated roots here?
	// If we rotate ssh roots keys, sshpop provisioner will lose ability to
	// validate old SSH certificates, unless they are added as federated certs.
	sshKeys, err := a.GetSSHRoots(context.Background())
	if err != nil {
		return err
	}
	// Initialize provisioners
	audiences := a.config.getAudiences()
	a.provisioners = provisioner.NewCollection(audiences)
	config := provisioner.Config{
		Claims:    claimer.Claims(),
		Audiences: audiences,
		DB:        a.db,
		SSHKeys: &provisioner.SSHKeys{
			UserKeys: sshKeys.UserKeys,
			HostKeys: sshKeys.HostKeys,
		},
		GetIdentityFunc: a.getIdentityFunc,
	}
	// Store all the provisioners
	for _, p := range a.config.AuthorityConfig.Provisioners {
		if err := p.Init(config); err != nil {
			return err
		}
		if err := a.provisioners.Store(p); err != nil {
			return err
		}
	}

	// Configure templates, currently only ssh templates are supported.
	if a.sshCAHostCertSignKey != nil || a.sshCAUserCertSignKey != nil {
		a.templates = a.config.Templates
		if a.templates == nil {
			a.templates = templates.DefaultTemplates()
		}
		if a.templates.Data == nil {
			a.templates.Data = make(map[string]interface{})
		}
		a.templates.Data["Step"] = tmplVars
	}

	// JWT numeric dates are seconds.
	a.startTime = time.Now().Truncate(time.Second)
	// Set flag indicating that initialization has been completed, and should
	// not be repeated.
	a.initOnce = true

	return nil
}

// GetDatabase returns the authority database. If the configuration does not
// define a database, GetDatabase will return a db.SimpleDB instance.
func (a *Authority) GetDatabase() db.AuthDB {
	return a.db
}

// Shutdown safely shuts down any clients, databases, etc. held by the Authority.
func (a *Authority) Shutdown() error {
	if err := a.keyManager.Close(); err != nil {
		log.Printf("error closing the key manager: %v", err)
	}
	return a.db.Shutdown()
}
