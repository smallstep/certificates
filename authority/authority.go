package authority

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"sync"
	"time"

	"github.com/smallstep/certificates/templates"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/crypto/x509util"
	"golang.org/x/crypto/ssh"
)

const (
	legacyAuthority = "step-certificate-authority"
)

// Authority implements the Certificate Authority internal interface.
type Authority struct {
	config                  *Config
	rootX509Certs           []*x509.Certificate
	intermediateIdentity    *x509util.Identity
	sshCAUserCertSignKey    ssh.Signer
	sshCAHostCertSignKey    ssh.Signer
	sshCAUserCerts          []ssh.PublicKey
	sshCAHostCerts          []ssh.PublicKey
	sshCAUserFederatedCerts []ssh.PublicKey
	sshCAHostFederatedCerts []ssh.PublicKey
	certificates            *sync.Map
	startTime               time.Time
	provisioners            *provisioner.Collection
	db                      db.AuthDB
	// Do not re-initialize
	initOnce bool
	// Custom functions
	sshBastionFunc  func(user, hostname string) (*Bastion, error)
	getIdentityFunc provisioner.GetIdentityFunc
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
		provisioners: provisioner.NewCollection(config.getAudiences()),
	}
	for _, opt := range opts {
		opt(a)
	}
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
	// Initialize step-ca Database if it's not already initialized with WithDB.
	// If a.config.DB is nil then a simple, barebones in memory DB will be used.
	if a.db == nil {
		if a.db, err = db.New(a.config.DB); err != nil {
			return err
		}
	}

	// Load the root certificates and add them to the certificate store
	a.rootX509Certs = make([]*x509.Certificate, len(a.config.Root))
	for i, path := range a.config.Root {
		crt, err := pemutil.ReadCertificate(path)
		if err != nil {
			return err
		}
		// Add root certificate to the certificate map
		sum := sha256.Sum256(crt.Raw)
		a.certificates.Store(hex.EncodeToString(sum[:]), crt)
		a.rootX509Certs[i] = crt
	}

	// Add federated roots
	for _, path := range a.config.FederatedRoots {
		crt, err := pemutil.ReadCertificate(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(crt.Raw)
		a.certificates.Store(hex.EncodeToString(sum[:]), crt)
	}

	// Decrypt and load intermediate public / private key pair.
	if len(a.config.Password) > 0 {
		a.intermediateIdentity, err = x509util.LoadIdentityFromDisk(
			a.config.IntermediateCert,
			a.config.IntermediateKey,
			pemutil.WithPassword([]byte(a.config.Password)),
		)
		if err != nil {
			return err
		}
	} else {
		a.intermediateIdentity, err = x509util.LoadIdentityFromDisk(a.config.IntermediateCert, a.config.IntermediateKey)
		if err != nil {
			return err
		}
	}

	// Decrypt and load SSH keys
	if a.config.SSH != nil {
		if a.config.SSH.HostKey != "" {
			signer, err := parseCryptoSigner(a.config.SSH.HostKey, a.config.Password)
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
			signer, err := parseCryptoSigner(a.config.SSH.UserKey, a.config.Password)
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
	}

	// Merge global and configuration claims
	claimer, err := provisioner.NewClaimer(a.config.AuthorityConfig.Claims, globalProvisionerClaims)
	if err != nil {
		return err
	}
	// TODO: should we also be combining the ssh federated roots here?
	// If we rotate ssh roots keys, sshpop provisioner will lose ability to
	// validate old SSH certificates, unless they are added as federated certs.
	sshKeys, err := a.GetSSHRoots()
	if err != nil {
		return err
	}
	// Initialize provisioners
	config := provisioner.Config{
		Claims:    claimer.Claims(),
		Audiences: a.config.getAudiences(),
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

	// Configure protected template variables:
	if t := a.config.Templates; t != nil {
		if t.Data == nil {
			t.Data = make(map[string]interface{})
		}
		var vars templates.Step
		if a.config.SSH != nil {
			if a.sshCAHostCertSignKey != nil {
				vars.SSH.HostKey = a.sshCAHostCertSignKey.PublicKey()
				vars.SSH.HostFederatedKeys = append(vars.SSH.HostFederatedKeys, a.sshCAHostFederatedCerts[1:]...)
			}
			if a.sshCAUserCertSignKey != nil {
				vars.SSH.UserKey = a.sshCAUserCertSignKey.PublicKey()
				vars.SSH.UserFederatedKeys = append(vars.SSH.UserFederatedKeys, a.sshCAUserFederatedCerts[1:]...)
			}
		}
		t.Data["Step"] = vars
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
	return a.db.Shutdown()
}

func parseCryptoSigner(filename, password string) (crypto.Signer, error) {
	var opts []pemutil.Options
	if password != "" {
		opts = append(opts, pemutil.WithPassword([]byte(password)))
	}
	key, err := pemutil.Read(filename, opts...)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.Errorf("key %s of type %T cannot be used for signing operations", filename, key)
	}
	return signer, nil
}
