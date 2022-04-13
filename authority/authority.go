package authority

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/admin"
	adminDBNosql "github.com/smallstep/certificates/authority/admin/db/nosql"
	"github.com/smallstep/certificates/authority/administrator"
	"github.com/smallstep/certificates/authority/cache"
	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/cas"
	casapi "github.com/smallstep/certificates/cas/apiv1"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/certificates/kms"
	kmsapi "github.com/smallstep/certificates/kms/apiv1"
	"github.com/smallstep/certificates/kms/sshagentkms"
	"github.com/smallstep/certificates/scep"
	"github.com/smallstep/certificates/templates"
	"github.com/smallstep/nosql"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/linkedca"
	"golang.org/x/crypto/ssh"
)

// Authority implements the Certificate Authority internal interface.
type Authority struct {
	config        *config.Config
	keyManager    kms.KeyManager
	provisioners  Provisioners
	admins        Admins
	db            db.AuthDB
	adminDB       admin.DB
	templates     *templates.Templates
	linkedCAToken string

	// X509 CA
	password           []byte
	issuerPassword     []byte
	x509CAService      cas.CertificateAuthorityService
	rootX509Certs      []*x509.Certificate
	rootX509CertPool   *x509.CertPool
	federatedX509Certs []*x509.Certificate
	certificates       *sync.Map
	x509Enforcers      []provisioner.CertificateEnforcer

	// SCEP CA
	scepService *scep.Service

	// SSH CA
	sshHostPassword         []byte
	sshUserPassword         []byte
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
	sshBastionFunc        func(ctx context.Context, user, hostname string) (*config.Bastion, error)
	sshCheckHostFunc      func(ctx context.Context, principal string, tok string, roots []*x509.Certificate) (bool, error)
	sshGetHostsFunc       func(ctx context.Context, cert *x509.Certificate) ([]config.Host, error)
	getIdentityFunc       provisioner.GetIdentityFunc
	authorizeRenewFunc    provisioner.AuthorizeRenewFunc
	authorizeSSHRenewFunc provisioner.AuthorizeSSHRenewFunc
	cachePool             cache.Pool

	adminMutex sync.RWMutex
}

type Info struct {
	StartTime          time.Time
	RootX509Certs      []*x509.Certificate
	SSHCAUserPublicKey []byte
	SSHCAHostPublicKey []byte
	DNSNames           []string
}

// New creates and initiates a new Authority type.
func New(cfg *config.Config, opts ...Option) (*Authority, error) {
	err := cfg.Validate()
	if err != nil {
		return nil, err
	}

	var a = &Authority{
		config:       cfg,
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
		config:       &config.Config{},
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
	case a.x509CAService == nil && a.config.IntermediateCert == "":
		return nil, errors.New("cannot create an authority without an issuer certificate")
	case a.x509CAService == nil && a.config.IntermediateKey == "":
		return nil, errors.New("cannot create an authority without an issuer signer")
	}

	// Initialize config required fields.
	a.config.Init()

	// Initialize authority from options or configuration.
	if err := a.init(); err != nil {
		return nil, err
	}

	return a, nil
}

// reloadAdminResources reloads admins and provisioners from the DB.
func (a *Authority) reloadAdminResources(ctx context.Context) error {
	var (
		provList  provisioner.List
		adminList []*linkedca.Admin
	)
	if a.config.AuthorityConfig.EnableAdmin {
		provs, err := a.adminDB.GetProvisioners(ctx)
		if err != nil {
			return admin.WrapErrorISE(err, "error getting provisioners to initialize authority")
		}
		provList, err = provisionerListToCertificates(provs)
		if err != nil {
			return admin.WrapErrorISE(err, "error converting provisioner list to certificates")
		}
		adminList, err = a.adminDB.GetAdmins(ctx)
		if err != nil {
			return admin.WrapErrorISE(err, "error getting admins to initialize authority")
		}
	} else {
		provList = a.config.AuthorityConfig.Provisioners
		adminList = a.config.AuthorityConfig.Admins
	}

	provisionerConfig, err := a.generateProvisionerConfig(ctx)
	if err != nil {
		return admin.WrapErrorISE(err, "error generating provisioner config")
	}

	// Create provisioner collection.
	provClxn := provisioner.NewCollection(provisionerConfig)
	for _, p := range provList {
		if err := p.Init(provisionerConfig); err != nil {
			return err
		}
		if err := provClxn.Store(p); err != nil {
			return err
		}
	}
	// Create admin collection.
	adminClxn := administrator.NewCollection(provClxn)
	for _, adm := range adminList {
		p, ok := provClxn.Load(adm.ProvisionerId)
		if !ok {
			return admin.NewErrorISE("provisioner %s not found when loading admin %s",
				adm.ProvisionerId, adm.Id)
		}
		if err := adminClxn.Store(adm, p); err != nil {
			return err
		}
	}

	a.config.AuthorityConfig.Provisioners = provList
	a.provisioners = provClxn
	a.config.AuthorityConfig.Admins = adminList
	a.admins = adminClxn
	return nil
}

// init performs validation and initializes the fields of an Authority struct.
func (a *Authority) init() error {
	// Check if handler has already been validated/initialized.
	if a.initOnce {
		return nil
	}

	var err error

	// Set password if they are not set.
	var configPassword []byte
	if a.config.Password != "" {
		configPassword = []byte(a.config.Password)
	}
	if configPassword != nil && a.password == nil {
		a.password = configPassword
	}
	if a.sshHostPassword == nil {
		a.sshHostPassword = a.password
	}
	if a.sshUserPassword == nil {
		a.sshUserPassword = a.password
	}

	// Automatically enable admin for all linked cas.
	if a.linkedCAToken != "" {
		a.config.AuthorityConfig.EnableAdmin = true
	}

	// Initialize step-ca Database if it's not already initialized with WithDB.
	// If a.config.DB is nil then a simple, barebones in memory DB will be used.
	if a.db == nil {
		if a.db, err = db.New(a.config.DB); err != nil {
			return err
		}
	}

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

	// Initialize linkedca client if necessary. On a linked RA, the issuer
	// configuration might come from majordomo.
	var linkedcaClient *linkedCaClient
	if a.config.AuthorityConfig.EnableAdmin && a.linkedCAToken != "" && a.adminDB == nil {
		linkedcaClient, err = newLinkedCAClient(a.linkedCAToken)
		if err != nil {
			return err
		}
		// If authorityId is configured make sure it matches the one in the token
		if id := a.config.AuthorityConfig.AuthorityID; id != "" && !strings.EqualFold(id, linkedcaClient.authorityID) {
			return errors.New("error initializing linkedca: token authority and configured authority do not match")
		}
		linkedcaClient.Run()
	}

	// Initialize the X.509 CA Service if it has not been set in the options.
	if a.x509CAService == nil {
		var options casapi.Options
		if a.config.AuthorityConfig.Options != nil {
			options = *a.config.AuthorityConfig.Options
		}

		// Configure linked RA
		if linkedcaClient != nil && options.CertificateAuthority == "" {
			conf, err := linkedcaClient.GetConfiguration(context.Background())
			if err != nil {
				return err
			}
			if conf.RaConfig != nil {
				options.CertificateAuthority = conf.RaConfig.CaUrl
				options.CertificateAuthorityFingerprint = conf.RaConfig.Fingerprint
				options.CertificateIssuer = &casapi.CertificateIssuer{
					Type:        conf.RaConfig.Provisioner.Type.String(),
					Provisioner: conf.RaConfig.Provisioner.Name,
				}
			}
		}

		// Set the issuer password if passed in the flags.
		if options.CertificateIssuer != nil && a.issuerPassword != nil {
			options.CertificateIssuer.Password = string(a.issuerPassword)
		}

		// Read intermediate and create X509 signer for default CAS.
		if options.Is(casapi.SoftCAS) {
			options.CertificateChain, err = pemutil.ReadCertificateBundle(a.config.IntermediateCert)
			if err != nil {
				return err
			}
			options.Signer, err = a.keyManager.CreateSigner(&kmsapi.CreateSignerRequest{
				SigningKey: a.config.IntermediateKey,
				Password:   []byte(a.password),
			})
			if err != nil {
				return err
			}
		}

		a.x509CAService, err = cas.New(context.Background(), options)
		if err != nil {
			return err
		}

		// Get root certificate from CAS.
		if srv, ok := a.x509CAService.(casapi.CertificateAuthorityGetter); ok {
			resp, err := srv.GetCertificateAuthority(&casapi.GetCertificateAuthorityRequest{
				Name: options.CertificateAuthority,
			})
			if err != nil {
				return err
			}
			a.rootX509Certs = append(a.rootX509Certs, resp.RootCertificate)
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

	a.rootX509CertPool = x509.NewCertPool()
	for _, cert := range a.rootX509Certs {
		a.rootX509CertPool.AddCert(cert)
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

	// Decrypt and load SSH keys
	var tmplVars templates.Step
	if a.config.SSH != nil {
		if a.config.SSH.HostKey != "" {
			signer, err := a.keyManager.CreateSigner(&kmsapi.CreateSignerRequest{
				SigningKey: a.config.SSH.HostKey,
				Password:   []byte(a.sshHostPassword),
			})
			if err != nil {
				return err
			}
			// If our signer is from sshagentkms, just unwrap it instead of
			// wrapping it in another layer, and this prevents crypto from
			// erroring out with: ssh: unsupported key type *agent.Key
			switch s := signer.(type) {
			case *sshagentkms.WrappedSSHSigner:
				a.sshCAHostCertSignKey = s.Sshsigner
			case crypto.Signer:
				a.sshCAHostCertSignKey, err = ssh.NewSignerFromSigner(s)
			default:
				return errors.Errorf("unsupported signer type %T", signer)
			}
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
				Password:   []byte(a.sshUserPassword),
			})
			if err != nil {
				return err
			}
			// If our signer is from sshagentkms, just unwrap it instead of
			// wrapping it in another layer, and this prevents crypto from
			// erroring out with: ssh: unsupported key type *agent.Key
			switch s := signer.(type) {
			case *sshagentkms.WrappedSSHSigner:
				a.sshCAUserCertSignKey = s.Sshsigner
			case crypto.Signer:
				a.sshCAUserCertSignKey, err = ssh.NewSignerFromSigner(s)
			default:
				return errors.Errorf("unsupported signer type %T", signer)
			}
			if err != nil {
				return errors.Wrap(err, "error creating ssh signer")
			}
			// Append public key to list of user certs
			a.sshCAUserCerts = append(a.sshCAUserCerts, a.sshCAUserCertSignKey.PublicKey())
			a.sshCAUserFederatedCerts = append(a.sshCAUserFederatedCerts, a.sshCAUserCertSignKey.PublicKey())
		}

		// Append other public keys and add them to the template variables.
		for _, key := range a.config.SSH.Keys {
			publicKey := key.PublicKey()
			switch key.Type {
			case provisioner.SSHHostCert:
				if key.Federated {
					a.sshCAHostFederatedCerts = append(a.sshCAHostFederatedCerts, publicKey)
				} else {
					a.sshCAHostCerts = append(a.sshCAHostCerts, publicKey)
				}
			case provisioner.SSHUserCert:
				if key.Federated {
					a.sshCAUserFederatedCerts = append(a.sshCAUserFederatedCerts, publicKey)
				} else {
					a.sshCAUserCerts = append(a.sshCAUserCerts, publicKey)
				}
			default:
				return errors.Errorf("unsupported type %s", key.Type)
			}
		}
	}

	// Configure template variables. On the template variables HostFederatedKeys
	// and UserFederatedKeys we will skip the actual CA that will be available
	// in HostKey and UserKey.
	//
	// We cannot do it in the previous blocks because this configuration can be
	// injected using options.
	if a.sshCAHostCertSignKey != nil {
		tmplVars.SSH.HostKey = a.sshCAHostCertSignKey.PublicKey()
		tmplVars.SSH.HostFederatedKeys = append(tmplVars.SSH.HostFederatedKeys, a.sshCAHostFederatedCerts[1:]...)
	} else {
		tmplVars.SSH.HostFederatedKeys = append(tmplVars.SSH.HostFederatedKeys, a.sshCAHostFederatedCerts...)
	}
	if a.sshCAUserCertSignKey != nil {
		tmplVars.SSH.UserKey = a.sshCAUserCertSignKey.PublicKey()
		tmplVars.SSH.UserFederatedKeys = append(tmplVars.SSH.UserFederatedKeys, a.sshCAUserFederatedCerts[1:]...)
	} else {
		tmplVars.SSH.UserFederatedKeys = append(tmplVars.SSH.UserFederatedKeys, a.sshCAUserFederatedCerts...)
	}

	// Check if a KMS with decryption capability is required and available
	if a.requiresDecrypter() {
		if _, ok := a.keyManager.(kmsapi.Decrypter); !ok {
			return errors.New("keymanager doesn't provide crypto.Decrypter")
		}
	}

	// TODO: decide if this is a good approach for providing the SCEP functionality
	// It currently mirrors the logic for the x509CAService
	if a.requiresSCEPService() && a.scepService == nil {
		var options scep.Options

		// Read intermediate and create X509 signer and decrypter for default CAS.
		options.CertificateChain, err = pemutil.ReadCertificateBundle(a.config.IntermediateCert)
		if err != nil {
			return err
		}
		options.CertificateChain = append(options.CertificateChain, a.rootX509Certs...)
		options.Signer, err = a.keyManager.CreateSigner(&kmsapi.CreateSignerRequest{
			SigningKey: a.config.IntermediateKey,
			Password:   []byte(a.password),
		})
		if err != nil {
			return err
		}

		if km, ok := a.keyManager.(kmsapi.Decrypter); ok {
			options.Decrypter, err = km.CreateDecrypter(&kmsapi.CreateDecrypterRequest{
				DecryptionKey: a.config.IntermediateKey,
				Password:      []byte(a.password),
			})
			if err != nil {
				return err
			}
		}

		a.scepService, err = scep.NewService(context.Background(), options)
		if err != nil {
			return err
		}

		// TODO: mimick the x509CAService GetCertificateAuthority here too?
	}

	if a.config.AuthorityConfig.EnableAdmin {
		// Initialize step-ca Admin Database if it's not already initialized using
		// WithAdminDB.
		if a.adminDB == nil {
			if linkedcaClient != nil {
				a.adminDB = linkedcaClient
			} else {
				a.adminDB, err = adminDBNosql.New(a.db.(nosql.DB), admin.DefaultAuthorityID)
				if err != nil {
					return err
				}
			}
		}

		// Initialize the default cache pool.
		if a.cachePool == nil {
			a.cachePool = cache.DefaultPool()
		}

		provs, err := a.adminDB.GetProvisioners(context.Background())
		if err != nil {
			return admin.WrapErrorISE(err, "error loading provisioners to initialize authority")
		}
		if len(provs) == 0 && !strings.EqualFold(a.config.AuthorityConfig.DeploymentType, "linked") {
			// Create First Provisioner
			prov, err := CreateFirstProvisioner(context.Background(), a.adminDB, string(a.password))
			if err != nil {
				return admin.WrapErrorISE(err, "error creating first provisioner")
			}

			// Create first admin
			if err := a.adminDB.CreateAdmin(context.Background(), &linkedca.Admin{
				ProvisionerId: prov.Id,
				Subject:       "step",
				Type:          linkedca.Admin_SUPER_ADMIN,
			}); err != nil {
				return admin.WrapErrorISE(err, "error creating first admin")
			}
		}
	}

	// Load Provisioners and Admins
	if err := a.reloadAdminResources(context.Background()); err != nil {
		return err
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

// GetAdminDatabase returns the admin database, if one exists.
func (a *Authority) GetAdminDatabase() admin.DB {
	return a.adminDB
}

func (a *Authority) GetInfo() Info {
	ai := Info{
		StartTime:     a.startTime,
		RootX509Certs: a.rootX509Certs,
		DNSNames:      a.config.DNSNames,
	}
	if a.sshCAUserCertSignKey != nil {
		ai.SSHCAUserPublicKey = ssh.MarshalAuthorizedKey(a.sshCAUserCertSignKey.PublicKey())
	}
	if a.sshCAHostCertSignKey != nil {
		ai.SSHCAHostPublicKey = ssh.MarshalAuthorizedKey(a.sshCAHostCertSignKey.PublicKey())
	}
	return ai
}

// IsAdminAPIEnabled returns a boolean indicating whether the Admin API has
// been enabled.
func (a *Authority) IsAdminAPIEnabled() bool {
	return a.config.AuthorityConfig.EnableAdmin
}

// Shutdown safely shuts down any clients, databases, etc. held by the Authority.
func (a *Authority) Shutdown() error {
	if err := a.keyManager.Close(); err != nil {
		log.Printf("error closing the key manager: %v", err)
	}
	return a.db.Shutdown()
}

// CloseForReload closes internal services, to allow a safe reload.
func (a *Authority) CloseForReload() {
	if err := a.keyManager.Close(); err != nil {
		log.Printf("error closing the key manager: %v", err)
	}
	if client, ok := a.adminDB.(*linkedCaClient); ok {
		client.Stop()
	}
}

// IsRevoked returns whether or not a certificate has been
// revoked before.
func (a *Authority) IsRevoked(sn string) (bool, error) {
	// Check the passive revocation table.
	if lca, ok := a.adminDB.(interface {
		IsRevoked(string) (bool, error)
	}); ok {
		return lca.IsRevoked(sn)
	}

	return a.db.IsRevoked(sn)
}

// requiresDecrypter returns whether the Authority
// requires a KMS that provides a crypto.Decrypter
// Currently this is only required when SCEP is
// enabled.
func (a *Authority) requiresDecrypter() bool {
	return a.requiresSCEPService()
}

// requiresSCEPService iterates over the configured provisioners
// and determines if one of them is a SCEP provisioner.
func (a *Authority) requiresSCEPService() bool {
	for _, p := range a.config.AuthorityConfig.Provisioners {
		if p.GetType() == provisioner.TypeSCEP {
			return true
		}
	}
	return false
}

// GetSCEPService returns the configured SCEP Service
// TODO: this function is intended to exist temporarily
// in order to make SCEP work more easily. It can be
// made more correct by using the right interfaces/abstractions
// after it works as expected.
func (a *Authority) GetSCEPService() *scep.Service {
	return a.scepService
}
