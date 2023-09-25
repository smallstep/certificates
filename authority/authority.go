package authority

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"

	"go.step.sm/crypto/kms"
	kmsapi "go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/sshagentkms"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/linkedca"

	"github.com/smallstep/certificates/authority/admin"
	adminDBNosql "github.com/smallstep/certificates/authority/admin/db/nosql"
	"github.com/smallstep/certificates/authority/administrator"
	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/internal/constraints"
	"github.com/smallstep/certificates/authority/policy"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/cas"
	casapi "github.com/smallstep/certificates/cas/apiv1"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/certificates/scep"
	"github.com/smallstep/certificates/templates"
	"github.com/smallstep/nosql"
)

// Authority implements the Certificate Authority internal interface.
type Authority struct {
	config        *config.Config
	keyManager    kms.KeyManager
	provisioners  *provisioner.Collection
	admins        *administrator.Collection
	db            db.AuthDB
	adminDB       admin.DB
	templates     *templates.Templates
	linkedCAToken string
	webhookClient *http.Client

	// X509 CA
	password              []byte
	issuerPassword        []byte
	x509CAService         cas.CertificateAuthorityService
	rootX509Certs         []*x509.Certificate
	rootX509CertPool      *x509.CertPool
	federatedX509Certs    []*x509.Certificate
	intermediateX509Certs []*x509.Certificate
	certificates          *sync.Map
	x509Enforcers         []provisioner.CertificateEnforcer

	// SCEP CA
	scepOptions   *scep.Options
	validateSCEP  bool
	scepAuthority *scep.Authority

	// SSH CA
	sshHostPassword         []byte
	sshUserPassword         []byte
	sshCAUserCertSignKey    ssh.Signer
	sshCAHostCertSignKey    ssh.Signer
	sshCAUserCerts          []ssh.PublicKey
	sshCAHostCerts          []ssh.PublicKey
	sshCAUserFederatedCerts []ssh.PublicKey
	sshCAHostFederatedCerts []ssh.PublicKey

	// CRL vars
	crlTicker  *time.Ticker
	crlStopper chan struct{}
	crlMutex   sync.Mutex

	// If true, do not re-initialize
	initOnce  bool
	startTime time.Time

	// Custom functions
	sshBastionFunc        func(ctx context.Context, user, hostname string) (*config.Bastion, error)
	sshCheckHostFunc      func(ctx context.Context, principal string, tok string, roots []*x509.Certificate) (bool, error)
	sshGetHostsFunc       func(ctx context.Context, cert *x509.Certificate) ([]config.Host, error)
	getIdentityFunc       provisioner.GetIdentityFunc
	authorizeRenewFunc    provisioner.AuthorizeRenewFunc
	authorizeSSHRenewFunc provisioner.AuthorizeSSHRenewFunc

	// Constraints and Policy engines
	constraintsEngine *constraints.Engine
	policyEngine      *policy.Engine

	adminMutex sync.RWMutex

	// If true, do not initialize the authority
	skipInit bool

	// If true, do not output initialization logs
	quietInit bool
}

// Info contains information about the authority.
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
		validateSCEP: true,
	}

	// Apply options.
	for _, fn := range opts {
		if err := fn(a); err != nil {
			return nil, err
		}
	}

	if !a.skipInit {
		// Initialize authority from options or configuration.
		if err := a.init(); err != nil {
			return nil, err
		}
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

	if !a.skipInit {
		// Initialize authority from options or configuration.
		if err := a.init(); err != nil {
			return nil, err
		}
	}

	return a, nil
}

type authorityKey struct{}

// NewContext adds the given authority to the context.
func NewContext(ctx context.Context, a *Authority) context.Context {
	return context.WithValue(ctx, authorityKey{}, a)
}

// FromContext returns the current authority from the given context.
func FromContext(ctx context.Context) (a *Authority, ok bool) {
	a, ok = ctx.Value(authorityKey{}).(*Authority)
	return
}

// MustFromContext returns the current authority from the given context. It will
// panic if the authority is not in the context.
func MustFromContext(ctx context.Context) *Authority {
	if a, ok := FromContext(ctx); !ok {
		panic("authority is not in the context")
	} else {
		return a
	}
}

// ReloadAdminResources reloads admins and provisioners from the DB.
func (a *Authority) ReloadAdminResources(ctx context.Context) error {
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
	provClxn := provisioner.NewCollection(provisionerConfig.Audiences)
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

	switch {
	case a.requiresSCEP() && a.GetSCEP() == nil:
		// TODO(hs): try to initialize SCEP here too? It's a bit
		// problematic if this method is called as part of an update
		// via Admin API and a password needs to be provided.
	case a.requiresSCEP() && a.GetSCEP() != nil:
		// update the SCEP Authority with the currently active SCEP
		// provisioner names and revalidate the configuration.
		a.scepAuthority.UpdateProvisioners(a.getSCEPProvisionerNames())
		if err := a.scepAuthority.Validate(); err != nil {
			log.Printf("failed validating SCEP authority: %v\n", err)
		}
	case !a.requiresSCEP() && a.GetSCEP() != nil:
		// TODO(hs): don't remove the authority if we can't also
		// reload it.
		//a.scepAuthority = nil
	}

	return nil
}

// init performs validation and initializes the fields of an Authority struct.
func (a *Authority) init() error {
	// Check if handler has already been validated/initialized.
	if a.initOnce {
		return nil
	}

	var err error
	ctx := NewContext(context.Background(), a)

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
		a.keyManager, err = kms.New(ctx, options)
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
		a.config.AuthorityConfig.AuthorityID = linkedcaClient.authorityID
		linkedcaClient.Run()
	}

	// Initialize the X.509 CA Service if it has not been set in the options.
	if a.x509CAService == nil {
		var options casapi.Options
		if a.config.AuthorityConfig.Options != nil {
			options = *a.config.AuthorityConfig.Options
		}

		// AuthorityID might be empty. It's always available linked CAs/RAs.
		options.AuthorityID = a.config.AuthorityConfig.AuthorityID

		// Configure linked RA
		if linkedcaClient != nil && options.CertificateAuthority == "" {
			conf, err := linkedcaClient.GetConfiguration(ctx)
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
				// Configure the RA authority type if needed
				if options.Type == "" {
					options.Type = casapi.StepCAS
				}
			}
			// Remote configuration is currently only supported on a linked RA
			if sc := conf.ServerConfig; sc != nil {
				if a.config.Address == "" {
					a.config.Address = sc.Address
				}
				if len(a.config.DNSNames) == 0 {
					a.config.DNSNames = sc.DnsNames
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
				Password:   a.password,
			})
			if err != nil {
				return err
			}
			// If not defined with an option, add intermediates to the list of
			// certificates used for name constraints validation at issuance
			// time.
			if len(a.intermediateX509Certs) == 0 {
				a.intermediateX509Certs = append(a.intermediateX509Certs, options.CertificateChain...)
			}
		}
		a.x509CAService, err = cas.New(ctx, options)
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
		a.rootX509Certs = make([]*x509.Certificate, 0, len(a.config.Root))
		for _, path := range a.config.Root {
			crts, err := pemutil.ReadCertificateBundle(path)
			if err != nil {
				return err
			}
			a.rootX509Certs = append(a.rootX509Certs, crts...)
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
		a.federatedX509Certs = make([]*x509.Certificate, 0, len(a.config.FederatedRoots))
		for _, path := range a.config.FederatedRoots {
			crts, err := pemutil.ReadCertificateBundle(path)
			if err != nil {
				return err
			}
			a.federatedX509Certs = append(a.federatedX509Certs, crts...)
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
				Password:   a.sshHostPassword,
			})
			if err != nil {
				return err
			}
			// If our signer is from sshagentkms, just unwrap it instead of
			// wrapping it in another layer, and this prevents crypto from
			// erroring out with: ssh: unsupported key type *agent.Key
			switch s := signer.(type) {
			case *sshagentkms.WrappedSSHSigner:
				a.sshCAHostCertSignKey = s.Signer
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
				Password:   a.sshUserPassword,
			})
			if err != nil {
				return err
			}
			// If our signer is from sshagentkms, just unwrap it instead of
			// wrapping it in another layer, and this prevents crypto from
			// erroring out with: ssh: unsupported key type *agent.Key
			switch s := signer.(type) {
			case *sshagentkms.WrappedSSHSigner:
				a.sshCAUserCertSignKey = s.Signer
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

		provs, err := a.adminDB.GetProvisioners(ctx)
		if err != nil {
			return admin.WrapErrorISE(err, "error loading provisioners to initialize authority")
		}
		if len(provs) == 0 && !strings.EqualFold(a.config.AuthorityConfig.DeploymentType, "linked") {
			// Migration will currently only be kicked off once, because either one or more provisioners
			// are migrated or a default JWK provisioner will be created in the DB. It won't run for
			// linked or hosted deployments. Not for linked, because that case is explicitly checked
			// for above. Not for hosted, because there'll be at least an existing OIDC provisioner.
			var firstJWKProvisioner *linkedca.Provisioner
			if len(a.config.AuthorityConfig.Provisioners) > 0 {
				// Existing provisioners detected; try migrating them to DB storage.
				a.initLogf("Starting migration of provisioners")
				for _, p := range a.config.AuthorityConfig.Provisioners {
					lp, err := ProvisionerToLinkedca(p)
					if err != nil {
						return admin.WrapErrorISE(err, "error transforming provisioner %q while migrating", p.GetName())
					}

					// Store the provisioner to be migrated
					if err := a.adminDB.CreateProvisioner(ctx, lp); err != nil {
						return admin.WrapErrorISE(err, "error creating provisioner %q while migrating", p.GetName())
					}

					// Mark the first JWK provisioner, so that it can be used for administration purposes
					if firstJWKProvisioner == nil && lp.Type == linkedca.Provisioner_JWK {
						firstJWKProvisioner = lp
						a.initLogf("Migrated JWK provisioner %q with admin permissions", p.GetName())
					} else {
						a.initLogf("Migrated %s provisioner %q", p.GetType(), p.GetName())
					}
				}

				c := a.config
				if c.WasLoadedFromFile() {
					// The provisioners in the configuration file can be deleted from
					// the file by editing it. Automatic rewriting of the file was considered
					// to be too surprising for users and not the right solution for all
					// use cases, so we leave it up to users to this themselves.
					a.initLogf("Provisioners that were migrated can now be removed from `ca.json` by editing it")
				}

				a.initLogf("Finished migrating provisioners")
			}

			// Create first JWK provisioner for remote administration purposes if none exists yet
			if firstJWKProvisioner == nil {
				firstJWKProvisioner, err = CreateFirstProvisioner(ctx, a.adminDB, string(a.password))
				if err != nil {
					return admin.WrapErrorISE(err, "error creating first provisioner")
				}
				a.initLogf("Created JWK provisioner %q with admin permissions", firstJWKProvisioner.GetName())
			}

			// Create first super admin, belonging to the first JWK provisioner
			// TODO(hs): pass a user-provided first super admin subject to here. With `ca init` it's
			// added to the DB immediately if using remote management. But when migrating from
			// ca.json to the DB, this option doesn't exist. Adding a flag just to do it during
			// migration isn't nice. We could opt for a user to change it afterwards. There exist
			// cases in which creation of `step` could lock out a user from API access. This is the
			// case if `step` isn't allowed to be signed by Name Constraints or the X.509 policy.
			// We have protection for that when creating and updating a policy, but if a policy or
			// Name Constraints are in use at the time of migration, that could lock the user out.
			superAdminSubject := "step"
			if err := a.adminDB.CreateAdmin(ctx, &linkedca.Admin{
				ProvisionerId: firstJWKProvisioner.Id,
				Subject:       superAdminSubject,
				Type:          linkedca.Admin_SUPER_ADMIN,
			}); err != nil {
				return admin.WrapErrorISE(err, "error creating first admin")
			}

			a.initLogf("Created super admin %q for JWK provisioner %q", superAdminSubject, firstJWKProvisioner.GetName())
		}
	}

	// Load Provisioners and Admins
	if err := a.ReloadAdminResources(ctx); err != nil {
		return err
	}

	// The SCEP functionality is provided through an instance of
	// scep.Authority. It is initialized when the CA is started and
	// if it doesn't exist yet. It gets refreshed if it already
	// exists. If the SCEP authority is no longer required on reload,
	// it gets removed.
	// TODO(hs): reloading through SIGHUP doesn't hit these cases. This
	// is because an entirely new authority.Authority is created, including
	// a new scep.Authority. Look into this to see if we want this to
	// keep working like that, or want to reuse a single instance and
	// update that.
	switch {
	case a.requiresSCEP() && a.GetSCEP() == nil:
		if a.scepOptions == nil {
			options := &scep.Options{
				Roots:         a.rootX509Certs,
				Intermediates: a.intermediateX509Certs,
				SignerCert:    a.intermediateX509Certs[0],
			}
			if options.Signer, err = a.keyManager.CreateSigner(&kmsapi.CreateSignerRequest{
				SigningKey: a.config.IntermediateKey,
				Password:   a.password,
			}); err != nil {
				return err
			}
			// TODO(hs): instead of creating the decrypter here, pass the
			// intermediate key + chain down to the SCEP authority,
			// and only instantiate it when required there. Is that possible?
			// Also with entering passwords?
			// TODO(hs): if moving the logic, try improving the logic for the
			// decrypter password too? Right now it needs to be entered multiple
			// times; I've observed it to be three times maximum, every time
			// the intermediate key is read.
			_, isRSA := options.Signer.Public().(*rsa.PublicKey)
			if km, ok := a.keyManager.(kmsapi.Decrypter); ok && isRSA {
				if decrypter, err := km.CreateDecrypter(&kmsapi.CreateDecrypterRequest{
					DecryptionKey: a.config.IntermediateKey,
					Password:      a.password,
				}); err == nil {
					// only pass the decrypter down when it was successfully created,
					// meaning it's an RSA key, and `CreateDecrypter` did not fail.
					options.Decrypter = decrypter
					options.DecrypterCert = options.Intermediates[0]
				}
			}

			a.scepOptions = options
		}

		// provide the current SCEP provisioner names, so that the provisioners
		// can be validated when the CA is started.
		a.scepOptions.SCEPProvisionerNames = a.getSCEPProvisionerNames()

		// create a new SCEP authority
		scepAuthority, err := scep.New(a, *a.scepOptions)
		if err != nil {
			return err
		}

		if a.validateSCEP {
			// validate the SCEP authority
			if err := scepAuthority.Validate(); err != nil {
				a.initLogf("failed validating SCEP authority: %v", err)
			}
		}

		// set the SCEP authority
		a.scepAuthority = scepAuthority
	case !a.requiresSCEP() && a.GetSCEP() != nil:
		// clear the SCEP authority if it's no longer required
		a.scepAuthority = nil
	case a.requiresSCEP() && a.GetSCEP() != nil:
		// update the SCEP Authority with the currently active SCEP
		// provisioner names and revalidate the configuration.
		a.scepAuthority.UpdateProvisioners(a.getSCEPProvisionerNames())
		if err := a.scepAuthority.Validate(); err != nil {
			log.Printf("failed validating SCEP authority: %v\n", err)
		}
	}

	// Load X509 constraints engine.
	//
	// This is currently only available in CA mode.
	if size := len(a.intermediateX509Certs); size > 0 {
		last := a.intermediateX509Certs[size-1]
		constraintCerts := make([]*x509.Certificate, 0, size+1)
		constraintCerts = append(constraintCerts, a.intermediateX509Certs...)
		for _, root := range a.rootX509Certs {
			if bytes.Equal(last.RawIssuer, root.RawSubject) && bytes.Equal(last.AuthorityKeyId, root.SubjectKeyId) {
				constraintCerts = append(constraintCerts, root)
			}
		}
		a.constraintsEngine = constraints.New(constraintCerts...)
	}

	// Load x509 and SSH Policy Engines
	if err := a.reloadPolicyEngines(ctx); err != nil {
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

	// Start the CRL generator, we can assume the configuration is validated.
	if a.config.CRL.IsEnabled() {
		// Default cache duration to the default one
		if v := a.config.CRL.CacheDuration; v == nil || v.Duration <= 0 {
			a.config.CRL.CacheDuration = config.DefaultCRLCacheDuration
		}
		// Start CRL generator
		if err := a.startCRLGenerator(); err != nil {
			return err
		}
	}

	// JWT numeric dates are seconds.
	a.startTime = time.Now().Truncate(time.Second)
	// Set flag indicating that initialization has been completed, and should
	// not be repeated.
	a.initOnce = true

	return nil
}

// initLogf is used to log initialization information. The output
// can be disabled by starting the CA with the `--quiet` flag.
func (a *Authority) initLogf(format string, v ...any) {
	if !a.quietInit {
		log.Printf(format, v...)
	}
}

// GetID returns the define authority id or a zero uuid.
func (a *Authority) GetID() string {
	const zeroUUID = "00000000-0000-0000-0000-000000000000"
	if id := a.config.AuthorityConfig.AuthorityID; id != "" {
		return id
	}
	return zeroUUID
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

// GetConfig returns the config.
func (a *Authority) GetConfig() *config.Config {
	return a.config
}

// GetInfo returns information about the authority.
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
	if a.crlTicker != nil {
		a.crlTicker.Stop()
		close(a.crlStopper)
	}

	if err := a.keyManager.Close(); err != nil {
		log.Printf("error closing the key manager: %v", err)
	}
	return a.db.Shutdown()
}

// CloseForReload closes internal services, to allow a safe reload.
func (a *Authority) CloseForReload() {
	if a.crlTicker != nil {
		a.crlTicker.Stop()
		close(a.crlStopper)
	}

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

// requiresSCEP iterates over the configured provisioners
// and determines if at least one of them is a SCEP provisioner.
func (a *Authority) requiresSCEP() bool {
	for _, p := range a.config.AuthorityConfig.Provisioners {
		if p.GetType() == provisioner.TypeSCEP {
			return true
		}
	}
	return false
}

// getSCEPProvisionerNames returns the names of the SCEP provisioners
// that are currently available in the CA.
func (a *Authority) getSCEPProvisionerNames() (names []string) {
	for _, p := range a.config.AuthorityConfig.Provisioners {
		if p.GetType() == provisioner.TypeSCEP {
			names = append(names, p.GetName())
		}
	}

	return
}

// GetSCEP returns the configured SCEP Authority
func (a *Authority) GetSCEP() *scep.Authority {
	return a.scepAuthority
}

func (a *Authority) startCRLGenerator() error {
	if !a.config.CRL.IsEnabled() {
		return nil
	}

	// Check that there is a valid CRL in the DB right now. If it doesn't exist
	// or is expired, generate one now
	_, ok := a.db.(db.CertificateRevocationListDB)
	if !ok {
		return errors.Errorf("CRL Generation requested, but database does not support CRL generation")
	}

	// Always create a new CRL on startup in case the CA has been down and the
	// time to next expected CRL update is less than the cache duration.
	if err := a.GenerateCertificateRevocationList(); err != nil {
		return errors.Wrap(err, "could not generate a CRL")
	}

	a.crlStopper = make(chan struct{}, 1)
	a.crlTicker = time.NewTicker(a.config.CRL.TickerDuration())

	go func() {
		for {
			select {
			case <-a.crlTicker.C:
				log.Println("Regenerating CRL")
				if err := a.GenerateCertificateRevocationList(); err != nil {
					log.Printf("error regenerating the CRL: %v", err)
				}
			case <-a.crlStopper:
				return
			}
		}
	}()

	return nil
}
