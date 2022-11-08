package ca

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/pkg/errors"
	"github.com/smallstep/certificates/acme"
	acmeAPI "github.com/smallstep/certificates/acme/api"
	acmeNoSQL "github.com/smallstep/certificates/acme/db/nosql"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/admin"
	adminAPI "github.com/smallstep/certificates/authority/admin/api"
	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/certificates/logging"
	"github.com/smallstep/certificates/monitoring"
	"github.com/smallstep/certificates/scep"
	scepAPI "github.com/smallstep/certificates/scep/api"
	"github.com/smallstep/certificates/server"
	"github.com/smallstep/nosql"
	"go.step.sm/cli-utils/step"
	"go.step.sm/crypto/x509util"
)

type options struct {
	configFile      string
	linkedCAToken   string
	quiet           bool
	password        []byte
	issuerPassword  []byte
	sshHostPassword []byte
	sshUserPassword []byte
	database        db.AuthDB
}

func (o *options) apply(opts []Option) {
	for _, fn := range opts {
		fn(o)
	}
}

// Option is the type of options passed to the CA constructor.
type Option func(o *options)

// WithConfigFile sets the given name as the configuration file name in the CA
// options.
func WithConfigFile(name string) Option {
	return func(o *options) {
		o.configFile = name
	}
}

// WithPassword sets the given password as the configured password in the CA
// options.
func WithPassword(password []byte) Option {
	return func(o *options) {
		o.password = password
	}
}

// WithSSHHostPassword sets the given password to decrypt the key used to sign
// ssh host certificates.
func WithSSHHostPassword(password []byte) Option {
	return func(o *options) {
		o.sshHostPassword = password
	}
}

// WithSSHUserPassword sets the given password to decrypt the key used to sign
// ssh user certificates.
func WithSSHUserPassword(password []byte) Option {
	return func(o *options) {
		o.sshUserPassword = password
	}
}

// WithIssuerPassword sets the given password as the configured certificate
// issuer password in the CA options.
func WithIssuerPassword(password []byte) Option {
	return func(o *options) {
		o.issuerPassword = password
	}
}

// WithDatabase sets the given authority database to the CA options.
func WithDatabase(d db.AuthDB) Option {
	return func(o *options) {
		o.database = d
	}
}

// WithLinkedCAToken sets the token used to authenticate with the linkedca.
func WithLinkedCAToken(token string) Option {
	return func(o *options) {
		o.linkedCAToken = token
	}
}

// WithQuiet sets the quiet flag.
func WithQuiet(quiet bool) Option {
	return func(o *options) {
		o.quiet = quiet
	}
}

// CA is the type used to build the complete certificate authority. It builds
// the HTTP server, set ups the middlewares and the HTTP handlers.
type CA struct {
	auth        *authority.Authority
	config      *config.Config
	srv         *server.Server
	insecureSrv *server.Server
	opts        *options
	renewer     *TLSRenewer
}

// New creates and initializes the CA with the given configuration and options.
func New(cfg *config.Config, opts ...Option) (*CA, error) {
	ca := &CA{
		config: cfg,
		opts:   new(options),
	}
	ca.opts.apply(opts)
	return ca.Init(cfg)
}

// Init initializes the CA with the given configuration.
func (ca *CA) Init(cfg *config.Config) (*CA, error) {
	// Set password, it's ok to set nil password, the ca will prompt for them if
	// they are required.
	opts := []authority.Option{
		authority.WithPassword(ca.opts.password),
		authority.WithSSHHostPassword(ca.opts.sshHostPassword),
		authority.WithSSHUserPassword(ca.opts.sshUserPassword),
		authority.WithIssuerPassword(ca.opts.issuerPassword),
	}
	if ca.opts.linkedCAToken != "" {
		opts = append(opts, authority.WithLinkedCAToken(ca.opts.linkedCAToken))
	}

	if ca.opts.database != nil {
		opts = append(opts, authority.WithDatabase(ca.opts.database))
	}

	if ca.opts.quiet {
		opts = append(opts, authority.WithQuietInit())
	}

	webhookTransport := http.DefaultTransport.(*http.Transport).Clone()
	opts = append(opts, authority.WithWebhookClient(&http.Client{Transport: webhookTransport}))

	auth, err := authority.New(cfg, opts...)
	if err != nil {
		return nil, err
	}
	ca.auth = auth

	tlsConfig, clientTLSConfig, err := ca.getTLSConfig(auth)
	if err != nil {
		return nil, err
	}

	webhookTransport.TLSClientConfig = clientTLSConfig

	// Using chi as the main router
	mux := chi.NewRouter()
	handler := http.Handler(mux)

	insecureMux := chi.NewRouter()
	insecureHandler := http.Handler(insecureMux)

	// Add HEAD middleware
	mux.Use(middleware.GetHead)
	insecureMux.Use(middleware.GetHead)

	// Add regular CA api endpoints in / and /1.0
	api.Route(mux)
	mux.Route("/1.0", func(r chi.Router) {
		api.Route(r)
	})

	//Add ACME api endpoints in /acme and /1.0/acme
	dns := cfg.DNSNames[0]
	u, err := url.Parse("https://" + cfg.Address)
	if err != nil {
		return nil, err
	}
	port := u.Port()
	if port != "" && port != "443" {
		dns = fmt.Sprintf("%s:%s", dns, port)
	}

	// ACME Router is only available if we have a database.
	var acmeDB acme.DB
	var acmeLinker acme.Linker
	if cfg.DB != nil {
		acmeDB, err = acmeNoSQL.New(auth.GetDatabase().(nosql.DB))
		if err != nil {
			return nil, errors.Wrap(err, "error configuring ACME DB interface")
		}
		acmeLinker = acme.NewLinker(dns, "acme")
		mux.Route("/acme", func(r chi.Router) {
			acmeAPI.Route(r)
		})
		// Use 2.0 because, at the moment, our ACME api is only compatible with v2.0
		// of the ACME spec.
		mux.Route("/2.0/acme", func(r chi.Router) {
			acmeAPI.Route(r)
		})
	}

	// Admin API Router
	if cfg.AuthorityConfig.EnableAdmin {
		adminDB := auth.GetAdminDatabase()
		if adminDB != nil {
			acmeAdminResponder := adminAPI.NewACMEAdminResponder()
			policyAdminResponder := adminAPI.NewPolicyAdminResponder()
			webhookAdminResponder := adminAPI.NewWebhookAdminResponder()
			mux.Route("/admin", func(r chi.Router) {
				adminAPI.Route(
					r,
					adminAPI.WithACMEResponder(acmeAdminResponder),
					adminAPI.WithPolicyResponder(policyAdminResponder),
					adminAPI.WithWebhookResponder(webhookAdminResponder),
				)
			})
		}
	}

	var scepAuthority *scep.Authority
	if ca.shouldServeSCEPEndpoints() {
		scepPrefix := "scep"
		scepAuthority, err = scep.New(auth, scep.AuthorityOptions{
			Service: auth.GetSCEPService(),
			DNS:     dns,
			Prefix:  scepPrefix,
		})
		if err != nil {
			return nil, errors.Wrap(err, "error creating SCEP authority")
		}

		// According to the RFC (https://tools.ietf.org/html/rfc8894#section-7.10),
		// SCEP operations are performed using HTTP, so that's why the API is mounted
		// to the insecure mux.
		insecureMux.Route("/"+scepPrefix, func(r chi.Router) {
			scepAPI.Route(r)
		})

		// The RFC also mentions usage of HTTPS, but seems to advise
		// against it, because of potential interoperability issues.
		// Currently I think it's not bad to use HTTPS also, so that's
		// why I've kept the API endpoints in both muxes and both HTTP
		// as well as HTTPS can be used to request certificates
		// using SCEP.
		mux.Route("/"+scepPrefix, func(r chi.Router) {
			scepAPI.Route(r)
		})
	}

	// helpful routine for logging all routes
	//dumpRoutes(mux)

	// Add monitoring if configured
	if len(cfg.Monitoring) > 0 {
		m, err := monitoring.New(cfg.Monitoring)
		if err != nil {
			return nil, err
		}
		handler = m.Middleware(handler)
		insecureHandler = m.Middleware(insecureHandler)
	}

	// Add logger if configured
	if len(cfg.Logger) > 0 {
		logger, err := logging.New("ca", cfg.Logger)
		if err != nil {
			return nil, err
		}
		handler = logger.Middleware(handler)
		insecureHandler = logger.Middleware(insecureHandler)
	}

	// Create context with all the necessary values.
	baseContext := buildContext(auth, scepAuthority, acmeDB, acmeLinker)

	ca.srv = server.New(cfg.Address, handler, tlsConfig)
	ca.srv.BaseContext = func(net.Listener) context.Context {
		return baseContext
	}

	// only start the insecure server if the insecure address is configured
	// and, currently, also only when it should serve SCEP endpoints.
	if ca.shouldServeSCEPEndpoints() && cfg.InsecureAddress != "" {
		// TODO: instead opt for having a single server.Server but two
		// http.Servers handling the HTTP and HTTPS handler? The latter
		// will probably introduce more complexity in terms of graceful
		// reload.
		ca.insecureSrv = server.New(cfg.InsecureAddress, insecureHandler, nil)
		ca.insecureSrv.BaseContext = func(net.Listener) context.Context {
			return baseContext
		}
	}

	return ca, nil
}

// buildContext builds the server base context.
func buildContext(a *authority.Authority, scepAuthority *scep.Authority, acmeDB acme.DB, acmeLinker acme.Linker) context.Context {
	ctx := authority.NewContext(context.Background(), a)
	if authDB := a.GetDatabase(); authDB != nil {
		ctx = db.NewContext(ctx, authDB)
	}
	if adminDB := a.GetAdminDatabase(); adminDB != nil {
		ctx = admin.NewContext(ctx, adminDB)
	}
	if scepAuthority != nil {
		ctx = scep.NewContext(ctx, scepAuthority)
	}
	if acmeDB != nil {
		ctx = acme.NewContext(ctx, acmeDB, acme.NewClient(), acmeLinker, nil)
	}
	return ctx
}

// Run starts the CA calling to the server ListenAndServe method.
func (ca *CA) Run() error {
	var wg sync.WaitGroup
	errs := make(chan error, 1)

	if !ca.opts.quiet {
		authorityInfo := ca.auth.GetInfo()
		log.Printf("Starting %s", step.Version())
		log.Printf("Documentation: https://u.step.sm/docs/ca")
		log.Printf("Community Discord: https://u.step.sm/discord")
		if step.Contexts().GetCurrent() != nil {
			log.Printf("Current context: %s", step.Contexts().GetCurrent().Name)
		}
		log.Printf("Config file: %s", ca.getConfigFileOutput())
		baseURL := fmt.Sprintf("https://%s%s",
			authorityInfo.DNSNames[0],
			ca.config.Address[strings.LastIndex(ca.config.Address, ":"):])
		log.Printf("The primary server URL is %s", baseURL)
		log.Printf("Root certificates are available at %s/roots.pem", baseURL)
		if len(authorityInfo.DNSNames) > 1 {
			log.Printf("Additional configured hostnames: %s",
				strings.Join(authorityInfo.DNSNames[1:], ", "))
		}
		for _, crt := range authorityInfo.RootX509Certs {
			log.Printf("X.509 Root Fingerprint: %s", x509util.Fingerprint(crt))
		}
		if authorityInfo.SSHCAHostPublicKey != nil {
			log.Printf("SSH Host CA Key: %s\n", bytes.TrimSpace(authorityInfo.SSHCAHostPublicKey))
		}
		if authorityInfo.SSHCAUserPublicKey != nil {
			log.Printf("SSH User CA Key: %s\n", bytes.TrimSpace(authorityInfo.SSHCAUserPublicKey))
		}
	}

	if ca.insecureSrv != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- ca.insecureSrv.ListenAndServe()
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		errs <- ca.srv.ListenAndServe()
	}()

	// wait till error occurs; ensures the servers keep listening
	err := <-errs

	wg.Wait()

	return err
}

// Stop stops the CA calling to the server Shutdown method.
func (ca *CA) Stop() error {
	ca.renewer.Stop()
	if err := ca.auth.Shutdown(); err != nil {
		log.Printf("error stopping ca.Authority: %+v\n", err)
	}
	var insecureShutdownErr error
	if ca.insecureSrv != nil {
		insecureShutdownErr = ca.insecureSrv.Shutdown()
	}

	secureErr := ca.srv.Shutdown()

	if insecureShutdownErr != nil {
		return insecureShutdownErr
	}
	return secureErr
}

// Reload reloads the configuration of the CA and calls to the server Reload
// method.
func (ca *CA) Reload() error {
	cfg, err := config.LoadConfiguration(ca.opts.configFile)
	if err != nil {
		return errors.Wrap(err, "error reloading ca configuration")
	}

	logContinue := func(reason string) {
		log.Println(reason)
		log.Println("Continuing to run with the original configuration.")
		log.Println("You can force a restart by sending a SIGTERM signal and then restarting the step-ca.")
	}

	// Do not allow reload if the database configuration has changed.
	if !reflect.DeepEqual(ca.config.DB, cfg.DB) {
		logContinue("Reload failed because the database configuration has changed.")
		return errors.New("error reloading ca: database configuration cannot change")
	}

	newCA, err := New(cfg,
		WithPassword(ca.opts.password),
		WithSSHHostPassword(ca.opts.sshHostPassword),
		WithSSHUserPassword(ca.opts.sshUserPassword),
		WithIssuerPassword(ca.opts.issuerPassword),
		WithLinkedCAToken(ca.opts.linkedCAToken),
		WithQuiet(ca.opts.quiet),
		WithConfigFile(ca.opts.configFile),
		WithDatabase(ca.auth.GetDatabase()),
	)
	if err != nil {
		logContinue("Reload failed because the CA with new configuration could not be initialized.")
		return errors.Wrap(err, "error reloading ca")
	}

	if ca.insecureSrv != nil {
		if err = ca.insecureSrv.Reload(newCA.insecureSrv); err != nil {
			logContinue("Reload failed because insecure server could not be replaced.")
			return errors.Wrap(err, "error reloading insecure server")
		}
	}

	if err = ca.srv.Reload(newCA.srv); err != nil {
		logContinue("Reload failed because server could not be replaced.")
		return errors.Wrap(err, "error reloading server")
	}

	// 1. Stop previous renewer
	// 2. Safely shutdown any internal resources (e.g. key manager)
	// 3. Replace ca properties
	// Do not replace ca.srv
	ca.renewer.Stop()
	ca.auth.CloseForReload()
	ca.auth = newCA.auth
	ca.config = newCA.config
	ca.opts = newCA.opts
	ca.renewer = newCA.renewer
	return nil
}

// get TLSConfig returns separate TLSConfigs for server and client with the
// same self-renewing certificate.
func (ca *CA) getTLSConfig(auth *authority.Authority) (*tls.Config, *tls.Config, error) {
	// Create initial TLS certificate
	tlsCrt, err := auth.GetTLSCertificate()
	if err != nil {
		return nil, nil, err
	}

	// Start tls renewer with the new certificate.
	// If a renewer was started, attempt to stop it before.
	if ca.renewer != nil {
		ca.renewer.Stop()
	}

	ca.renewer, err = NewTLSRenewer(tlsCrt, auth.GetTLSCertificate)
	if err != nil {
		return nil, nil, err
	}
	ca.renewer.Run()

	var serverTLSConfig *tls.Config
	if ca.config.TLS != nil {
		serverTLSConfig = ca.config.TLS.TLSConfig()
	} else {
		serverTLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}

	// GetCertificate will only be called if the client supplies SNI
	// information or if tlsConfig.Certificates is empty.
	// When client requests are made using an IP address (as opposed to a domain
	// name) the server does not receive any SNI and may fallback to using the
	// first entry in the Certificates attribute; by setting the attribute to
	// empty we are implicitly forcing GetCertificate to be the only mechanism
	// by which the server can find it's own leaf Certificate.
	serverTLSConfig.Certificates = []tls.Certificate{}

	clientTLSConfig := serverTLSConfig.Clone()

	serverTLSConfig.GetCertificate = ca.renewer.GetCertificateForCA
	clientTLSConfig.GetClientCertificate = ca.renewer.GetClientCertificate

	// initialize a certificate pool with root CA certificates to trust when doing mTLS.
	certPool := x509.NewCertPool()
	// initialize a certificate pool with root CA certificates to trust when connecting
	// to webhook servers
	rootCAsPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, nil, err
	}
	for _, crt := range auth.GetRootCertificates() {
		certPool.AddCert(crt)
		rootCAsPool.AddCert(crt)
	}

	// adding the intermediate CA certificates to the pool will allow clients that
	// do mTLS but don't send an intermediate to successfully connect. The intermediates
	// added here are used when building a certificate chain.
	intermediates := tlsCrt.Certificate[1:]
	for _, certBytes := range intermediates {
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, nil, err
		}
		certPool.AddCert(cert)
		rootCAsPool.AddCert(cert)
	}

	// Add support for mutual tls to renew certificates
	serverTLSConfig.ClientAuth = tls.VerifyClientCertIfGiven
	serverTLSConfig.ClientCAs = certPool

	clientTLSConfig.RootCAs = rootCAsPool

	return serverTLSConfig, clientTLSConfig, nil
}

// shouldServeSCEPEndpoints returns if the CA should be
// configured with endpoints for SCEP. This is assumed to be
// true if a SCEPService exists, which is true in case a
// SCEP provisioner was configured.
func (ca *CA) shouldServeSCEPEndpoints() bool {
	return ca.auth.GetSCEPService() != nil
}

//nolint:unused // useful for debugging
func dumpRoutes(mux chi.Routes) {
	// helpful routine for logging all routes
	walkFunc := func(method string, route string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		fmt.Printf("%s %s\n", method, route)
		return nil
	}
	if err := chi.Walk(mux, walkFunc); err != nil {
		fmt.Printf("Logging err: %s\n", err.Error())
	}
}

func (ca *CA) getConfigFileOutput() string {
	if ca.config.WasLoadedFromFile() {
		return ca.config.Filepath()
	}
	return "loaded from token"
}
