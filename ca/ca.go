package ca

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/pkg/errors"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/logging"
	"github.com/smallstep/certificates/monitoring"
	"github.com/smallstep/certificates/server"
)

type options struct {
	configFile string
	password   []byte
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

// CA is the type used to build the complete certificate authority. It builds
// the HTTP server, set ups the middlewares and the HTTP handlers.
type CA struct {
	auth    *authority.Authority
	config  *authority.Config
	srv     *server.Server
	opts    *options
	renewer *TLSRenewer
}

// New creates and initializes the CA with the given configuration and options.
func New(config *authority.Config, opts ...Option) (*CA, error) {
	ca := &CA{
		config: config,
		opts:   new(options),
	}
	ca.opts.apply(opts)
	return ca.Init(config)
}

// Init initializes the CA with the given configuration.
func (ca *CA) Init(config *authority.Config) (*CA, error) {
	if l := len(ca.opts.password); l > 0 {
		ca.config.Password = string(ca.opts.password)
	}

	auth, err := authority.New(config)
	if err != nil {
		return nil, err
	}

	tlsConfig, err := ca.getTLSConfig(auth)
	if err != nil {
		return nil, err
	}

	// Using chi as the main router
	mux := chi.NewRouter()
	handler := http.Handler(mux)

	// Add api endpoints in / and /1.0
	routerHandler := api.New(auth)
	routerHandler.Route(mux)
	mux.Route("/1.0", func(r chi.Router) {
		routerHandler.Route(r)
	})

	// Add monitoring if configured
	if len(config.Monitoring) > 0 {
		m, err := monitoring.New(config.Monitoring)
		if err != nil {
			return nil, err
		}
		handler = m.Middleware(handler)
	}

	// Add logger if configured
	if len(config.Logger) > 0 {
		logger, err := logging.New("ca", config.Logger)
		if err != nil {
			return nil, err
		}
		handler = logger.Middleware(handler)
	}

	ca.auth = auth
	ca.srv = server.New(config.Address, handler, tlsConfig)
	return ca, nil
}

// Run starts the CA calling to the server ListenAndServe method.
func (ca *CA) Run() error {
	return ca.srv.ListenAndServe()
}

// Stop stops the CA calling to the server Shutdown method.
func (ca *CA) Stop() error {
	ca.renewer.Stop()
	if err := ca.auth.Shutdown(); err != nil {
		log.Printf("error stopping ca.Authority: %+v\n", err)
	}
	return ca.srv.Shutdown()
}

// Reload reloads the configuration of the CA and calls to the server Reload
// method.
func (ca *CA) Reload() error {
	var hasDB bool
	if ca.config.DB != nil {
		hasDB = true
	}
	if ca.opts.configFile == "" {
		return errors.New("error reloading ca: configuration file is not set")
	}

	config, err := authority.LoadConfiguration(ca.opts.configFile)
	if err != nil {
		return errors.Wrap(err, "error reloading ca configuration")
	}

	logShutDown := func(ss ...string) {
		for _, s := range ss {
			log.Println(s)
		}
		log.Println("Continuing to serve requests may result in inconsistent state. Shutting Down ...")
	}
	logContinue := func(reason string) {
		log.Println(reason)
		log.Println("Continuing to run with the original configuration.")
		log.Println("You can force a restart by sending a SIGTERM signal and then restarting the step-ca.")
	}

	// Shut down the old authority (shut down the database). If New or Reload
	// fails then the CA will continue to run but the database will have been
	// shutdown, which will cause errors.
	if err := ca.auth.Shutdown(); err != nil {
		if hasDB {
			logShutDown("Attempt to shut down the ca.Authority has failed.")
			return ca.Stop()
		}
		logContinue("Reload failed because the ca.Authority could not be shut down.")
		return err
	}
	newCA, err := New(config, WithPassword(ca.opts.password), WithConfigFile(ca.opts.configFile))
	if err != nil {
		if hasDB {
			logShutDown("Attempt to initialize a CA with the new configuration has failed.",
				"The database has already been shutdown.")
			return ca.Stop()
		}
		logContinue("Reload failed because the CA with new configuration could " +
			"not be initialized.")
		return errors.Wrap(err, "error reloading ca")
	}

	if err = ca.srv.Reload(newCA.srv); err != nil {
		if hasDB {
			logShutDown("Attempt to replace the old CA server has failed.",
				"The database has already been shutdown.")
			return ca.Stop()
		}
		logContinue("Reload failed because server could not be replaced.")
		return errors.Wrap(err, "error reloading server")
	}
	return nil
}

// getTLSConfig returns a TLSConfig for the CA server with a self-renewing
// server certificate.
func (ca *CA) getTLSConfig(auth *authority.Authority) (*tls.Config, error) {
	// Create initial TLS certificate
	tlsCrt, err := auth.GetTLSCertificate()
	if err != nil {
		return nil, err
	}

	// Start tls renewer with the new certificate.
	// If a renewer was started, attempt to stop it before.
	if ca.renewer != nil {
		ca.renewer.Stop()
	}

	ca.renewer, err = NewTLSRenewer(tlsCrt, auth.GetTLSCertificate)
	if err != nil {
		return nil, err
	}
	ca.renewer.Run()

	var tlsConfig *tls.Config
	if ca.config.TLS != nil {
		tlsConfig = ca.config.TLS.TLSConfig()
	} else {
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}

	certPool := x509.NewCertPool()
	for _, crt := range auth.GetRootCertificates() {
		certPool.AddCert(crt)
	}

	// GetCertificate will only be called if the client supplies SNI
	// information or if tlsConfig.Certificates is empty.
	// When client requests are made using an IP address (as opposed to a domain
	// name) the server does not receive any SNI and may fallback to using the
	// first entry in the Certificates attribute; by setting the attribute to
	// empty we are implicitly forcing GetCertificate to be the only mechanism
	// by which the server can find it's own leaf Certificate.
	tlsConfig.Certificates = []tls.Certificate{}
	tlsConfig.GetCertificate = ca.renewer.GetCertificateForCA

	// Add support for mutual tls to renew certificates
	tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
	tlsConfig.ClientCAs = certPool

	// Use server's most preferred ciphersuite
	tlsConfig.PreferServerCipherSuites = true

	return tlsConfig, nil
}
