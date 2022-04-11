package authority

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/cas"
	casapi "github.com/smallstep/certificates/cas/apiv1"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/certificates/kms"
	"golang.org/x/crypto/ssh"
)

// Option sets options to the Authority.
type Option func(*Authority) error

// WithConfig replaces the current config with the given one. No validation is
// performed in the given value.
func WithConfig(cfg *config.Config) Option {
	return func(a *Authority) error {
		a.config = cfg
		return nil
	}
}

// WithConfigFile reads the given filename as a configuration file and replaces
// the current one. No validation is performed in the given configuration.
func WithConfigFile(filename string) Option {
	return func(a *Authority) (err error) {
		a.config, err = config.LoadConfiguration(filename)
		return
	}
}

// WithPassword set the password to decrypt the intermediate key as well as the
// ssh host and user keys if they are not overridden by other options.
func WithPassword(password []byte) Option {
	return func(a *Authority) (err error) {
		a.password = password
		return
	}
}

// WithSSHHostPassword set the password to decrypt the key used to sign SSH host
// certificates.
func WithSSHHostPassword(password []byte) Option {
	return func(a *Authority) (err error) {
		a.sshHostPassword = password
		return
	}
}

// WithSSHUserPassword set the password to decrypt the key used to sign SSH user
// certificates.
func WithSSHUserPassword(password []byte) Option {
	return func(a *Authority) (err error) {
		a.sshUserPassword = password
		return
	}
}

// WithIssuerPassword set the password to decrypt the certificate issuer private
// key used in RA mode.
func WithIssuerPassword(password []byte) Option {
	return func(a *Authority) (err error) {
		a.issuerPassword = password
		return
	}
}

// WithDatabase sets an already initialized authority database to a new
// authority. This option is intended to be use on graceful reloads.
func WithDatabase(d db.AuthDB) Option {
	return func(a *Authority) error {
		a.db = d
		return nil
	}
}

// WithGetIdentityFunc sets a custom function to retrieve the identity from
// an external resource.
func WithGetIdentityFunc(fn func(ctx context.Context, p provisioner.Interface, email string) (*provisioner.Identity, error)) Option {
	return func(a *Authority) error {
		a.getIdentityFunc = fn
		return nil
	}
}

// WithAuthorizeRenewFunc sets a custom function that authorizes the renewal of
// an X.509 certificate.
func WithAuthorizeRenewFunc(fn func(ctx context.Context, p *provisioner.Controller, cert *x509.Certificate) error) Option {
	return func(a *Authority) error {
		a.authorizeRenewFunc = fn
		return nil
	}
}

// WithAuthorizeSSHRenewFunc sets a custom function that authorizes the renewal
// of a SSH certificate.
func WithAuthorizeSSHRenewFunc(fn func(ctx context.Context, p *provisioner.Controller, cert *ssh.Certificate) error) Option {
	return func(a *Authority) error {
		a.authorizeSSHRenewFunc = fn
		return nil
	}
}

// WithSSHBastionFunc sets a custom function to get the bastion for a
// given user-host pair.
func WithSSHBastionFunc(fn func(ctx context.Context, user, host string) (*config.Bastion, error)) Option {
	return func(a *Authority) error {
		a.sshBastionFunc = fn
		return nil
	}
}

// WithSSHGetHosts sets a custom function to return a list of step ssh enabled
// hosts.
func WithSSHGetHosts(fn func(ctx context.Context, cert *x509.Certificate) ([]config.Host, error)) Option {
	return func(a *Authority) error {
		a.sshGetHostsFunc = fn
		return nil
	}
}

// WithSSHCheckHost sets a custom function to check whether a given host is
// step ssh enabled. The token is used to validate the request, while the roots
// are used to validate the token.
func WithSSHCheckHost(fn func(ctx context.Context, principal string, tok string, roots []*x509.Certificate) (bool, error)) Option {
	return func(a *Authority) error {
		a.sshCheckHostFunc = fn
		return nil
	}
}

// WithKeyManager defines the key manager used to get and create keys, and sign
// certificates.
func WithKeyManager(k kms.KeyManager) Option {
	return func(a *Authority) error {
		a.keyManager = k
		return nil
	}
}

// WithX509Signer defines the signer used to sign X509 certificates.
func WithX509Signer(crt *x509.Certificate, s crypto.Signer) Option {
	return func(a *Authority) error {
		srv, err := cas.New(context.Background(), casapi.Options{
			Type:             casapi.SoftCAS,
			Signer:           s,
			CertificateChain: []*x509.Certificate{crt},
		})
		if err != nil {
			return err
		}
		a.x509CAService = srv
		return nil
	}
}

// WithX509SignerFunc defines the function used to get the chain of certificates
// and signer used when we sign X.509 certificates.
func WithX509SignerFunc(fn func() ([]*x509.Certificate, crypto.Signer, error)) Option {
	return func(a *Authority) error {
		srv, err := cas.New(context.Background(), casapi.Options{
			Type:              casapi.SoftCAS,
			CertificateSigner: fn,
		})
		if err != nil {
			return err
		}
		a.x509CAService = srv
		return nil
	}
}

// WithSSHUserSigner defines the signer used to sign SSH user certificates.
func WithSSHUserSigner(s crypto.Signer) Option {
	return func(a *Authority) error {
		signer, err := ssh.NewSignerFromSigner(s)
		if err != nil {
			return errors.Wrap(err, "error creating ssh user signer")
		}
		a.sshCAUserCertSignKey = signer
		// Append public key to list of user certs
		pub := signer.PublicKey()
		a.sshCAUserCerts = append(a.sshCAUserCerts, pub)
		a.sshCAUserFederatedCerts = append(a.sshCAUserFederatedCerts, pub)
		return nil
	}
}

// WithSSHHostSigner defines the signer used to sign SSH host certificates.
func WithSSHHostSigner(s crypto.Signer) Option {
	return func(a *Authority) error {
		signer, err := ssh.NewSignerFromSigner(s)
		if err != nil {
			return errors.Wrap(err, "error creating ssh host signer")
		}
		a.sshCAHostCertSignKey = signer
		// Append public key to list of host certs
		pub := signer.PublicKey()
		a.sshCAHostCerts = append(a.sshCAHostCerts, pub)
		a.sshCAHostFederatedCerts = append(a.sshCAHostFederatedCerts, pub)
		return nil
	}
}

// WithX509RootCerts is an option that allows to define the list of root
// certificates to use. This option will replace any root certificate defined
// before.
func WithX509RootCerts(rootCerts ...*x509.Certificate) Option {
	return func(a *Authority) error {
		a.rootX509Certs = rootCerts
		return nil
	}
}

// WithX509FederatedCerts is an option that allows to define the list of
// federated certificates. This option will replace any federated certificate
// defined before.
func WithX509FederatedCerts(certs ...*x509.Certificate) Option {
	return func(a *Authority) error {
		a.federatedX509Certs = certs
		return nil
	}
}

// WithX509RootBundle is an option that allows to define the list of root
// certificates. This option will replace any root certificate defined before.
func WithX509RootBundle(pemCerts []byte) Option {
	return func(a *Authority) error {
		certs, err := readCertificateBundle(pemCerts)
		if err != nil {
			return err
		}
		a.rootX509Certs = certs
		return nil
	}
}

// WithX509FederatedBundle is an option that allows to define the list of
// federated certificates. This option will replace any federated certificate
// defined before.
func WithX509FederatedBundle(pemCerts []byte) Option {
	return func(a *Authority) error {
		certs, err := readCertificateBundle(pemCerts)
		if err != nil {
			return err
		}
		a.federatedX509Certs = certs
		return nil
	}
}

// WithAdminDB is an option to set the database backing the admin APIs.
func WithAdminDB(d admin.DB) Option {
	return func(a *Authority) error {
		a.adminDB = d
		return nil
	}
}

// WithLinkedCAToken is an option to set the authentication token used to enable
// linked ca.
func WithLinkedCAToken(token string) Option {
	return func(a *Authority) error {
		a.linkedCAToken = token
		return nil
	}
}

// WithX509Enforcers is an option that allows to define custom certificate
// modifiers that will be processed just before the signing of the certificate.
func WithX509Enforcers(ces ...provisioner.CertificateEnforcer) Option {
	return func(a *Authority) error {
		a.x509Enforcers = ces
		return nil
	}
}

func readCertificateBundle(pemCerts []byte) ([]*x509.Certificate, error) {
	var block *pem.Block
	var certs []*x509.Certificate
	for len(pemCerts) > 0 {
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}

		certs = append(certs, cert)
	}
	return certs, nil
}
