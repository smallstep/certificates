package authority

import (
	"crypto/x509"

	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/db"
)

// Option sets options to the Authority.
type Option func(*Authority)

// WithDatabase sets an already initialized authority database to a new
// authority. This option is intended to be use on graceful reloads.
func WithDatabase(db db.AuthDB) Option {
	return func(a *Authority) {
		a.db = db
	}
}

// WithGetIdentityFunc sets a custom function to retrieve the identity from
// an external resource.
func WithGetIdentityFunc(fn func(p provisioner.Interface, email string) (*provisioner.Identity, error)) Option {
	return func(a *Authority) {
		a.getIdentityFunc = fn
	}
}

// WithSSHBastionFunc sets a custom function to get the bastion for a
// given user-host pair.
func WithSSHBastionFunc(fn func(user, host string) (*Bastion, error)) Option {
	return func(a *Authority) {
		a.sshBastionFunc = fn
	}
}

// WithSSHGetHosts sets a custom function to get the bastion for a
// given user-host pair.
func WithSSHGetHosts(fn func(cert *x509.Certificate) ([]string, error)) Option {
	return func(a *Authority) {
		a.sshGetHostsFunc = fn
	}
}
