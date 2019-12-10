package authority

import (
	"context"
	"crypto/x509"

	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/certificates/sshutil"
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
func WithSSHGetHosts(fn func(cert *x509.Certificate) ([]sshutil.Host, error)) Option {
	return func(a *Authority) {
		a.sshGetHostsFunc = fn
	}
}

// WithSSHCheckHost sets a custom function to check whether a given host is
// step ssh enabled. The token is used to validate the request, while the roots
// are used to validate the token.
func WithSSHCheckHost(fn func(ctx context.Context, principal string, tok string, roots []*x509.Certificate) (bool, error)) Option {
	return func(a *Authority) {
		a.sshCheckHostFunc = fn
	}
}
