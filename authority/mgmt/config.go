package mgmt

import (
	"context"

	"github.com/pkg/errors"
)

const (
	// DefaultAuthorityID is the default AuthorityID. This will be the ID
	// of the first Authority created, as well as the default AuthorityID
	// if one is not specified in the configuration.
	DefaultAuthorityID = "00000000-0000-0000-0000-000000000000"
)

// StatusType is the type for status.
type StatusType int

const (
	// StatusActive active
	StatusActive StatusType = iota
	// StatusDeleted deleted
	StatusDeleted
)

// Claims encapsulates all x509 and ssh claims applied to the authority
// configuration. E.g. maxTLSCertDuration, defaultSSHCertDuration, etc.
type Claims struct {
	X509           *X509Claims `json:"x509Claims"`
	SSH            *SSHClaims  `json:"sshClaims"`
	DisableRenewal bool        `json:"disableRenewal"`
}

// X509Claims are the x509 claims applied to the authority.
type X509Claims struct {
	Durations *Durations `json:"durations"`
}

// SSHClaims are the ssh claims applied to the authority.
type SSHClaims struct {
	Enabled       bool       `json:"enabled"`
	UserDurations *Durations `json:"userDurations"`
	HostDurations *Durations `json:"hostDurations"`
}

// Durations represents min, max, default, duration.
type Durations struct {
	Min     string `json:"min"`
	Max     string `json:"max"`
	Default string `json:"default"`
}

type AuthorityOption func(*AuthConfig) error

func WithDefaultAuthorityID(ac *AuthConfig) error {
	ac.ID = DefaultAuthorityID
	return nil
}

func CreateDefaultAuthority(ctx context.Context, db DB) (*AuthConfig, error) {
	options := []AuthorityOption{WithDefaultAuthorityID}

	return CreateAuthority(ctx, db, options...)
}

func CreateAuthority(ctx context.Context, db DB, options ...AuthorityOption) (*AuthConfig, error) {
	ac := NewDefaultAuthConfig()

	for _, o := range options {
		if err := o(ac); err != nil {
			return nil, err
		}
	}

	if err := db.CreateAuthConfig(ctx, ac); err != nil {
		return nil, errors.Wrap(err, "error creating authConfig")
	}

	// Generate default JWK provisioner.

	provOpts := []ProvisionerOption{WithPassword("pass")}
	prov, err := CreateProvisioner(ctx, db, "JWK", "changeme", provOpts...)
	if err != nil {
		// TODO should we try to clean up?
		return nil, WrapErrorISE(err, "error creating first provisioner")
	}

	admin, err := CreateAdmin(ctx, db, "Change Me", prov, true)
	if err != nil {
		// TODO should we try to clean up?
		return nil, WrapErrorISE(err, "error creating first provisioner")
	}

	ac.Provisioners = []*Provisioner{prov}
	ac.Admins = []*Admin{admin}

	return ac, nil
}
