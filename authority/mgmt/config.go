package mgmt

import (
	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/linkedca"
)

const (
	// DefaultAuthorityID is the default AuthorityID. This will be the ID
	// of the first Authority created, as well as the default AuthorityID
	// if one is not specified in the configuration.
	DefaultAuthorityID = "00000000-0000-0000-0000-000000000000"
)

func NewDefaultClaims() *linkedca.Claims {
	return &linkedca.Claims{
		X509: &linkedca.X509Claims{
			Durations: &linkedca.Durations{
				Min:     config.GlobalProvisionerClaims.MinTLSDur.String(),
				Max:     config.GlobalProvisionerClaims.MaxTLSDur.String(),
				Default: config.GlobalProvisionerClaims.DefaultTLSDur.String(),
			},
		},
		Ssh: &linkedca.SSHClaims{
			UserDurations: &linkedca.Durations{
				Min:     config.GlobalProvisionerClaims.MinUserSSHDur.String(),
				Max:     config.GlobalProvisionerClaims.MaxUserSSHDur.String(),
				Default: config.GlobalProvisionerClaims.DefaultUserSSHDur.String(),
			},
			HostDurations: &linkedca.Durations{
				Min:     config.GlobalProvisionerClaims.MinHostSSHDur.String(),
				Max:     config.GlobalProvisionerClaims.MaxHostSSHDur.String(),
				Default: config.GlobalProvisionerClaims.DefaultHostSSHDur.String(),
			},
		},
		DisableRenewal: config.DefaultDisableRenewal,
	}
}

/*
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

	adm := &Admin{
		ProvisionerID: prov.ID,
		Subject:       "Change Me",
		Type:          AdminTypeSuper,
	}
	if err := db.CreateAdmin(ctx, adm); err != nil {
		// TODO should we try to clean up?
		return nil, WrapErrorISE(err, "error creating first admin")
	}

	ac.Provisioners = []*Provisioner{prov}
	ac.Admins = []*Admin{adm}

	return ac, nil
}
*/
