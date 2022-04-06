package authority

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/errs"
	"go.step.sm/cli-utils/step"
	"go.step.sm/cli-utils/ui"
	"go.step.sm/crypto/jose"
	"go.step.sm/linkedca"
	"gopkg.in/square/go-jose.v2/jwt"
)

// Provisioners is the interface used by the provisioners collection.
type Provisioners interface {
	Load(id string) (provisioner.Interface, bool)
	Store(p provisioner.Interface) error
	Update(p provisioner.Interface) error
	Remove(id string) error
	LoadByName(name string) (provisioner.Interface, bool)
	LoadByToken(token *jose.JSONWebToken, claims *jose.Claims) (provisioner.Interface, bool)
	LoadByTokenID(tokenProvisionerID string) (provisioner.Interface, bool)
	LoadByCertificate(cert *x509.Certificate) (provisioner.Interface, bool)
	Find(cursor string, limit int) (provisioner.List, string)
	LoadEncryptedKey(keyID string) (string, bool)
}

// GetEncryptedKey returns the JWE key corresponding to the given kid argument.
func (a *Authority) GetEncryptedKey(kid string) (string, error) {
	a.adminMutex.RLock()
	defer a.adminMutex.RUnlock()
	key, ok := a.provisioners.LoadEncryptedKey(kid)
	if !ok {
		return "", errs.NotFound("encrypted key with kid %s was not found", kid)
	}
	return key, nil
}

// GetProvisioners returns a map listing each provisioner and the JWK Key Set
// with their public keys.
func (a *Authority) GetProvisioners(cursor string, limit int) (provisioner.List, string, error) {
	a.adminMutex.RLock()
	defer a.adminMutex.RUnlock()
	provisioners, nextCursor := a.provisioners.Find(cursor, limit)
	return provisioners, nextCursor, nil
}

// LoadProvisionerByCertificate returns an interface to the provisioner that
// provisioned the certificate.
func (a *Authority) LoadProvisionerByCertificate(crt *x509.Certificate) (provisioner.Interface, error) {
	a.adminMutex.RLock()
	defer a.adminMutex.RUnlock()
	p, ok := a.provisioners.LoadByCertificate(crt)
	if !ok {
		return nil, admin.NewError(admin.ErrorNotFoundType, "unable to load provisioner from certificate")
	}
	return p, nil
}

// LoadProvisionerByToken returns an interface to the provisioner that
// provisioned the token.
func (a *Authority) LoadProvisionerByToken(token *jwt.JSONWebToken, claims *jwt.Claims) (provisioner.Interface, error) {
	a.adminMutex.RLock()
	defer a.adminMutex.RUnlock()
	p, ok := a.provisioners.LoadByToken(token, claims)
	if !ok {
		return nil, admin.NewError(admin.ErrorNotFoundType, "unable to load provisioner from token")
	}
	return p, nil
}

// LoadProvisionerByID returns an interface to the provisioner with the given ID.
func (a *Authority) LoadProvisionerByID(id string) (provisioner.Interface, error) {
	a.adminMutex.RLock()
	defer a.adminMutex.RUnlock()
	p, ok := a.provisioners.Load(id)
	if !ok {
		return nil, admin.NewError(admin.ErrorNotFoundType, "provisioner %s not found", id)
	}
	return p, nil
}

// LoadProvisionerByName returns an interface to the provisioner with the given Name.
func (a *Authority) LoadProvisionerByName(name string) (provisioner.Interface, error) {
	a.adminMutex.RLock()
	defer a.adminMutex.RUnlock()
	p, ok := a.provisioners.LoadByName(name)
	if !ok {
		return nil, admin.NewError(admin.ErrorNotFoundType, "provisioner %s not found", name)
	}
	return p, nil
}

func (a *Authority) generateProvisionerConfig(ctx context.Context) (provisioner.Config, error) {
	// Merge global and configuration claims
	claimer, err := provisioner.NewClaimer(a.config.AuthorityConfig.Claims, config.GlobalProvisionerClaims)
	if err != nil {
		return provisioner.Config{}, err
	}
	// TODO: should we also be combining the ssh federated roots here?
	// If we rotate ssh roots keys, sshpop provisioner will lose ability to
	// validate old SSH certificates, unless they are added as federated certs.
	sshKeys, err := a.GetSSHRoots(ctx)
	if err != nil {
		return provisioner.Config{}, err
	}
	return provisioner.Config{
		Claims:    claimer.Claims(),
		Audiences: a.config.GetAudiences(),
		DB:        a.db,
		SSHKeys: &provisioner.SSHKeys{
			UserKeys: sshKeys.UserKeys,
			HostKeys: sshKeys.HostKeys,
		},
		GetIdentityFunc:       a.getIdentityFunc,
		AuthorizeRenewFunc:    a.authorizeRenewFunc,
		AuthorizeSSHRenewFunc: a.authorizeSSHRenewFunc,
	}, nil

}

// StoreProvisioner stores an provisioner.Interface to the authority.
func (a *Authority) StoreProvisioner(ctx context.Context, prov *linkedca.Provisioner) error {
	a.adminMutex.Lock()
	defer a.adminMutex.Unlock()

	certProv, err := ProvisionerToCertificates(prov)
	if err != nil {
		return admin.WrapErrorISE(err,
			"error converting to certificates provisioner from linkedca provisioner")
	}

	if _, ok := a.provisioners.LoadByName(prov.GetName()); ok {
		return admin.NewError(admin.ErrorBadRequestType,
			"provisioner with name %s already exists", prov.GetName())
	}
	if _, ok := a.provisioners.LoadByTokenID(certProv.GetIDForToken()); ok {
		return admin.NewError(admin.ErrorBadRequestType,
			"provisioner with token ID %s already exists", certProv.GetIDForToken())
	}

	provisionerConfig, err := a.generateProvisionerConfig(ctx)
	if err != nil {
		return admin.WrapErrorISE(err, "error generating provisioner config")
	}

	if err := certProv.Init(provisionerConfig); err != nil {
		return admin.WrapError(admin.ErrorBadRequestType, err, "error validating configuration for provisioner %s", prov.Name)
	}

	// Store to database -- this will set the ID.
	if err := a.adminDB.CreateProvisioner(ctx, prov); err != nil {
		return admin.WrapErrorISE(err, "error creating provisioner")
	}

	// We need a new conversion that has the newly set ID.
	certProv, err = ProvisionerToCertificates(prov)
	if err != nil {
		return admin.WrapErrorISE(err,
			"error converting to certificates provisioner from linkedca provisioner")
	}

	if err := certProv.Init(provisionerConfig); err != nil {
		return admin.WrapErrorISE(err, "error initializing provisioner %s", prov.Name)
	}

	if err := a.provisioners.Store(certProv); err != nil {
		if err := a.reloadAdminResources(ctx); err != nil {
			return admin.WrapErrorISE(err, "error reloading admin resources on failed provisioner store")
		}
		return admin.WrapErrorISE(err, "error storing provisioner in authority cache")
	}
	return nil
}

// UpdateProvisioner stores an provisioner.Interface to the authority.
func (a *Authority) UpdateProvisioner(ctx context.Context, nu *linkedca.Provisioner) error {
	a.adminMutex.Lock()
	defer a.adminMutex.Unlock()

	certProv, err := ProvisionerToCertificates(nu)
	if err != nil {
		return admin.WrapErrorISE(err,
			"error converting to certificates provisioner from linkedca provisioner")
	}

	provisionerConfig, err := a.generateProvisionerConfig(ctx)
	if err != nil {
		return admin.WrapErrorISE(err, "error generating provisioner config")
	}

	if err := certProv.Init(provisionerConfig); err != nil {
		return admin.WrapErrorISE(err, "error initializing provisioner %s", nu.Name)
	}

	if err := a.provisioners.Update(certProv); err != nil {
		return admin.WrapErrorISE(err, "error updating provisioner '%s' in authority cache", nu.Name)
	}
	if err := a.adminDB.UpdateProvisioner(ctx, nu); err != nil {
		if err := a.reloadAdminResources(ctx); err != nil {
			return admin.WrapErrorISE(err, "error reloading admin resources on failed provisioner update")
		}
		return admin.WrapErrorISE(err, "error updating provisioner '%s'", nu.Name)
	}
	return nil
}

// RemoveProvisioner removes an provisioner.Interface from the authority.
func (a *Authority) RemoveProvisioner(ctx context.Context, id string) error {
	a.adminMutex.Lock()
	defer a.adminMutex.Unlock()

	p, ok := a.provisioners.Load(id)
	if !ok {
		return admin.NewError(admin.ErrorBadRequestType,
			"provisioner %s not found", id)
	}

	provName, provID := p.GetName(), p.GetID()
	// Validate
	//  - Check that there will be SUPER_ADMINs that remain after we
	//    remove this provisioner.
	if a.admins.SuperCount() == a.admins.SuperCountByProvisioner(provName) {
		return admin.NewError(admin.ErrorBadRequestType,
			"cannot remove provisioner %s because no super admins will remain", provName)
	}

	// Delete all admins associated with the provisioner.
	admins, ok := a.admins.LoadByProvisioner(provName)
	if ok {
		for _, adm := range admins {
			if err := a.removeAdmin(ctx, adm.Id); err != nil {
				return admin.WrapErrorISE(err, "error deleting admin %s, as part of provisioner %s deletion", adm.Subject, provName)
			}
		}
	}

	// Remove provisioner from authority caches.
	if err := a.provisioners.Remove(provID); err != nil {
		return admin.WrapErrorISE(err, "error removing admin from authority cache")
	}
	// Remove provisioner from database.
	if err := a.adminDB.DeleteProvisioner(ctx, provID); err != nil {
		if err := a.reloadAdminResources(ctx); err != nil {
			return admin.WrapErrorISE(err, "error reloading admin resources on failed provisioner remove")
		}
		return admin.WrapErrorISE(err, "error deleting provisioner %s", provName)
	}
	return nil
}

// CreateFirstProvisioner creates and stores the first provisioner when using
// admin database provisioner storage.
func CreateFirstProvisioner(ctx context.Context, db admin.DB, password string) (*linkedca.Provisioner, error) {
	if password == "" {
		pass, err := ui.PromptPasswordGenerate("Please enter the password to encrypt your first provisioner, leave empty and we'll generate one")
		if err != nil {
			return nil, err
		}
		password = string(pass)
	}

	jwk, jwe, err := jose.GenerateDefaultKeyPair([]byte(password))
	if err != nil {
		return nil, admin.WrapErrorISE(err, "error generating JWK key pair")
	}

	jwkPubBytes, err := jwk.MarshalJSON()
	if err != nil {
		return nil, admin.WrapErrorISE(err, "error marshaling JWK")
	}
	jwePrivStr, err := jwe.CompactSerialize()
	if err != nil {
		return nil, admin.WrapErrorISE(err, "error serializing JWE")
	}

	p := &linkedca.Provisioner{
		Name: "Admin JWK",
		Type: linkedca.Provisioner_JWK,
		Details: &linkedca.ProvisionerDetails{
			Data: &linkedca.ProvisionerDetails_JWK{
				JWK: &linkedca.JWKProvisioner{
					PublicKey:           jwkPubBytes,
					EncryptedPrivateKey: []byte(jwePrivStr),
				},
			},
		},
		Claims: &linkedca.Claims{
			X509: &linkedca.X509Claims{
				Enabled: true,
				Durations: &linkedca.Durations{
					Default: "5m",
				},
			},
		},
	}
	if err := db.CreateProvisioner(ctx, p); err != nil {
		return nil, admin.WrapErrorISE(err, "error creating provisioner")
	}
	return p, nil
}

// ValidateClaims validates the Claims type.
func ValidateClaims(c *linkedca.Claims) error {
	if c == nil {
		return nil
	}
	if c.X509 != nil {
		if c.X509.Durations != nil {
			if err := ValidateDurations(c.X509.Durations); err != nil {
				return err
			}
		}
	}
	if c.Ssh != nil {
		if c.Ssh.UserDurations != nil {
			if err := ValidateDurations(c.Ssh.UserDurations); err != nil {
				return err
			}
		}
		if c.Ssh.HostDurations != nil {
			if err := ValidateDurations(c.Ssh.HostDurations); err != nil {
				return err
			}
		}
	}
	return nil
}

// ValidateDurations validates the Durations type.
func ValidateDurations(d *linkedca.Durations) error {
	var (
		err           error
		min, max, def *provisioner.Duration
	)

	if d.Min != "" {
		min, err = provisioner.NewDuration(d.Min)
		if err != nil {
			return admin.WrapError(admin.ErrorBadRequestType, err, "min duration '%s' is invalid", d.Min)
		}
		if min.Value() < 0 {
			return admin.WrapError(admin.ErrorBadRequestType, err, "min duration '%s' cannot be less than 0", d.Min)
		}
	}
	if d.Max != "" {
		max, err = provisioner.NewDuration(d.Max)
		if err != nil {
			return admin.WrapError(admin.ErrorBadRequestType, err, "max duration '%s' is invalid", d.Max)
		}
		if max.Value() < 0 {
			return admin.WrapError(admin.ErrorBadRequestType, err, "max duration '%s' cannot be less than 0", d.Max)
		}
	}
	if d.Default != "" {
		def, err = provisioner.NewDuration(d.Default)
		if err != nil {
			return admin.WrapError(admin.ErrorBadRequestType, err, "default duration '%s' is invalid", d.Default)
		}
		if def.Value() < 0 {
			return admin.WrapError(admin.ErrorBadRequestType, err, "default duration '%s' cannot be less than 0", d.Default)
		}
	}
	if d.Min != "" && d.Max != "" && min.Value() > max.Value() {
		return admin.NewError(admin.ErrorBadRequestType,
			"min duration '%s' cannot be greater than max duration '%s'", d.Min, d.Max)
	}
	if d.Min != "" && d.Default != "" && min.Value() > def.Value() {
		return admin.NewError(admin.ErrorBadRequestType,
			"min duration '%s' cannot be greater than default duration '%s'", d.Min, d.Default)
	}
	if d.Default != "" && d.Max != "" && min.Value() > def.Value() {
		return admin.NewError(admin.ErrorBadRequestType,
			"default duration '%s' cannot be greater than max duration '%s'", d.Default, d.Max)
	}
	return nil
}

func provisionerListToCertificates(l []*linkedca.Provisioner) (provisioner.List, error) {
	var nu provisioner.List
	for _, p := range l {
		certProv, err := ProvisionerToCertificates(p)
		if err != nil {
			return nil, err
		}
		nu = append(nu, certProv)
	}
	return nu, nil
}

func optionsToCertificates(p *linkedca.Provisioner) *provisioner.Options {
	ops := &provisioner.Options{
		X509: &provisioner.X509Options{},
		SSH:  &provisioner.SSHOptions{},
	}
	if p.X509Template != nil {
		ops.X509.Template = string(p.X509Template.Template)
		ops.X509.TemplateData = p.X509Template.Data
	}
	if p.SshTemplate != nil {
		ops.SSH.Template = string(p.SshTemplate.Template)
		ops.SSH.TemplateData = p.SshTemplate.Data
	}
	return ops
}

func durationsToCertificates(d *linkedca.Durations) (min, max, def *provisioner.Duration, err error) {
	if len(d.Min) > 0 {
		min, err = provisioner.NewDuration(d.Min)
		if err != nil {
			return nil, nil, nil, admin.WrapErrorISE(err, "error parsing minimum duration '%s'", d.Min)
		}
	}
	if len(d.Max) > 0 {
		max, err = provisioner.NewDuration(d.Max)
		if err != nil {
			return nil, nil, nil, admin.WrapErrorISE(err, "error parsing maximum duration '%s'", d.Max)
		}
	}
	if len(d.Default) > 0 {
		def, err = provisioner.NewDuration(d.Default)
		if err != nil {
			return nil, nil, nil, admin.WrapErrorISE(err, "error parsing default duration '%s'", d.Default)
		}
	}
	return
}

func durationsToLinkedca(d *provisioner.Duration) string {
	if d == nil {
		return ""
	}
	return d.Duration.String()
}

// claimsToCertificates converts the linkedca provisioner claims type to the
// certifictes claims type.
func claimsToCertificates(c *linkedca.Claims) (*provisioner.Claims, error) {
	if c == nil {
		return nil, nil
	}

	pc := &provisioner.Claims{
		DisableRenewal:        &c.DisableRenewal,
		AllowRenewAfterExpiry: &c.AllowRenewAfterExpiry,
	}

	var err error

	if xc := c.X509; xc != nil {
		if d := xc.Durations; d != nil {
			pc.MinTLSDur, pc.MaxTLSDur, pc.DefaultTLSDur, err = durationsToCertificates(d)
			if err != nil {
				return nil, err
			}
		}
	}
	if sc := c.Ssh; sc != nil {
		pc.EnableSSHCA = &sc.Enabled
		if d := sc.UserDurations; d != nil {
			pc.MinUserSSHDur, pc.MaxUserSSHDur, pc.DefaultUserSSHDur, err = durationsToCertificates(d)
			if err != nil {
				return nil, err
			}
		}
		if d := sc.HostDurations; d != nil {
			pc.MinHostSSHDur, pc.MaxHostSSHDur, pc.DefaultHostSSHDur, err = durationsToCertificates(d)
			if err != nil {
				return nil, err
			}
		}
	}

	return pc, nil
}

func claimsToLinkedca(c *provisioner.Claims) *linkedca.Claims {
	if c == nil {
		return nil
	}

	disableRenewal := config.DefaultDisableRenewal
	allowRenewAfterExpiry := config.DefaultAllowRenewAfterExpiry

	if c.DisableRenewal != nil {
		disableRenewal = *c.DisableRenewal
	}
	if c.AllowRenewAfterExpiry != nil {
		allowRenewAfterExpiry = *c.AllowRenewAfterExpiry
	}

	lc := &linkedca.Claims{
		DisableRenewal:        disableRenewal,
		AllowRenewAfterExpiry: allowRenewAfterExpiry,
	}

	if c.DefaultTLSDur != nil || c.MinTLSDur != nil || c.MaxTLSDur != nil {
		lc.X509 = &linkedca.X509Claims{
			Enabled: true,
			Durations: &linkedca.Durations{
				Default: durationsToLinkedca(c.DefaultTLSDur),
				Min:     durationsToLinkedca(c.MinTLSDur),
				Max:     durationsToLinkedca(c.MaxTLSDur),
			},
		}
	}

	if c.EnableSSHCA != nil && *c.EnableSSHCA {
		lc.Ssh = &linkedca.SSHClaims{
			Enabled: true,
		}
		if c.DefaultUserSSHDur != nil || c.MinUserSSHDur != nil || c.MaxUserSSHDur != nil {
			lc.Ssh.UserDurations = &linkedca.Durations{
				Default: durationsToLinkedca(c.DefaultUserSSHDur),
				Min:     durationsToLinkedca(c.MinUserSSHDur),
				Max:     durationsToLinkedca(c.MaxUserSSHDur),
			}
		}
		if c.DefaultHostSSHDur != nil || c.MinHostSSHDur != nil || c.MaxHostSSHDur != nil {
			lc.Ssh.HostDurations = &linkedca.Durations{
				Default: durationsToLinkedca(c.DefaultHostSSHDur),
				Min:     durationsToLinkedca(c.MinHostSSHDur),
				Max:     durationsToLinkedca(c.MaxHostSSHDur),
			}
		}
	}

	return lc
}

func provisionerOptionsToLinkedca(p *provisioner.Options) (*linkedca.Template, *linkedca.Template, error) {
	var err error
	var x509Template, sshTemplate *linkedca.Template

	if p == nil {
		return nil, nil, nil
	}

	if p.X509 != nil && p.X509.HasTemplate() {
		x509Template = &linkedca.Template{
			Template: nil,
			Data:     nil,
		}

		if p.X509.Template != "" {
			x509Template.Template = []byte(p.SSH.Template)
		} else if p.X509.TemplateFile != "" {
			filename := step.Abs(p.X509.TemplateFile)
			if x509Template.Template, err = os.ReadFile(filename); err != nil {
				return nil, nil, errors.Wrap(err, "error reading x509 template")
			}
		}
	}

	if p.SSH != nil && p.SSH.HasTemplate() {
		sshTemplate = &linkedca.Template{
			Template: nil,
			Data:     nil,
		}

		if p.SSH.Template != "" {
			sshTemplate.Template = []byte(p.SSH.Template)
		} else if p.SSH.TemplateFile != "" {
			filename := step.Abs(p.SSH.TemplateFile)
			if sshTemplate.Template, err = os.ReadFile(filename); err != nil {
				return nil, nil, errors.Wrap(err, "error reading ssh template")
			}
		}
	}

	return x509Template, sshTemplate, nil
}

func provisionerPEMToLinkedca(b []byte) [][]byte {
	var roots [][]byte
	var block *pem.Block
	for {
		if block, b = pem.Decode(b); block == nil {
			break
		}
		roots = append(roots, pem.EncodeToMemory(block))
	}
	return roots
}

// ProvisionerToCertificates converts the linkedca provisioner type to the certificates provisioner
// interface.
func ProvisionerToCertificates(p *linkedca.Provisioner) (provisioner.Interface, error) {
	claims, err := claimsToCertificates(p.Claims)
	if err != nil {
		return nil, err
	}

	details := p.Details.GetData()
	if details == nil {
		return nil, errors.New("provisioner does not have any details")
	}

	options := optionsToCertificates(p)

	switch d := details.(type) {
	case *linkedca.ProvisionerDetails_JWK:
		jwk := new(jose.JSONWebKey)
		if err := json.Unmarshal(d.JWK.PublicKey, &jwk); err != nil {
			return nil, errors.Wrap(err, "error unmarshaling public key")
		}
		return &provisioner.JWK{
			ID:           p.Id,
			Type:         p.Type.String(),
			Name:         p.Name,
			Key:          jwk,
			EncryptedKey: string(d.JWK.EncryptedPrivateKey),
			Claims:       claims,
			Options:      options,
		}, nil
	case *linkedca.ProvisionerDetails_X5C:
		var roots []byte
		for i, root := range d.X5C.GetRoots() {
			if i > 0 {
				roots = append(roots, '\n')
			}
			roots = append(roots, root...)
		}
		return &provisioner.X5C{
			ID:      p.Id,
			Type:    p.Type.String(),
			Name:    p.Name,
			Roots:   roots,
			Claims:  claims,
			Options: options,
		}, nil
	case *linkedca.ProvisionerDetails_K8SSA:
		var publicKeys []byte
		for i, k := range d.K8SSA.GetPublicKeys() {
			if i > 0 {
				publicKeys = append(publicKeys, '\n')
			}
			publicKeys = append(publicKeys, k...)
		}
		return &provisioner.K8sSA{
			ID:      p.Id,
			Type:    p.Type.String(),
			Name:    p.Name,
			PubKeys: publicKeys,
			Claims:  claims,
			Options: options,
		}, nil
	case *linkedca.ProvisionerDetails_SSHPOP:
		return &provisioner.SSHPOP{
			ID:     p.Id,
			Type:   p.Type.String(),
			Name:   p.Name,
			Claims: claims,
		}, nil
	case *linkedca.ProvisionerDetails_ACME:
		cfg := d.ACME
		return &provisioner.ACME{
			ID:         p.Id,
			Type:       p.Type.String(),
			Name:       p.Name,
			ForceCN:    cfg.ForceCn,
			RequireEAB: cfg.RequireEab,
			Claims:     claims,
			Options:    options,
		}, nil
	case *linkedca.ProvisionerDetails_OIDC:
		cfg := d.OIDC
		return &provisioner.OIDC{
			ID:                    p.Id,
			Type:                  p.Type.String(),
			Name:                  p.Name,
			TenantID:              cfg.TenantId,
			ClientID:              cfg.ClientId,
			ClientSecret:          cfg.ClientSecret,
			ConfigurationEndpoint: cfg.ConfigurationEndpoint,
			Admins:                cfg.Admins,
			Domains:               cfg.Domains,
			Groups:                cfg.Groups,
			ListenAddress:         cfg.ListenAddress,
			Claims:                claims,
			Options:               options,
		}, nil
	case *linkedca.ProvisionerDetails_AWS:
		cfg := d.AWS
		instanceAge, err := parseInstanceAge(cfg.InstanceAge)
		if err != nil {
			return nil, err
		}
		return &provisioner.AWS{
			ID:                     p.Id,
			Type:                   p.Type.String(),
			Name:                   p.Name,
			Accounts:               cfg.Accounts,
			DisableCustomSANs:      cfg.DisableCustomSans,
			DisableTrustOnFirstUse: cfg.DisableTrustOnFirstUse,
			InstanceAge:            instanceAge,
			Claims:                 claims,
			Options:                options,
		}, nil
	case *linkedca.ProvisionerDetails_GCP:
		cfg := d.GCP
		instanceAge, err := parseInstanceAge(cfg.InstanceAge)
		if err != nil {
			return nil, err
		}
		return &provisioner.GCP{
			ID:                     p.Id,
			Type:                   p.Type.String(),
			Name:                   p.Name,
			ServiceAccounts:        cfg.ServiceAccounts,
			ProjectIDs:             cfg.ProjectIds,
			DisableCustomSANs:      cfg.DisableCustomSans,
			DisableTrustOnFirstUse: cfg.DisableTrustOnFirstUse,
			InstanceAge:            instanceAge,
			Claims:                 claims,
			Options:                options,
		}, nil
	case *linkedca.ProvisionerDetails_Azure:
		cfg := d.Azure
		return &provisioner.Azure{
			ID:                     p.Id,
			Type:                   p.Type.String(),
			Name:                   p.Name,
			TenantID:               cfg.TenantId,
			ResourceGroups:         cfg.ResourceGroups,
			SubscriptionIDs:        cfg.SubscriptionIds,
			ObjectIDs:              cfg.ObjectIds,
			Audience:               cfg.Audience,
			DisableCustomSANs:      cfg.DisableCustomSans,
			DisableTrustOnFirstUse: cfg.DisableTrustOnFirstUse,
			Claims:                 claims,
			Options:                options,
		}, nil
	case *linkedca.ProvisionerDetails_SCEP:
		cfg := d.SCEP
		return &provisioner.SCEP{
			ID:                            p.Id,
			Type:                          p.Type.String(),
			Name:                          p.Name,
			ForceCN:                       cfg.ForceCn,
			ChallengePassword:             cfg.Challenge,
			Capabilities:                  cfg.Capabilities,
			IncludeRoot:                   cfg.IncludeRoot,
			MinimumPublicKeyLength:        int(cfg.MinimumPublicKeyLength),
			EncryptionAlgorithmIdentifier: int(cfg.EncryptionAlgorithmIdentifier),
			Claims:                        claims,
			Options:                       options,
		}, nil
	case *linkedca.ProvisionerDetails_Nebula:
		var roots []byte
		for i, root := range d.Nebula.GetRoots() {
			if i > 0 && !bytes.HasSuffix(root, []byte{'\n'}) {
				roots = append(roots, '\n')
			}
			roots = append(roots, root...)
		}
		return &provisioner.Nebula{
			ID:      p.Id,
			Type:    p.Type.String(),
			Name:    p.Name,
			Roots:   roots,
			Claims:  claims,
			Options: options,
		}, nil
	default:
		return nil, fmt.Errorf("provisioner %s not implemented", p.Type)
	}
}

// ProvisionerToLinkedca converts a provisioner.Interface to a
// linkedca.Provisioner type.
func ProvisionerToLinkedca(p provisioner.Interface) (*linkedca.Provisioner, error) {
	switch p := p.(type) {
	case *provisioner.JWK:
		x509Template, sshTemplate, err := provisionerOptionsToLinkedca(p.Options)
		if err != nil {
			return nil, err
		}
		publicKey, err := json.Marshal(p.Key)
		if err != nil {
			return nil, errors.Wrap(err, "error marshaling key")
		}
		return &linkedca.Provisioner{
			Id:   p.ID,
			Type: linkedca.Provisioner_JWK,
			Name: p.GetName(),
			Details: &linkedca.ProvisionerDetails{
				Data: &linkedca.ProvisionerDetails_JWK{
					JWK: &linkedca.JWKProvisioner{
						PublicKey:           publicKey,
						EncryptedPrivateKey: []byte(p.EncryptedKey),
					},
				},
			},
			Claims:       claimsToLinkedca(p.Claims),
			X509Template: x509Template,
			SshTemplate:  sshTemplate,
		}, nil
	case *provisioner.OIDC:
		x509Template, sshTemplate, err := provisionerOptionsToLinkedca(p.Options)
		if err != nil {
			return nil, err
		}
		return &linkedca.Provisioner{
			Id:   p.ID,
			Type: linkedca.Provisioner_OIDC,
			Name: p.GetName(),
			Details: &linkedca.ProvisionerDetails{
				Data: &linkedca.ProvisionerDetails_OIDC{
					OIDC: &linkedca.OIDCProvisioner{
						ClientId:              p.ClientID,
						ClientSecret:          p.ClientSecret,
						ConfigurationEndpoint: p.ConfigurationEndpoint,
						Admins:                p.Admins,
						Domains:               p.Domains,
						Groups:                p.Groups,
						ListenAddress:         p.ListenAddress,
						TenantId:              p.TenantID,
					},
				},
			},
			Claims:       claimsToLinkedca(p.Claims),
			X509Template: x509Template,
			SshTemplate:  sshTemplate,
		}, nil
	case *provisioner.GCP:
		x509Template, sshTemplate, err := provisionerOptionsToLinkedca(p.Options)
		if err != nil {
			return nil, err
		}
		return &linkedca.Provisioner{
			Id:   p.ID,
			Type: linkedca.Provisioner_GCP,
			Name: p.GetName(),
			Details: &linkedca.ProvisionerDetails{
				Data: &linkedca.ProvisionerDetails_GCP{
					GCP: &linkedca.GCPProvisioner{
						ServiceAccounts:        p.ServiceAccounts,
						ProjectIds:             p.ProjectIDs,
						DisableCustomSans:      p.DisableCustomSANs,
						DisableTrustOnFirstUse: p.DisableTrustOnFirstUse,
						InstanceAge:            p.InstanceAge.String(),
					},
				},
			},
			Claims:       claimsToLinkedca(p.Claims),
			X509Template: x509Template,
			SshTemplate:  sshTemplate,
		}, nil
	case *provisioner.AWS:
		x509Template, sshTemplate, err := provisionerOptionsToLinkedca(p.Options)
		if err != nil {
			return nil, err
		}
		return &linkedca.Provisioner{
			Id:   p.ID,
			Type: linkedca.Provisioner_AWS,
			Name: p.GetName(),
			Details: &linkedca.ProvisionerDetails{
				Data: &linkedca.ProvisionerDetails_AWS{
					AWS: &linkedca.AWSProvisioner{
						Accounts:               p.Accounts,
						DisableCustomSans:      p.DisableCustomSANs,
						DisableTrustOnFirstUse: p.DisableTrustOnFirstUse,
						InstanceAge:            p.InstanceAge.String(),
					},
				},
			},
			Claims:       claimsToLinkedca(p.Claims),
			X509Template: x509Template,
			SshTemplate:  sshTemplate,
		}, nil
	case *provisioner.Azure:
		x509Template, sshTemplate, err := provisionerOptionsToLinkedca(p.Options)
		if err != nil {
			return nil, err
		}
		return &linkedca.Provisioner{
			Id:   p.ID,
			Type: linkedca.Provisioner_AZURE,
			Name: p.GetName(),
			Details: &linkedca.ProvisionerDetails{
				Data: &linkedca.ProvisionerDetails_Azure{
					Azure: &linkedca.AzureProvisioner{
						TenantId:               p.TenantID,
						ResourceGroups:         p.ResourceGroups,
						SubscriptionIds:        p.SubscriptionIDs,
						ObjectIds:              p.ObjectIDs,
						Audience:               p.Audience,
						DisableCustomSans:      p.DisableCustomSANs,
						DisableTrustOnFirstUse: p.DisableTrustOnFirstUse,
					},
				},
			},
			Claims:       claimsToLinkedca(p.Claims),
			X509Template: x509Template,
			SshTemplate:  sshTemplate,
		}, nil
	case *provisioner.ACME:
		x509Template, sshTemplate, err := provisionerOptionsToLinkedca(p.Options)
		if err != nil {
			return nil, err
		}
		return &linkedca.Provisioner{
			Id:   p.ID,
			Type: linkedca.Provisioner_ACME,
			Name: p.GetName(),
			Details: &linkedca.ProvisionerDetails{
				Data: &linkedca.ProvisionerDetails_ACME{
					ACME: &linkedca.ACMEProvisioner{
						ForceCn: p.ForceCN,
					},
				},
			},
			Claims:       claimsToLinkedca(p.Claims),
			X509Template: x509Template,
			SshTemplate:  sshTemplate,
		}, nil
	case *provisioner.X5C:
		x509Template, sshTemplate, err := provisionerOptionsToLinkedca(p.Options)
		if err != nil {
			return nil, err
		}
		return &linkedca.Provisioner{
			Id:   p.ID,
			Type: linkedca.Provisioner_X5C,
			Name: p.GetName(),
			Details: &linkedca.ProvisionerDetails{
				Data: &linkedca.ProvisionerDetails_X5C{
					X5C: &linkedca.X5CProvisioner{
						Roots: provisionerPEMToLinkedca(p.Roots),
					},
				},
			},
			Claims:       claimsToLinkedca(p.Claims),
			X509Template: x509Template,
			SshTemplate:  sshTemplate,
		}, nil
	case *provisioner.K8sSA:
		x509Template, sshTemplate, err := provisionerOptionsToLinkedca(p.Options)
		if err != nil {
			return nil, err
		}
		return &linkedca.Provisioner{
			Id:   p.ID,
			Type: linkedca.Provisioner_K8SSA,
			Name: p.GetName(),
			Details: &linkedca.ProvisionerDetails{
				Data: &linkedca.ProvisionerDetails_K8SSA{
					K8SSA: &linkedca.K8SSAProvisioner{
						PublicKeys: provisionerPEMToLinkedca(p.PubKeys),
					},
				},
			},
			Claims:       claimsToLinkedca(p.Claims),
			X509Template: x509Template,
			SshTemplate:  sshTemplate,
		}, nil
	case *provisioner.SSHPOP:
		return &linkedca.Provisioner{
			Id:   p.ID,
			Type: linkedca.Provisioner_SSHPOP,
			Name: p.GetName(),
			Details: &linkedca.ProvisionerDetails{
				Data: &linkedca.ProvisionerDetails_SSHPOP{
					SSHPOP: &linkedca.SSHPOPProvisioner{},
				},
			},
			Claims: claimsToLinkedca(p.Claims),
		}, nil
	case *provisioner.SCEP:
		x509Template, sshTemplate, err := provisionerOptionsToLinkedca(p.Options)
		if err != nil {
			return nil, err
		}
		return &linkedca.Provisioner{
			Id:   p.ID,
			Type: linkedca.Provisioner_SCEP,
			Name: p.GetName(),
			Details: &linkedca.ProvisionerDetails{
				Data: &linkedca.ProvisionerDetails_SCEP{
					SCEP: &linkedca.SCEPProvisioner{
						ForceCn:                       p.ForceCN,
						Challenge:                     p.GetChallengePassword(),
						Capabilities:                  p.Capabilities,
						MinimumPublicKeyLength:        int32(p.MinimumPublicKeyLength),
						IncludeRoot:                   p.IncludeRoot,
						EncryptionAlgorithmIdentifier: int32(p.EncryptionAlgorithmIdentifier),
					},
				},
			},
			Claims:       claimsToLinkedca(p.Claims),
			X509Template: x509Template,
			SshTemplate:  sshTemplate,
		}, nil
	case *provisioner.Nebula:
		x509Template, sshTemplate, err := provisionerOptionsToLinkedca(p.Options)
		if err != nil {
			return nil, err
		}
		return &linkedca.Provisioner{
			Id:   p.ID,
			Type: linkedca.Provisioner_NEBULA,
			Name: p.GetName(),
			Details: &linkedca.ProvisionerDetails{
				Data: &linkedca.ProvisionerDetails_Nebula{
					Nebula: &linkedca.NebulaProvisioner{
						Roots: provisionerPEMToLinkedca(p.Roots),
					},
				},
			},
			Claims:       claimsToLinkedca(p.Claims),
			X509Template: x509Template,
			SshTemplate:  sshTemplate,
		}, nil
	default:
		return nil, fmt.Errorf("provisioner %s not implemented", p.GetType())
	}
}

func parseInstanceAge(age string) (provisioner.Duration, error) {
	var instanceAge provisioner.Duration
	if age != "" {
		iap, err := provisioner.NewDuration(age)
		if err != nil {
			return instanceAge, err
		}
		instanceAge = *iap
	}
	return instanceAge, nil
}
