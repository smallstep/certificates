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
	"gopkg.in/square/go-jose.v2/jwt"

	"go.step.sm/cli-utils/step"
	"go.step.sm/cli-utils/ui"
	"go.step.sm/crypto/jose"
	"go.step.sm/linkedca"

	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/policy"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/certificates/errs"
)

type raProvisioner interface {
	RAInfo() *provisioner.RAInfo
}

type attProvisioner interface {
	AttestationData() *provisioner.AttestationData
}

// wrapProvisioner wraps the given provisioner with RA information and
// attestation data.
func wrapProvisioner(p provisioner.Interface, attData *provisioner.AttestationData) *wrappedProvisioner {
	var raInfo *provisioner.RAInfo
	if rap, ok := p.(raProvisioner); ok {
		raInfo = rap.RAInfo()
	}

	return &wrappedProvisioner{
		Interface:       p,
		attestationData: attData,
		raInfo:          raInfo,
	}
}

// wrapRAProvisioner wraps the given provisioner with RA information.
func wrapRAProvisioner(p provisioner.Interface, raInfo *provisioner.RAInfo) *wrappedProvisioner {
	return &wrappedProvisioner{
		Interface: p,
		raInfo:    raInfo,
	}
}

// isRAProvisioner returns if the given provisioner is an RA provisioner.
func isRAProvisioner(p provisioner.Interface) bool {
	if rap, ok := p.(raProvisioner); ok {
		return rap.RAInfo() != nil
	}
	return false
}

// wrappedProvisioner implements raProvisioner and attProvisioner.
type wrappedProvisioner struct {
	provisioner.Interface
	attestationData *provisioner.AttestationData
	raInfo          *provisioner.RAInfo
}

func (p *wrappedProvisioner) AttestationData() *provisioner.AttestationData {
	return p.attestationData
}

func (p *wrappedProvisioner) RAInfo() *provisioner.RAInfo {
	return p.raInfo
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
	if p, err := a.unsafeLoadProvisionerFromDatabase(crt); err == nil {
		return p, nil
	}
	return a.unsafeLoadProvisionerFromExtension(crt)
}

func (a *Authority) unsafeLoadProvisionerFromExtension(crt *x509.Certificate) (provisioner.Interface, error) {
	p, ok := a.provisioners.LoadByCertificate(crt)
	if !ok || p.GetType() == 0 {
		return nil, admin.NewError(admin.ErrorNotFoundType, "unable to load provisioner from certificate")
	}
	return p, nil
}

func (a *Authority) unsafeLoadProvisionerFromDatabase(crt *x509.Certificate) (provisioner.Interface, error) {
	// certificateDataGetter is an interface that can be used to retrieve the
	// provisioner from a db or a linked ca.
	type certificateDataGetter interface {
		GetCertificateData(string) (*db.CertificateData, error)
	}

	var err error
	var data *db.CertificateData

	if cdg, ok := a.adminDB.(certificateDataGetter); ok {
		data, err = cdg.GetCertificateData(crt.SerialNumber.String())
	} else if cdg, ok := a.db.(certificateDataGetter); ok {
		data, err = cdg.GetCertificateData(crt.SerialNumber.String())
	}
	if err == nil && data != nil && data.Provisioner != nil {
		if p, ok := a.provisioners.Load(data.Provisioner.ID); ok {
			if data.RaInfo != nil {
				return wrapRAProvisioner(p, data.RaInfo), nil
			}
			return p, nil
		}
	}
	return nil, admin.NewError(admin.ErrorNotFoundType, "unable to load provisioner from certificate")
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
		SSHKeys: &provisioner.SSHKeys{
			UserKeys: sshKeys.UserKeys,
			HostKeys: sshKeys.HostKeys,
		},
		GetIdentityFunc:       a.getIdentityFunc,
		AuthorizeRenewFunc:    a.authorizeRenewFunc,
		AuthorizeSSHRenewFunc: a.authorizeSSHRenewFunc,
		WebhookClient:         a.webhookClient,
	}, nil
}

// StoreProvisioner stores a provisioner to the authority.
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

	if err := a.checkProvisionerPolicy(ctx, prov.Name, prov.Policy); err != nil {
		return err
	}

	if err := certProv.Init(provisionerConfig); err != nil {
		return admin.WrapError(admin.ErrorBadRequestType, err, "error validating configuration for provisioner %q", prov.Name)
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
		if err := a.ReloadAdminResources(ctx); err != nil {
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

	if err := a.checkProvisionerPolicy(ctx, nu.Name, nu.Policy); err != nil {
		return err
	}

	if err := certProv.Init(provisionerConfig); err != nil {
		return admin.WrapErrorISE(err, "error initializing provisioner %s", nu.Name)
	}

	if err := a.provisioners.Update(certProv); err != nil {
		return admin.WrapErrorISE(err, "error updating provisioner '%s' in authority cache", nu.Name)
	}
	if err := a.adminDB.UpdateProvisioner(ctx, nu); err != nil {
		if err := a.ReloadAdminResources(ctx); err != nil {
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
	if a.IsAdminAPIEnabled() {
		// Validate
		//  - Check that there will be SUPER_ADMINs that remain after we
		//    remove this provisioner.
		if a.IsAdminAPIEnabled() && a.admins.SuperCount() == a.admins.SuperCountByProvisioner(provName) {
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
	}

	// Remove provisioner from authority caches.
	if err := a.provisioners.Remove(provID); err != nil {
		return admin.WrapErrorISE(err, "error removing provisioner from authority cache")
	}
	// Remove provisioner from database.
	if err := a.adminDB.DeleteProvisioner(ctx, provID); err != nil {
		if err := a.ReloadAdminResources(ctx); err != nil {
			return admin.WrapErrorISE(err, "error reloading admin resources on failed provisioner remove")
		}
		return admin.WrapErrorISE(err, "error deleting provisioner %s", provName)
	}
	return nil
}

// CreateFirstProvisioner creates and stores the first provisioner when using
// admin database provisioner storage.
func CreateFirstProvisioner(ctx context.Context, adminDB admin.DB, password string) (*linkedca.Provisioner, error) {
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
	if err := adminDB.CreateProvisioner(ctx, p); err != nil {
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
	if pol := p.GetPolicy(); pol != nil {
		if x := pol.GetX509(); x != nil {
			if allow := x.GetAllow(); allow != nil {
				ops.X509.AllowedNames = &policy.X509NameOptions{
					DNSDomains:     allow.Dns,
					IPRanges:       allow.Ips,
					EmailAddresses: allow.Emails,
					URIDomains:     allow.Uris,
				}
			}
			if deny := x.GetDeny(); deny != nil {
				ops.X509.DeniedNames = &policy.X509NameOptions{
					DNSDomains:     deny.Dns,
					IPRanges:       deny.Ips,
					EmailAddresses: deny.Emails,
					URIDomains:     deny.Uris,
				}
			}
		}
		if ssh := pol.GetSsh(); ssh != nil {
			if host := ssh.GetHost(); host != nil {
				ops.SSH.Host = &policy.SSHHostCertificateOptions{}
				if allow := host.GetAllow(); allow != nil {
					ops.SSH.Host.AllowedNames = &policy.SSHNameOptions{
						DNSDomains: allow.Dns,
						IPRanges:   allow.Ips,
						Principals: allow.Principals,
					}
				}
				if deny := host.GetDeny(); deny != nil {
					ops.SSH.Host.DeniedNames = &policy.SSHNameOptions{
						DNSDomains: deny.Dns,
						IPRanges:   deny.Ips,
						Principals: deny.Principals,
					}
				}
			}
			if user := ssh.GetUser(); user != nil {
				ops.SSH.User = &policy.SSHUserCertificateOptions{}
				if allow := user.GetAllow(); allow != nil {
					ops.SSH.User.AllowedNames = &policy.SSHNameOptions{
						EmailAddresses: allow.Emails,
						Principals:     allow.Principals,
					}
				}
				if deny := user.GetDeny(); deny != nil {
					ops.SSH.User.DeniedNames = &policy.SSHNameOptions{
						EmailAddresses: deny.Emails,
						Principals:     deny.Principals,
					}
				}
			}
		}
	}
	for _, wh := range p.Webhooks {
		whCert := webhookToCertificates(wh)
		ops.Webhooks = append(ops.Webhooks, whCert)
	}
	return ops
}

func webhookToCertificates(wh *linkedca.Webhook) *provisioner.Webhook {
	pwh := &provisioner.Webhook{
		ID:                   wh.Id,
		Name:                 wh.Name,
		URL:                  wh.Url,
		Kind:                 wh.Kind.String(),
		Secret:               wh.Secret,
		DisableTLSClientAuth: wh.DisableTlsClientAuth,
		CertType:             wh.CertType.String(),
	}

	switch a := wh.GetAuth().(type) {
	case *linkedca.Webhook_BearerToken:
		pwh.BearerToken = a.BearerToken.BearerToken
	case *linkedca.Webhook_BasicAuth:
		pwh.BasicAuth.Username = a.BasicAuth.Username
		pwh.BasicAuth.Password = a.BasicAuth.Password
	}

	return pwh
}

func provisionerWebhookToLinkedca(pwh *provisioner.Webhook) *linkedca.Webhook {
	lwh := &linkedca.Webhook{
		Id:                   pwh.ID,
		Name:                 pwh.Name,
		Url:                  pwh.URL,
		Kind:                 linkedca.Webhook_Kind(linkedca.Webhook_Kind_value[pwh.Kind]),
		Secret:               pwh.Secret,
		DisableTlsClientAuth: pwh.DisableTLSClientAuth,
		CertType:             linkedca.Webhook_CertType(linkedca.Webhook_CertType_value[pwh.CertType]),
	}
	if pwh.BearerToken != "" {
		lwh.Auth = &linkedca.Webhook_BearerToken{
			BearerToken: &linkedca.BearerToken{
				BearerToken: pwh.BearerToken,
			},
		}
	} else if pwh.BasicAuth.Username != "" || pwh.BasicAuth.Password != "" {
		lwh.Auth = &linkedca.Webhook_BasicAuth{
			BasicAuth: &linkedca.BasicAuth{
				Username: pwh.BasicAuth.Username,
				Password: pwh.BasicAuth.Password,
			},
		}
	}

	return lwh
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
		//nolint:nilnil // nil claims do not pose an issue.
		return nil, nil
	}

	pc := &provisioner.Claims{
		DisableRenewal:             &c.DisableRenewal,
		AllowRenewalAfterExpiry:    &c.AllowRenewalAfterExpiry,
		DisableSmallstepExtensions: &c.DisableSmallstepExtensions,
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
	allowRenewalAfterExpiry := config.DefaultAllowRenewalAfterExpiry
	disableSmallstepExtensions := config.DefaultDisableSmallstepExtensions

	if c.DisableRenewal != nil {
		disableRenewal = *c.DisableRenewal
	}
	if c.AllowRenewalAfterExpiry != nil {
		allowRenewalAfterExpiry = *c.AllowRenewalAfterExpiry
	}
	if c.DisableSmallstepExtensions != nil {
		disableSmallstepExtensions = *c.DisableSmallstepExtensions
	}

	lc := &linkedca.Claims{
		DisableRenewal:             disableRenewal,
		AllowRenewalAfterExpiry:    allowRenewalAfterExpiry,
		DisableSmallstepExtensions: disableSmallstepExtensions,
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

func provisionerOptionsToLinkedca(p *provisioner.Options) (*linkedca.Template, *linkedca.Template, []*linkedca.Webhook, error) {
	var err error
	var x509Template, sshTemplate *linkedca.Template

	if p == nil {
		return nil, nil, nil, nil
	}

	if p.X509 != nil && p.X509.HasTemplate() {
		x509Template = &linkedca.Template{
			Template: nil,
			Data:     nil,
		}

		if p.X509.Template != "" {
			x509Template.Template = []byte(p.X509.Template)
		} else if p.X509.TemplateFile != "" {
			filename := step.Abs(p.X509.TemplateFile)
			if x509Template.Template, err = os.ReadFile(filename); err != nil {
				return nil, nil, nil, errors.Wrap(err, "error reading x509 template")
			}
		}

		if p.X509.TemplateData != nil {
			x509Template.Data = p.X509.TemplateData
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
				return nil, nil, nil, errors.Wrap(err, "error reading ssh template")
			}
		}

		if p.SSH.TemplateData != nil {
			sshTemplate.Data = p.SSH.TemplateData
		}
	}

	var webhooks []*linkedca.Webhook
	for _, pwh := range p.Webhooks {
		webhooks = append(webhooks, provisionerWebhookToLinkedca(pwh))
	}

	return x509Template, sshTemplate, webhooks, nil
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

func provisionerPEMToCertificates(bs [][]byte) []byte {
	var roots []byte
	for i, root := range bs {
		if i > 0 && !bytes.HasSuffix(root, []byte{'\n'}) {
			roots = append(roots, '\n')
		}
		roots = append(roots, root...)
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
			ID:                 p.Id,
			Type:               p.Type.String(),
			Name:               p.Name,
			ForceCN:            cfg.ForceCn,
			TermsOfService:     cfg.TermsOfService,
			Website:            cfg.Website,
			CaaIdentities:      cfg.CaaIdentities,
			RequireEAB:         cfg.RequireEab,
			Challenges:         challengesToCertificates(cfg.Challenges),
			AttestationFormats: attestationFormatsToCertificates(cfg.AttestationFormats),
			AttestationRoots:   provisionerPEMToCertificates(cfg.AttestationRoots),
			Claims:             claims,
			Options:            options,
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
		s := &provisioner.SCEP{
			ID:                            p.Id,
			Type:                          p.Type.String(),
			Name:                          p.Name,
			ForceCN:                       cfg.ForceCn,
			ChallengePassword:             cfg.Challenge,
			Capabilities:                  cfg.Capabilities,
			IncludeRoot:                   cfg.IncludeRoot,
			ExcludeIntermediate:           cfg.ExcludeIntermediate,
			MinimumPublicKeyLength:        int(cfg.MinimumPublicKeyLength),
			EncryptionAlgorithmIdentifier: int(cfg.EncryptionAlgorithmIdentifier),
			Claims:                        claims,
			Options:                       options,
		}
		if decrypter := cfg.GetDecrypter(); decrypter != nil {
			s.DecrypterCertificate = decrypter.Certificate
			s.DecrypterKeyPEM = decrypter.Key
			s.DecrypterKeyURI = decrypter.KeyUri
			s.DecrypterKeyPassword = string(decrypter.KeyPassword)
		}
		return s, nil
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
		x509Template, sshTemplate, webhooks, err := provisionerOptionsToLinkedca(p.Options)
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
			Webhooks:     webhooks,
		}, nil
	case *provisioner.OIDC:
		x509Template, sshTemplate, webhooks, err := provisionerOptionsToLinkedca(p.Options)
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
			Webhooks:     webhooks,
		}, nil
	case *provisioner.GCP:
		x509Template, sshTemplate, webhooks, err := provisionerOptionsToLinkedca(p.Options)
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
			Webhooks:     webhooks,
		}, nil
	case *provisioner.AWS:
		x509Template, sshTemplate, webhooks, err := provisionerOptionsToLinkedca(p.Options)
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
			Webhooks:     webhooks,
		}, nil
	case *provisioner.Azure:
		x509Template, sshTemplate, webhooks, err := provisionerOptionsToLinkedca(p.Options)
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
			Webhooks:     webhooks,
		}, nil
	case *provisioner.ACME:
		x509Template, sshTemplate, webhooks, err := provisionerOptionsToLinkedca(p.Options)
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
						ForceCn:            p.ForceCN,
						TermsOfService:     p.TermsOfService,
						Website:            p.Website,
						CaaIdentities:      p.CaaIdentities,
						RequireEab:         p.RequireEAB,
						Challenges:         challengesToLinkedca(p.Challenges),
						AttestationFormats: attestationFormatsToLinkedca(p.AttestationFormats),
						AttestationRoots:   provisionerPEMToLinkedca(p.AttestationRoots),
					},
				},
			},
			Claims:       claimsToLinkedca(p.Claims),
			X509Template: x509Template,
			SshTemplate:  sshTemplate,
			Webhooks:     webhooks,
		}, nil
	case *provisioner.X5C:
		x509Template, sshTemplate, webhooks, err := provisionerOptionsToLinkedca(p.Options)
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
			Webhooks:     webhooks,
		}, nil
	case *provisioner.K8sSA:
		x509Template, sshTemplate, webhooks, err := provisionerOptionsToLinkedca(p.Options)
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
			Webhooks:     webhooks,
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
		x509Template, sshTemplate, webhooks, err := provisionerOptionsToLinkedca(p.Options)
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
						Challenge:                     p.ChallengePassword,
						Capabilities:                  p.Capabilities,
						MinimumPublicKeyLength:        int32(p.MinimumPublicKeyLength),
						IncludeRoot:                   p.IncludeRoot,
						ExcludeIntermediate:           p.ExcludeIntermediate,
						EncryptionAlgorithmIdentifier: int32(p.EncryptionAlgorithmIdentifier),
						Decrypter: &linkedca.SCEPDecrypter{
							Certificate: p.DecrypterCertificate,
							Key:         p.DecrypterKeyPEM,
							KeyUri:      p.DecrypterKeyURI,
							KeyPassword: []byte(p.DecrypterKeyPassword),
						},
					},
				},
			},
			Claims:       claimsToLinkedca(p.Claims),
			X509Template: x509Template,
			SshTemplate:  sshTemplate,
			Webhooks:     webhooks,
		}, nil
	case *provisioner.Nebula:
		x509Template, sshTemplate, webhooks, err := provisionerOptionsToLinkedca(p.Options)
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
			Webhooks:     webhooks,
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

// challengesToCertificates converts linkedca challenges to provisioner ones
// skipping the unknown ones.
func challengesToCertificates(challenges []linkedca.ACMEProvisioner_ChallengeType) []provisioner.ACMEChallenge {
	ret := make([]provisioner.ACMEChallenge, 0, len(challenges))
	for _, ch := range challenges {
		switch ch {
		case linkedca.ACMEProvisioner_HTTP_01:
			ret = append(ret, provisioner.HTTP_01)
		case linkedca.ACMEProvisioner_DNS_01:
			ret = append(ret, provisioner.DNS_01)
		case linkedca.ACMEProvisioner_TLS_ALPN_01:
			ret = append(ret, provisioner.TLS_ALPN_01)
		case linkedca.ACMEProvisioner_DEVICE_ATTEST_01:
			ret = append(ret, provisioner.DEVICE_ATTEST_01)
		}
	}
	return ret
}

// challengesToLinkedca converts provisioner challenges to linkedca ones
// skipping the unknown ones.
func challengesToLinkedca(challenges []provisioner.ACMEChallenge) []linkedca.ACMEProvisioner_ChallengeType {
	ret := make([]linkedca.ACMEProvisioner_ChallengeType, 0, len(challenges))
	for _, ch := range challenges {
		switch provisioner.ACMEChallenge(ch.String()) {
		case provisioner.HTTP_01:
			ret = append(ret, linkedca.ACMEProvisioner_HTTP_01)
		case provisioner.DNS_01:
			ret = append(ret, linkedca.ACMEProvisioner_DNS_01)
		case provisioner.TLS_ALPN_01:
			ret = append(ret, linkedca.ACMEProvisioner_TLS_ALPN_01)
		case provisioner.DEVICE_ATTEST_01:
			ret = append(ret, linkedca.ACMEProvisioner_DEVICE_ATTEST_01)
		}
	}
	return ret
}

// attestationFormatsToCertificates converts linkedca attestation formats to
// provisioner ones skipping the unknown ones.
func attestationFormatsToCertificates(formats []linkedca.ACMEProvisioner_AttestationFormatType) []provisioner.ACMEAttestationFormat {
	ret := make([]provisioner.ACMEAttestationFormat, 0, len(formats))
	for _, f := range formats {
		switch f {
		case linkedca.ACMEProvisioner_APPLE:
			ret = append(ret, provisioner.APPLE)
		case linkedca.ACMEProvisioner_STEP:
			ret = append(ret, provisioner.STEP)
		case linkedca.ACMEProvisioner_TPM:
			ret = append(ret, provisioner.TPM)
		}
	}
	return ret
}

// attestationFormatsToLinkedca converts provisioner attestation formats to
// linkedca ones skipping the unknown ones.
func attestationFormatsToLinkedca(formats []provisioner.ACMEAttestationFormat) []linkedca.ACMEProvisioner_AttestationFormatType {
	ret := make([]linkedca.ACMEProvisioner_AttestationFormatType, 0, len(formats))
	for _, f := range formats {
		switch provisioner.ACMEAttestationFormat(f.String()) {
		case provisioner.APPLE:
			ret = append(ret, linkedca.ACMEProvisioner_APPLE)
		case provisioner.STEP:
			ret = append(ret, linkedca.ACMEProvisioner_STEP)
		case provisioner.TPM:
			ret = append(ret, linkedca.ACMEProvisioner_TPM)
		}
	}
	return ret
}
