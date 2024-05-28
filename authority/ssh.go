package authority

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"go.step.sm/crypto/randutil"
	"go.step.sm/crypto/sshutil"

	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/certificates/errs"
	"github.com/smallstep/certificates/templates"
	"github.com/smallstep/certificates/webhook"
)

const (
	// SSHAddUserPrincipal is the principal that will run the add user command.
	// Defaults to "provisioner" but it can be changed in the configuration.
	SSHAddUserPrincipal = "provisioner"

	// SSHAddUserCommand is the default command to run to add a new user.
	// Defaults to "sudo useradd -m <principal>; nc -q0 localhost 22" but it can be changed in the
	// configuration. The string "<principal>" will be replace by the new
	// principal to add.
	SSHAddUserCommand = "sudo useradd -m <principal>; nc -q0 localhost 22"
)

// GetSSHRoots returns the SSH User and Host public keys.
func (a *Authority) GetSSHRoots(context.Context) (*config.SSHKeys, error) {
	return &config.SSHKeys{
		HostKeys: a.sshCAHostCerts,
		UserKeys: a.sshCAUserCerts,
	}, nil
}

// GetSSHFederation returns the public keys for federated SSH signers.
func (a *Authority) GetSSHFederation(context.Context) (*config.SSHKeys, error) {
	return &config.SSHKeys{
		HostKeys: a.sshCAHostFederatedCerts,
		UserKeys: a.sshCAUserFederatedCerts,
	}, nil
}

// GetSSHConfig returns rendered templates for clients (user) or servers (host).
func (a *Authority) GetSSHConfig(_ context.Context, typ string, data map[string]string) ([]templates.Output, error) {
	if a.sshCAUserCertSignKey == nil && a.sshCAHostCertSignKey == nil {
		return nil, errs.NotFound("getSSHConfig: ssh is not configured")
	}

	if a.templates == nil {
		return nil, errs.NotFound("getSSHConfig: ssh templates are not configured")
	}

	var ts []templates.Template
	switch typ {
	case provisioner.SSHUserCert:
		if a.templates != nil && a.templates.SSH != nil {
			ts = a.templates.SSH.User
		}
	case provisioner.SSHHostCert:
		if a.templates != nil && a.templates.SSH != nil {
			ts = a.templates.SSH.Host
		}
	default:
		return nil, errs.BadRequest("invalid certificate type '%s'", typ)
	}

	// Merge user and default data
	var mergedData map[string]interface{}

	if len(data) == 0 {
		mergedData = a.templates.Data
	} else {
		mergedData = make(map[string]interface{}, len(a.templates.Data)+1)
		mergedData["User"] = data
		for k, v := range a.templates.Data {
			mergedData[k] = v
		}
	}

	// Render templates
	output := []templates.Output{}
	for _, t := range ts {
		if err := t.Load(); err != nil {
			return nil, err
		}

		// Check for required variables.
		if err := t.ValidateRequiredData(data); err != nil {
			return nil, errs.BadRequestErr(err, "%v, please use `--set <key=value>` flag", err)
		}

		o, err := t.Output(mergedData)
		if err != nil {
			return nil, err
		}

		// Backwards compatibility for version of the cli older than v0.18.0.
		// Before v0.18.0 we were not passing any value for SSHTemplateVersionKey
		// from the cli.
		if o.Name == "step_includes.tpl" && data[templates.SSHTemplateVersionKey] == "" {
			o.Type = templates.File
			o.Path = strings.TrimPrefix(o.Path, "${STEPPATH}/")
		}

		output = append(output, o)
	}
	return output, nil
}

// GetSSHBastion returns the bastion configuration, for the given pair user,
// hostname.
func (a *Authority) GetSSHBastion(ctx context.Context, user, hostname string) (*config.Bastion, error) {
	if a.sshBastionFunc != nil {
		bs, err := a.sshBastionFunc(ctx, user, hostname)
		return bs, errs.Wrap(http.StatusInternalServerError, err, "authority.GetSSHBastion")
	}
	if a.config.SSH != nil {
		if a.config.SSH.Bastion != nil && a.config.SSH.Bastion.Hostname != "" {
			// Do not return a bastion for a bastion host.
			//
			// This condition might fail if a different name or IP is used.
			// Trying to resolve hostnames to IPs and compare them won't be a
			// complete solution because it depends on the network
			// configuration, of the CA and clients and can also return false
			// positives. Although not perfect, this simple solution will work
			// in most cases.
			if !strings.EqualFold(hostname, a.config.SSH.Bastion.Hostname) {
				return a.config.SSH.Bastion, nil
			}
		}
		//nolint:nilnil // legacy
		return nil, nil
	}
	return nil, errs.NotFound("authority.GetSSHBastion; ssh is not configured")
}

// SignSSH creates a signed SSH certificate with the given public key and options.
func (a *Authority) SignSSH(ctx context.Context, key ssh.PublicKey, opts provisioner.SignSSHOptions, signOpts ...provisioner.SignOption) (*ssh.Certificate, error) {
	cert, prov, err := a.signSSH(ctx, key, opts, signOpts...)
	a.meter.SSHSigned(prov, err)
	return cert, err
}

func (a *Authority) signSSH(ctx context.Context, key ssh.PublicKey, opts provisioner.SignSSHOptions, signOpts ...provisioner.SignOption) (*ssh.Certificate, provisioner.Interface, error) {
	var (
		certOptions []sshutil.Option
		mods        []provisioner.SSHCertModifier
		validators  []provisioner.SSHCertValidator
	)

	// Validate given options.
	if err := opts.Validate(); err != nil {
		return nil, nil, err
	}

	// Set backdate with the configured value
	opts.Backdate = a.config.AuthorityConfig.Backdate.Duration

	var prov provisioner.Interface
	var webhookCtl webhookController
	for _, op := range signOpts {
		switch o := op.(type) {
		// Capture current provisioner
		case provisioner.Interface:
			prov = o

		// add options to NewCertificate
		case provisioner.SSHCertificateOptions:
			certOptions = append(certOptions, o.Options(opts)...)

		// modify the ssh.Certificate
		case provisioner.SSHCertModifier:
			mods = append(mods, o)

		// validate the ssh.Certificate
		case provisioner.SSHCertValidator:
			validators = append(validators, o)

		// validate the given SSHOptions
		case provisioner.SSHCertOptionsValidator:
			if err := o.Valid(opts); err != nil {
				return nil, prov, errs.BadRequestErr(err, "error validating ssh certificate options")
			}

		// call webhooks
		case webhookController:
			webhookCtl = o

		default:
			return nil, prov, errs.InternalServer("authority.SignSSH: invalid extra option type %T", o)
		}
	}

	// Simulated certificate request with request options.
	cr := sshutil.CertificateRequest{
		Type:       opts.CertType,
		KeyID:      opts.KeyID,
		Principals: opts.Principals,
		Key:        key,
	}

	// Call enriching webhooks
	if err := a.callEnrichingWebhooksSSH(ctx, prov, webhookCtl, cr); err != nil {
		return nil, prov, errs.ApplyOptions(
			errs.ForbiddenErr(err, err.Error()),
			errs.WithKeyVal("signOptions", signOpts),
		)
	}

	// Create certificate from template.
	certificate, err := sshutil.NewCertificate(cr, certOptions...)
	if err != nil {
		var te *sshutil.TemplateError
		switch {
		case errors.As(err, &te):
			return nil, prov, errs.ApplyOptions(
				errs.BadRequestErr(err, err.Error()),
				errs.WithKeyVal("signOptions", signOpts),
			)
		case strings.HasPrefix(err.Error(), "error unmarshaling certificate"):
			// explicitly check for unmarshaling errors, which are most probably caused by JSON template syntax errors
			return nil, prov, errs.InternalServerErr(templatingError(err),
				errs.WithKeyVal("signOptions", signOpts),
				errs.WithMessage("error applying certificate template"),
			)
		default:
			return nil, prov, errs.Wrap(http.StatusInternalServerError, err, "authority.SignSSH")
		}
	}

	// Get actual *ssh.Certificate and continue with provisioner modifiers.
	certTpl := certificate.GetCertificate()

	// Use SignSSHOptions to modify the certificate validity. It will be later
	// checked or set if not defined.
	if err := opts.ModifyValidity(certTpl); err != nil {
		return nil, prov, errs.BadRequestErr(err, err.Error())
	}

	// Use provisioner modifiers.
	for _, m := range mods {
		if err := m.Modify(certTpl, opts); err != nil {
			return nil, prov, errs.ForbiddenErr(err, "error creating ssh certificate")
		}
	}

	// Get signer from authority keys
	var signer ssh.Signer
	switch certTpl.CertType {
	case ssh.UserCert:
		if a.sshCAUserCertSignKey == nil {
			return nil, prov, errs.NotImplemented("authority.SignSSH: user certificate signing is not enabled")
		}
		signer = a.sshCAUserCertSignKey
	case ssh.HostCert:
		if a.sshCAHostCertSignKey == nil {
			return nil, prov, errs.NotImplemented("authority.SignSSH: host certificate signing is not enabled")
		}
		signer = a.sshCAHostCertSignKey
	default:
		return nil, prov, errs.InternalServer("authority.SignSSH: unexpected ssh certificate type: %d", certTpl.CertType)
	}

	// Check if authority is allowed to sign the certificate
	if err := a.isAllowedToSignSSHCertificate(certTpl); err != nil {
		var ee *errs.Error
		if errors.As(err, &ee) {
			return nil, prov, ee
		}
		return nil, prov, errs.InternalServerErr(err,
			errs.WithMessage("authority.SignSSH: error creating ssh certificate"),
		)
	}

	// Send certificate to webhooks for authorization
	if err := a.callAuthorizingWebhooksSSH(ctx, prov, webhookCtl, certificate, certTpl); err != nil {
		return nil, prov, errs.ApplyOptions(
			errs.ForbiddenErr(err, "authority.SignSSH: error signing certificate"),
		)
	}

	// Sign certificate.
	cert, err := sshutil.CreateCertificate(certTpl, signer)
	if err != nil {
		return nil, prov, errs.Wrap(http.StatusInternalServerError, err, "authority.SignSSH: error signing certificate")
	}

	// User provisioners validators.
	for _, v := range validators {
		if err := v.Valid(cert, opts); err != nil {
			return nil, prov, errs.ForbiddenErr(err, "error validating ssh certificate")
		}
	}

	if err := a.storeSSHCertificate(prov, cert); err != nil && !errors.Is(err, db.ErrNotImplemented) {
		return nil, prov, errs.Wrap(http.StatusInternalServerError, err, "authority.SignSSH: error storing certificate in db")
	}

	return cert, prov, nil
}

// isAllowedToSignSSHCertificate checks if the Authority is allowed to sign the SSH certificate.
func (a *Authority) isAllowedToSignSSHCertificate(cert *ssh.Certificate) error {
	return a.policyEngine.IsSSHCertificateAllowed(cert)
}

// RenewSSH creates a signed SSH certificate using the old SSH certificate as a template.
func (a *Authority) RenewSSH(ctx context.Context, oldCert *ssh.Certificate) (*ssh.Certificate, error) {
	cert, prov, err := a.renewSSH(ctx, oldCert)
	a.meter.SSHRenewed(prov, err)
	return cert, err
}

func (a *Authority) renewSSH(ctx context.Context, oldCert *ssh.Certificate) (*ssh.Certificate, provisioner.Interface, error) {
	if oldCert.ValidAfter == 0 || oldCert.ValidBefore == 0 {
		return nil, nil, errs.BadRequest("cannot renew a certificate without validity period")
	}

	if err := a.authorizeSSHCertificate(ctx, oldCert); err != nil {
		return nil, nil, err
	}

	// Attempt to extract the provisioner from the token.
	var prov provisioner.Interface
	if token, ok := provisioner.TokenFromContext(ctx); ok {
		prov, _, _ = a.getProvisionerFromToken(token)
	}

	backdate := a.config.AuthorityConfig.Backdate.Duration
	duration := time.Duration(oldCert.ValidBefore-oldCert.ValidAfter) * time.Second
	now := time.Now()
	va := now.Add(-1 * backdate)
	vb := now.Add(duration - backdate)

	// Build base certificate with the old key.
	// Nonce and serial will be automatically generated on signing.
	certTpl := &ssh.Certificate{
		Key:             oldCert.Key,
		CertType:        oldCert.CertType,
		KeyId:           oldCert.KeyId,
		ValidPrincipals: oldCert.ValidPrincipals,
		Permissions:     oldCert.Permissions,
		Reserved:        oldCert.Reserved,
		ValidAfter:      uint64(va.Unix()),
		ValidBefore:     uint64(vb.Unix()),
	}

	// Get signer from authority keys
	var signer ssh.Signer
	switch certTpl.CertType {
	case ssh.UserCert:
		if a.sshCAUserCertSignKey == nil {
			return nil, prov, errs.NotImplemented("renewSSH: user certificate signing is not enabled")
		}
		signer = a.sshCAUserCertSignKey
	case ssh.HostCert:
		if a.sshCAHostCertSignKey == nil {
			return nil, prov, errs.NotImplemented("renewSSH: host certificate signing is not enabled")
		}
		signer = a.sshCAHostCertSignKey
	default:
		return nil, prov, errs.InternalServer("renewSSH: unexpected ssh certificate type: %d", certTpl.CertType)
	}

	// Sign certificate.
	cert, err := sshutil.CreateCertificate(certTpl, signer)
	if err != nil {
		return nil, prov, errs.Wrap(http.StatusInternalServerError, err, "signSSH: error signing certificate")
	}

	if err := a.storeRenewedSSHCertificate(prov, oldCert, cert); err != nil && !errors.Is(err, db.ErrNotImplemented) {
		return nil, prov, errs.Wrap(http.StatusInternalServerError, err, "renewSSH: error storing certificate in db")
	}

	return cert, prov, nil
}

// RekeySSH creates a signed SSH certificate using the old SSH certificate as a template.
func (a *Authority) RekeySSH(ctx context.Context, oldCert *ssh.Certificate, pub ssh.PublicKey, signOpts ...provisioner.SignOption) (*ssh.Certificate, error) {
	cert, prov, err := a.rekeySSH(ctx, oldCert, pub, signOpts...)
	a.meter.SSHRekeyed(prov, err)
	return cert, err
}

func (a *Authority) rekeySSH(ctx context.Context, oldCert *ssh.Certificate, pub ssh.PublicKey, signOpts ...provisioner.SignOption) (*ssh.Certificate, provisioner.Interface, error) {
	var prov provisioner.Interface
	var validators []provisioner.SSHCertValidator
	for _, op := range signOpts {
		switch o := op.(type) {
		// Capture current provisioner
		case provisioner.Interface:
			prov = o
		// validate the ssh.Certificate
		case provisioner.SSHCertValidator:
			validators = append(validators, o)
		default:
			return nil, prov, errs.InternalServer("rekeySSH; invalid extra option type %T", o)
		}
	}

	if oldCert.ValidAfter == 0 || oldCert.ValidBefore == 0 {
		return nil, prov, errs.BadRequest("cannot rekey a certificate without validity period")
	}

	if err := a.authorizeSSHCertificate(ctx, oldCert); err != nil {
		return nil, prov, err
	}

	backdate := a.config.AuthorityConfig.Backdate.Duration
	duration := time.Duration(oldCert.ValidBefore-oldCert.ValidAfter) * time.Second
	now := time.Now()
	va := now.Add(-1 * backdate)
	vb := now.Add(duration - backdate)

	// Build base certificate with the new key.
	// Nonce and serial will be automatically generated on signing.
	cert := &ssh.Certificate{
		Key:             pub,
		CertType:        oldCert.CertType,
		KeyId:           oldCert.KeyId,
		ValidPrincipals: oldCert.ValidPrincipals,
		Permissions:     oldCert.Permissions,
		Reserved:        oldCert.Reserved,
		ValidAfter:      uint64(va.Unix()),
		ValidBefore:     uint64(vb.Unix()),
	}

	// Get signer from authority keys
	var signer ssh.Signer
	switch cert.CertType {
	case ssh.UserCert:
		if a.sshCAUserCertSignKey == nil {
			return nil, prov, errs.NotImplemented("rekeySSH; user certificate signing is not enabled")
		}
		signer = a.sshCAUserCertSignKey
	case ssh.HostCert:
		if a.sshCAHostCertSignKey == nil {
			return nil, prov, errs.NotImplemented("rekeySSH; host certificate signing is not enabled")
		}
		signer = a.sshCAHostCertSignKey
	default:
		return nil, prov, errs.BadRequest("unexpected certificate type '%d'", cert.CertType)
	}

	var err error
	// Sign certificate.
	cert, err = sshutil.CreateCertificate(cert, signer)
	if err != nil {
		return nil, prov, errs.Wrap(http.StatusInternalServerError, err, "signSSH: error signing certificate")
	}

	// Apply validators from provisioner.
	for _, v := range validators {
		if err := v.Valid(cert, provisioner.SignSSHOptions{Backdate: backdate}); err != nil {
			return nil, prov, errs.ForbiddenErr(err, "error validating ssh certificate")
		}
	}

	if err := a.storeRenewedSSHCertificate(prov, oldCert, cert); err != nil && !errors.Is(err, db.ErrNotImplemented) {
		return nil, prov, errs.Wrap(http.StatusInternalServerError, err, "rekeySSH; error storing certificate in db")
	}

	return cert, prov, nil
}

func (a *Authority) storeSSHCertificate(prov provisioner.Interface, cert *ssh.Certificate) error {
	type sshCertificateStorer interface {
		StoreSSHCertificate(provisioner.Interface, *ssh.Certificate) error
	}

	// Store certificate in admindb or linkedca
	switch s := a.adminDB.(type) {
	case sshCertificateStorer:
		return s.StoreSSHCertificate(prov, cert)
	case db.CertificateStorer:
		return s.StoreSSHCertificate(cert)
	}

	// Store certificate in localdb
	switch s := a.db.(type) {
	case sshCertificateStorer:
		return s.StoreSSHCertificate(prov, cert)
	case db.CertificateStorer:
		return s.StoreSSHCertificate(cert)
	default:
		return nil
	}
}

func (a *Authority) storeRenewedSSHCertificate(prov provisioner.Interface, parent, cert *ssh.Certificate) error {
	type sshRenewerCertificateStorer interface {
		StoreRenewedSSHCertificate(p provisioner.Interface, parent, cert *ssh.Certificate) error
	}

	// Store certificate in admindb or linkedca
	switch s := a.adminDB.(type) {
	case sshRenewerCertificateStorer:
		return s.StoreRenewedSSHCertificate(prov, parent, cert)
	case db.CertificateStorer:
		return s.StoreSSHCertificate(cert)
	}

	// Store certificate in localdb
	switch s := a.db.(type) {
	case sshRenewerCertificateStorer:
		return s.StoreRenewedSSHCertificate(prov, parent, cert)
	case db.CertificateStorer:
		return s.StoreSSHCertificate(cert)
	default:
		return nil
	}
}

// IsValidForAddUser checks if a user provisioner certificate can be issued to
// the given certificate.
func IsValidForAddUser(cert *ssh.Certificate) error {
	if cert.CertType != ssh.UserCert {
		return errs.Forbidden("certificate is not a user certificate")
	}

	switch len(cert.ValidPrincipals) {
	case 0:
		return errs.Forbidden("certificate does not have any principals")
	case 1:
		return nil
	case 2:
		// OIDC provisioners adds a second principal with the email address.
		// @ cannot be the first character.
		if strings.Index(cert.ValidPrincipals[1], "@") > 0 {
			return nil
		}
		return errs.Forbidden("certificate does not have only one principal")
	default:
		return errs.Forbidden("certificate does not have only one principal")
	}
}

// SignSSHAddUser signs a certificate that provisions a new user in a server.
func (a *Authority) SignSSHAddUser(ctx context.Context, key ssh.PublicKey, subject *ssh.Certificate) (*ssh.Certificate, error) {
	if a.sshCAUserCertSignKey == nil {
		return nil, errs.NotImplemented("signSSHAddUser: user certificate signing is not enabled")
	}
	if err := IsValidForAddUser(subject); err != nil {
		return nil, err
	}

	nonce, err := randutil.ASCII(32)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "signSSHAddUser")
	}

	var serial uint64
	if err := binary.Read(rand.Reader, binary.BigEndian, &serial); err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "signSSHAddUser: error reading random number")
	}

	// Attempt to extract the provisioner from the token.
	var prov provisioner.Interface
	if token, ok := provisioner.TokenFromContext(ctx); ok {
		prov, _, _ = a.getProvisionerFromToken(token)
	}

	signer := a.sshCAUserCertSignKey
	principal := subject.ValidPrincipals[0]
	addUserPrincipal := a.getAddUserPrincipal()

	cert := &ssh.Certificate{
		Nonce:           []byte(nonce),
		Key:             key,
		Serial:          serial,
		CertType:        ssh.UserCert,
		KeyId:           principal + "-" + addUserPrincipal,
		ValidPrincipals: []string{addUserPrincipal},
		ValidAfter:      subject.ValidAfter,
		ValidBefore:     subject.ValidBefore,
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{
				"force-command": a.getAddUserCommand(principal),
			},
		},
		SignatureKey: signer.PublicKey(),
	}

	// Get bytes for signing trailing the signature length.
	data := cert.Marshal()
	data = data[:len(data)-4]

	// Sign the certificate
	sig, err := signer.Sign(rand.Reader, data)
	if err != nil {
		return nil, err
	}
	cert.Signature = sig

	if err = a.storeRenewedSSHCertificate(prov, subject, cert); err != nil && !errors.Is(err, db.ErrNotImplemented) {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "signSSHAddUser: error storing certificate in db")
	}

	return cert, nil
}

// CheckSSHHost checks the given principal has been registered before.
func (a *Authority) CheckSSHHost(ctx context.Context, principal, token string) (bool, error) {
	if a.sshCheckHostFunc != nil {
		exists, err := a.sshCheckHostFunc(ctx, principal, token, a.GetRootCertificates())
		if err != nil {
			return false, errs.Wrap(http.StatusInternalServerError, err,
				"checkSSHHost: error from injected checkSSHHost func")
		}
		return exists, nil
	}
	exists, err := a.db.IsSSHHost(principal)
	if err != nil {
		if errors.Is(err, db.ErrNotImplemented) {
			return false, errs.Wrap(http.StatusNotImplemented, err,
				"checkSSHHost: isSSHHost is not implemented")
		}
		return false, errs.Wrap(http.StatusInternalServerError, err,
			"checkSSHHost: error checking if hosts exists")
	}

	return exists, nil
}

// GetSSHHosts returns a list of valid host principals.
func (a *Authority) GetSSHHosts(ctx context.Context, cert *x509.Certificate) ([]config.Host, error) {
	if a.GetConfig().AuthorityConfig.DisableGetSSHHosts {
		return nil, errs.New(http.StatusNotFound, "ssh hosts list api disabled")
	}
	if a.sshGetHostsFunc != nil {
		hosts, err := a.sshGetHostsFunc(ctx, cert)
		return hosts, errs.Wrap(http.StatusInternalServerError, err, "getSSHHosts")
	}
	hostnames, err := a.db.GetSSHHostPrincipals()
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "getSSHHosts")
	}

	hosts := make([]config.Host, len(hostnames))
	for i, hn := range hostnames {
		hosts[i] = config.Host{Hostname: hn}
	}
	return hosts, nil
}

func (a *Authority) getAddUserPrincipal() (cmd string) {
	if a.config.SSH.AddUserPrincipal == "" {
		return SSHAddUserPrincipal
	}
	return a.config.SSH.AddUserPrincipal
}

func (a *Authority) getAddUserCommand(principal string) string {
	var cmd string
	if a.config.SSH.AddUserCommand == "" {
		cmd = SSHAddUserCommand
	} else {
		cmd = a.config.SSH.AddUserCommand
	}
	return strings.ReplaceAll(cmd, "<principal>", principal)
}

func (a *Authority) callEnrichingWebhooksSSH(ctx context.Context, prov provisioner.Interface, webhookCtl webhookController, cr sshutil.CertificateRequest) (err error) {
	if webhookCtl == nil {
		return
	}
	defer func() { a.meter.SSHWebhookEnriched(prov, err) }()

	var whEnrichReq *webhook.RequestBody
	if whEnrichReq, err = webhook.NewRequestBody(
		webhook.WithSSHCertificateRequest(cr),
	); err == nil {
		err = webhookCtl.Enrich(ctx, whEnrichReq)
	}

	return
}

func (a *Authority) callAuthorizingWebhooksSSH(ctx context.Context, prov provisioner.Interface, webhookCtl webhookController, cert *sshutil.Certificate, certTpl *ssh.Certificate) (err error) {
	if webhookCtl == nil {
		return
	}
	defer func() { a.meter.SSHWebhookAuthorized(prov, err) }()

	var whAuthBody *webhook.RequestBody
	if whAuthBody, err = webhook.NewRequestBody(
		webhook.WithSSHCertificate(cert, certTpl),
	); err == nil {
		err = webhookCtl.Authorize(ctx, whAuthBody)
	}

	return
}
