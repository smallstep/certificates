package authority

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/certificates/errs"
	"github.com/smallstep/certificates/sshutil"
	"github.com/smallstep/certificates/templates"
	"github.com/smallstep/cli/crypto/randutil"
	"github.com/smallstep/cli/jose"
	"golang.org/x/crypto/ssh"
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

// SSHConfig contains the user and host keys.
type SSHConfig struct {
	HostKey          string          `json:"hostKey"`
	UserKey          string          `json:"userKey"`
	Keys             []*SSHPublicKey `json:"keys,omitempty"`
	AddUserPrincipal string          `json:"addUserPrincipal,omitempty"`
	AddUserCommand   string          `json:"addUserCommand,omitempty"`
	Bastion          *Bastion        `json:"bastion,omitempty"`
}

// Bastion contains the custom properties used on bastion.
type Bastion struct {
	Hostname string `json:"hostname"`
	User     string `json:"user,omitempty"`
	Port     string `json:"port,omitempty"`
	Command  string `json:"cmd,omitempty"`
	Flags    string `json:"flags,omitempty"`
}

// Validate checks the fields in SSHConfig.
func (c *SSHConfig) Validate() error {
	if c == nil {
		return nil
	}
	for _, k := range c.Keys {
		if err := k.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// SSHPublicKey contains a public key used by federated CAs to keep old signing
// keys for this ca.
type SSHPublicKey struct {
	Type      string          `json:"type"`
	Federated bool            `json:"federated"`
	Key       jose.JSONWebKey `json:"key"`
	publicKey ssh.PublicKey
}

// Validate checks the fields in SSHPublicKey.
func (k *SSHPublicKey) Validate() error {
	switch {
	case k.Type == "":
		return errors.New("type cannot be empty")
	case k.Type != provisioner.SSHHostCert && k.Type != provisioner.SSHUserCert:
		return errors.Errorf("invalid type %s, it must be user or host", k.Type)
	case !k.Key.IsPublic():
		return errors.New("invalid key type, it must be a public key")
	}

	key, err := ssh.NewPublicKey(k.Key.Key)
	if err != nil {
		return errors.Wrap(err, "error creating ssh key")
	}
	k.publicKey = key
	return nil
}

// PublicKey returns the ssh public key.
func (k *SSHPublicKey) PublicKey() ssh.PublicKey {
	return k.publicKey
}

// SSHKeys represents the SSH User and Host public keys.
type SSHKeys struct {
	UserKeys []ssh.PublicKey
	HostKeys []ssh.PublicKey
}

// GetSSHRoots returns the SSH User and Host public keys.
func (a *Authority) GetSSHRoots(context.Context) (*SSHKeys, error) {
	return &SSHKeys{
		HostKeys: a.sshCAHostCerts,
		UserKeys: a.sshCAUserCerts,
	}, nil
}

// GetSSHFederation returns the public keys for federated SSH signers.
func (a *Authority) GetSSHFederation(context.Context) (*SSHKeys, error) {
	return &SSHKeys{
		HostKeys: a.sshCAHostFederatedCerts,
		UserKeys: a.sshCAUserFederatedCerts,
	}, nil
}

// GetSSHConfig returns rendered templates for clients (user) or servers (host).
func (a *Authority) GetSSHConfig(ctx context.Context, typ string, data map[string]string) ([]templates.Output, error) {
	if a.sshCAUserCertSignKey == nil && a.sshCAHostCertSignKey == nil {
		return nil, errs.NotFound("getSSHConfig: ssh is not configured")
	}

	var ts []templates.Template
	switch typ {
	case provisioner.SSHUserCert:
		if a.config.Templates != nil && a.config.Templates.SSH != nil {
			ts = a.config.Templates.SSH.User
		}
	case provisioner.SSHHostCert:
		if a.config.Templates != nil && a.config.Templates.SSH != nil {
			ts = a.config.Templates.SSH.Host
		}
	default:
		return nil, errs.BadRequest("getSSHConfig: type %s is not valid", typ)
	}

	// Merge user and default data
	var mergedData map[string]interface{}

	if len(data) == 0 {
		mergedData = a.config.Templates.Data
	} else {
		mergedData = make(map[string]interface{}, len(a.config.Templates.Data)+1)
		mergedData["User"] = data
		for k, v := range a.config.Templates.Data {
			mergedData[k] = v
		}
	}

	// Render templates
	output := []templates.Output{}
	for _, t := range ts {
		o, err := t.Output(mergedData)
		if err != nil {
			return nil, err
		}
		output = append(output, o)
	}
	return output, nil
}

// GetSSHBastion returns the bastion configuration, for the given pair user,
// hostname.
func (a *Authority) GetSSHBastion(ctx context.Context, user string, hostname string) (*Bastion, error) {
	if a.sshBastionFunc != nil {
		bs, err := a.sshBastionFunc(ctx, user, hostname)
		return bs, errs.Wrap(http.StatusInternalServerError, err, "authority.GetSSHBastion")
	}
	if a.config.SSH != nil {
		if a.config.SSH.Bastion != nil && a.config.SSH.Bastion.Hostname != "" {
			return a.config.SSH.Bastion, nil
		}
		return nil, nil
	}
	return nil, errs.NotFound("authority.GetSSHBastion; ssh is not configured")
}

// SignSSH creates a signed SSH certificate with the given public key and options.
func (a *Authority) SignSSH(ctx context.Context, key ssh.PublicKey, opts provisioner.SSHOptions, signOpts ...provisioner.SignOption) (*ssh.Certificate, error) {
	var mods []provisioner.SSHCertModifier
	var validators []provisioner.SSHCertValidator

	// Set backdate with the configured value
	opts.Backdate = a.config.AuthorityConfig.Backdate.Duration

	for _, op := range signOpts {
		switch o := op.(type) {
		// modify the ssh.Certificate
		case provisioner.SSHCertModifier:
			mods = append(mods, o)
		// modify the ssh.Certificate given the SSHOptions
		case provisioner.SSHCertOptionModifier:
			mods = append(mods, o.Option(opts))
		// validate the ssh.Certificate
		case provisioner.SSHCertValidator:
			validators = append(validators, o)
		// validate the given SSHOptions
		case provisioner.SSHCertOptionsValidator:
			if err := o.Valid(opts); err != nil {
				return nil, errs.Wrap(http.StatusForbidden, err, "signSSH")
			}
		default:
			return nil, errs.InternalServer("signSSH: invalid extra option type %T", o)
		}
	}

	nonce, err := randutil.ASCII(32)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "signSSH")
	}

	var serial uint64
	if err := binary.Read(rand.Reader, binary.BigEndian, &serial); err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "signSSH: error reading random number")
	}

	// Build base certificate with the key and some random values
	cert := &ssh.Certificate{
		Nonce:  []byte(nonce),
		Key:    key,
		Serial: serial,
	}

	// Use opts to modify the certificate
	if err := opts.Modify(cert); err != nil {
		return nil, errs.Wrap(http.StatusForbidden, err, "signSSH")
	}

	// Use provisioner modifiers
	for _, m := range mods {
		if err := m.Modify(cert); err != nil {
			return nil, errs.Wrap(http.StatusForbidden, err, "signSSH")
		}
	}

	// Get signer from authority keys
	var signer ssh.Signer
	switch cert.CertType {
	case ssh.UserCert:
		if a.sshCAUserCertSignKey == nil {
			return nil, errs.NotImplemented("signSSH: user certificate signing is not enabled")
		}
		signer = a.sshCAUserCertSignKey
	case ssh.HostCert:
		if a.sshCAHostCertSignKey == nil {
			return nil, errs.NotImplemented("signSSH: host certificate signing is not enabled")
		}
		signer = a.sshCAHostCertSignKey
	default:
		return nil, errs.InternalServer("signSSH: unexpected ssh certificate type: %d", cert.CertType)
	}
	cert.SignatureKey = signer.PublicKey()

	// Get bytes for signing trailing the signature length.
	data := cert.Marshal()
	data = data[:len(data)-4]

	// Sign the certificate
	sig, err := signer.Sign(rand.Reader, data)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "signSSH: error signing certificate")
	}
	cert.Signature = sig

	// User provisioners validators
	for _, v := range validators {
		if err := v.Valid(cert, opts); err != nil {
			return nil, errs.Wrap(http.StatusForbidden, err, "signSSH")
		}
	}

	if err = a.db.StoreSSHCertificate(cert); err != nil && err != db.ErrNotImplemented {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "signSSH: error storing certificate in db")
	}

	return cert, nil
}

// RenewSSH creates a signed SSH certificate using the old SSH certificate as a template.
func (a *Authority) RenewSSH(ctx context.Context, oldCert *ssh.Certificate) (*ssh.Certificate, error) {
	nonce, err := randutil.ASCII(32)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "renewSSH")
	}

	var serial uint64
	if err := binary.Read(rand.Reader, binary.BigEndian, &serial); err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "renewSSH: error reading random number")
	}

	if oldCert.ValidAfter == 0 || oldCert.ValidBefore == 0 {
		return nil, errs.BadRequest("rewnewSSH: cannot renew certificate without validity period")
	}

	backdate := a.config.AuthorityConfig.Backdate.Duration
	duration := time.Duration(oldCert.ValidBefore-oldCert.ValidAfter) * time.Second
	now := time.Now()
	va := now.Add(-1 * backdate)
	vb := now.Add(duration - backdate)

	// Build base certificate with the key and some random values
	cert := &ssh.Certificate{
		Nonce:           []byte(nonce),
		Key:             oldCert.Key,
		Serial:          serial,
		CertType:        oldCert.CertType,
		KeyId:           oldCert.KeyId,
		ValidPrincipals: oldCert.ValidPrincipals,
		Permissions:     oldCert.Permissions,
		ValidAfter:      uint64(va.Unix()),
		ValidBefore:     uint64(vb.Unix()),
	}

	// Get signer from authority keys
	var signer ssh.Signer
	switch cert.CertType {
	case ssh.UserCert:
		if a.sshCAUserCertSignKey == nil {
			return nil, errs.NotImplemented("renewSSH: user certificate signing is not enabled")
		}
		signer = a.sshCAUserCertSignKey
	case ssh.HostCert:
		if a.sshCAHostCertSignKey == nil {
			return nil, errs.NotImplemented("renewSSH: host certificate signing is not enabled")
		}
		signer = a.sshCAHostCertSignKey
	default:
		return nil, errs.InternalServer("renewSSH: unexpected ssh certificate type: %d", cert.CertType)
	}
	cert.SignatureKey = signer.PublicKey()

	// Get bytes for signing trailing the signature length.
	data := cert.Marshal()
	data = data[:len(data)-4]

	// Sign the certificate
	sig, err := signer.Sign(rand.Reader, data)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "renewSSH: error signing certificate")
	}
	cert.Signature = sig

	if err = a.db.StoreSSHCertificate(cert); err != nil && err != db.ErrNotImplemented {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "renewSSH: error storing certificate in db")
	}

	return cert, nil
}

// RekeySSH creates a signed SSH certificate using the old SSH certificate as a template.
func (a *Authority) RekeySSH(ctx context.Context, oldCert *ssh.Certificate, pub ssh.PublicKey, signOpts ...provisioner.SignOption) (*ssh.Certificate, error) {
	var validators []provisioner.SSHCertValidator

	for _, op := range signOpts {
		switch o := op.(type) {
		// validate the ssh.Certificate
		case provisioner.SSHCertValidator:
			validators = append(validators, o)
		default:
			return nil, errs.InternalServer("rekeySSH; invalid extra option type %T", o)
		}
	}

	nonce, err := randutil.ASCII(32)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "rekeySSH")
	}

	var serial uint64
	if err := binary.Read(rand.Reader, binary.BigEndian, &serial); err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "rekeySSH; error reading random number")
	}

	if oldCert.ValidAfter == 0 || oldCert.ValidBefore == 0 {
		return nil, errs.BadRequest("rekeySSH; cannot rekey certificate without validity period")
	}

	backdate := a.config.AuthorityConfig.Backdate.Duration
	duration := time.Duration(oldCert.ValidBefore-oldCert.ValidAfter) * time.Second
	now := time.Now()
	va := now.Add(-1 * backdate)
	vb := now.Add(duration - backdate)

	// Build base certificate with the key and some random values
	cert := &ssh.Certificate{
		Nonce:           []byte(nonce),
		Key:             pub,
		Serial:          serial,
		CertType:        oldCert.CertType,
		KeyId:           oldCert.KeyId,
		ValidPrincipals: oldCert.ValidPrincipals,
		Permissions:     oldCert.Permissions,
		ValidAfter:      uint64(va.Unix()),
		ValidBefore:     uint64(vb.Unix()),
	}

	// Get signer from authority keys
	var signer ssh.Signer
	switch cert.CertType {
	case ssh.UserCert:
		if a.sshCAUserCertSignKey == nil {
			return nil, errs.NotImplemented("rekeySSH; user certificate signing is not enabled")
		}
		signer = a.sshCAUserCertSignKey
	case ssh.HostCert:
		if a.sshCAHostCertSignKey == nil {
			return nil, errs.NotImplemented("rekeySSH; host certificate signing is not enabled")
		}
		signer = a.sshCAHostCertSignKey
	default:
		return nil, errs.BadRequest("rekeySSH; unexpected ssh certificate type: %d", cert.CertType)
	}
	cert.SignatureKey = signer.PublicKey()

	// Get bytes for signing trailing the signature length.
	data := cert.Marshal()
	data = data[:len(data)-4]

	// Sign the certificate.
	sig, err := signer.Sign(rand.Reader, data)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "rekeySSH; error signing certificate")
	}
	cert.Signature = sig

	// Apply validators from provisioner.
	for _, v := range validators {
		if err := v.Valid(cert, provisioner.SSHOptions{Backdate: backdate}); err != nil {
			return nil, errs.Wrap(http.StatusForbidden, err, "rekeySSH")
		}
	}

	if err = a.db.StoreSSHCertificate(cert); err != nil && err != db.ErrNotImplemented {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "rekeySSH; error storing certificate in db")
	}

	return cert, nil
}

// IsValidForAddUser checks if a user provisioner certificate can be issued to
// the given certificate.
func IsValidForAddUser(cert *ssh.Certificate) error {
	if cert.CertType != ssh.UserCert {
		return errors.New("certificate is not a user certificate")
	}

	switch len(cert.ValidPrincipals) {
	case 0:
		return errors.New("certificate does not have any principals")
	case 1:
		return nil
	case 2:
		// OIDC provisioners adds a second principal with the email address.
		// @ cannot be the first character.
		if strings.Index(cert.ValidPrincipals[1], "@") > 0 {
			return nil
		}
		return errors.New("certificate does not have only one principal")
	default:
		return errors.New("certificate does not have only one principal")
	}
}

// SignSSHAddUser signs a certificate that provisions a new user in a server.
func (a *Authority) SignSSHAddUser(ctx context.Context, key ssh.PublicKey, subject *ssh.Certificate) (*ssh.Certificate, error) {
	if a.sshCAUserCertSignKey == nil {
		return nil, errs.NotImplemented("signSSHAddUser: user certificate signing is not enabled")
	}
	if err := IsValidForAddUser(subject); err != nil {
		return nil, errs.Wrap(http.StatusForbidden, err, "signSSHAddUser")
	}

	nonce, err := randutil.ASCII(32)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "signSSHAddUser")
	}

	var serial uint64
	if err := binary.Read(rand.Reader, binary.BigEndian, &serial); err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "signSSHAddUser: error reading random number")
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

	if err = a.db.StoreSSHCertificate(cert); err != nil && err != db.ErrNotImplemented {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "signSSHAddUser: error storing certificate in db")
	}

	return cert, nil
}

// CheckSSHHost checks the given principal has been registered before.
func (a *Authority) CheckSSHHost(ctx context.Context, principal string, token string) (bool, error) {
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
		if err == db.ErrNotImplemented {
			return false, errs.Wrap(http.StatusNotImplemented, err,
				"checkSSHHost: isSSHHost is not implemented")
		}
		return false, errs.Wrap(http.StatusInternalServerError, err,
			"checkSSHHost: error checking if hosts exists")
	}

	return exists, nil
}

// GetSSHHosts returns a list of valid host principals.
func (a *Authority) GetSSHHosts(ctx context.Context, cert *x509.Certificate) ([]sshutil.Host, error) {
	if a.sshGetHostsFunc != nil {
		hosts, err := a.sshGetHostsFunc(ctx, cert)
		return hosts, errs.Wrap(http.StatusInternalServerError, err, "getSSHHosts")
	}
	hostnames, err := a.db.GetSSHHostPrincipals()
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "getSSHHosts")
	}

	hosts := make([]sshutil.Host, len(hostnames))
	for i, hn := range hostnames {
		hosts[i] = sshutil.Host{Hostname: hn}
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
	return strings.Replace(cmd, "<principal>", principal, -1)
}
