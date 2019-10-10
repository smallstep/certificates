package authority

import (
	"crypto/rand"
	"encoding/binary"
	"net/http"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/db"
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
	AddUserPrincipal string          `json:"addUserPrincipal"`
	AddUserCommand   string          `json:"addUserCommand"`
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
func (a *Authority) GetSSHRoots() (*SSHKeys, error) {
	return &SSHKeys{
		HostKeys: a.sshCAHostCerts,
		UserKeys: a.sshCAUserCerts,
	}, nil
}

// GetSSHFederation returns the public keys for federated SSH signers.
func (a *Authority) GetSSHFederation() (*SSHKeys, error) {
	return &SSHKeys{
		HostKeys: a.sshCAHostFederatedCerts,
		UserKeys: a.sshCAUserFederatedCerts,
	}, nil
}

// GetSSHConfig returns rendered templates for clients (user) or servers (host).
func (a *Authority) GetSSHConfig(typ string, data map[string]string) ([]templates.Output, error) {
	if a.sshCAUserCertSignKey == nil && a.sshCAHostCertSignKey == nil {
		return nil, &apiError{
			err:  errors.New("getSSHConfig: ssh is not configured"),
			code: http.StatusNotFound,
		}
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
		return nil, &apiError{
			err:  errors.Errorf("getSSHConfig: type %s is not valid", typ),
			code: http.StatusBadRequest,
		}
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

// SignSSH creates a signed SSH certificate with the given public key and options.
func (a *Authority) SignSSH(key ssh.PublicKey, opts provisioner.SSHOptions, signOpts ...provisioner.SignOption) (*ssh.Certificate, error) {
	var mods []provisioner.SSHCertificateModifier
	var validators []provisioner.SSHCertificateValidator

	for _, op := range signOpts {
		switch o := op.(type) {
		// modify the ssh.Certificate
		case provisioner.SSHCertificateModifier:
			mods = append(mods, o)
		// modify the ssh.Certificate given the SSHOptions
		case provisioner.SSHCertificateOptionModifier:
			mods = append(mods, o.Option(opts))
		// validate the ssh.Certificate
		case provisioner.SSHCertificateValidator:
			validators = append(validators, o)
		// validate the given SSHOptions
		case provisioner.SSHCertificateOptionsValidator:
			if err := o.Valid(opts); err != nil {
				return nil, &apiError{err: err, code: http.StatusForbidden}
			}
		default:
			return nil, &apiError{
				err:  errors.Errorf("signSSH: invalid extra option type %T", o),
				code: http.StatusInternalServerError,
			}
		}
	}

	nonce, err := randutil.ASCII(32)
	if err != nil {
		return nil, &apiError{err: err, code: http.StatusInternalServerError}
	}

	var serial uint64
	if err := binary.Read(rand.Reader, binary.BigEndian, &serial); err != nil {
		return nil, &apiError{
			err:  errors.Wrap(err, "signSSH: error reading random number"),
			code: http.StatusInternalServerError,
		}
	}

	// Build base certificate with the key and some random values
	cert := &ssh.Certificate{
		Nonce:  []byte(nonce),
		Key:    key,
		Serial: serial,
	}

	// Use opts to modify the certificate
	if err := opts.Modify(cert); err != nil {
		return nil, &apiError{err: err, code: http.StatusForbidden}
	}

	// Use provisioner modifiers
	for _, m := range mods {
		if err := m.Modify(cert); err != nil {
			return nil, &apiError{err: err, code: http.StatusForbidden}
		}
	}

	// Get signer from authority keys
	var signer ssh.Signer
	switch cert.CertType {
	case ssh.UserCert:
		if a.sshCAUserCertSignKey == nil {
			return nil, &apiError{
				err:  errors.New("signSSH: user certificate signing is not enabled"),
				code: http.StatusNotImplemented,
			}
		}
		signer = a.sshCAUserCertSignKey
	case ssh.HostCert:
		if a.sshCAHostCertSignKey == nil {
			return nil, &apiError{
				err:  errors.New("signSSH: host certificate signing is not enabled"),
				code: http.StatusNotImplemented,
			}
		}
		signer = a.sshCAHostCertSignKey
	default:
		return nil, &apiError{
			err:  errors.Errorf("signSSH: unexpected ssh certificate type: %d", cert.CertType),
			code: http.StatusInternalServerError,
		}
	}
	cert.SignatureKey = signer.PublicKey()

	// Get bytes for signing trailing the signature length.
	data := cert.Marshal()
	data = data[:len(data)-4]

	// Sign the certificate
	sig, err := signer.Sign(rand.Reader, data)
	if err != nil {
		return nil, &apiError{
			err:  errors.Wrap(err, "signSSH: error signing certificate"),
			code: http.StatusInternalServerError,
		}
	}
	cert.Signature = sig

	// User provisioners validators
	for _, v := range validators {
		if err := v.Valid(cert); err != nil {
			return nil, &apiError{err: err, code: http.StatusForbidden}
		}
	}

	if err = a.db.StoreSSHCertificate(cert); err != nil && err != db.ErrNotImplemented {
		return nil, &apiError{
			err:  errors.Wrap(err, "signSSH: error storing certificate in db"),
			code: http.StatusInternalServerError,
		}
	}

	return cert, nil
}

// SignSSHAddUser signs a certificate that provisions a new user in a server.
func (a *Authority) SignSSHAddUser(key ssh.PublicKey, subject *ssh.Certificate) (*ssh.Certificate, error) {
	if a.sshCAUserCertSignKey == nil {
		return nil, &apiError{
			err:  errors.New("signSSHAddUser: user certificate signing is not enabled"),
			code: http.StatusNotImplemented,
		}
	}
	if subject.CertType != ssh.UserCert {
		return nil, &apiError{
			err:  errors.New("signSSHAddUser: certificate is not a user certificate"),
			code: http.StatusForbidden,
		}
	}
	if len(subject.ValidPrincipals) != 1 {
		return nil, &apiError{
			err:  errors.New("signSSHAddUser: certificate does not have only one principal"),
			code: http.StatusForbidden,
		}
	}

	nonce, err := randutil.ASCII(32)
	if err != nil {
		return nil, &apiError{err: err, code: http.StatusInternalServerError}
	}

	var serial uint64
	if err := binary.Read(rand.Reader, binary.BigEndian, &serial); err != nil {
		return nil, &apiError{
			err:  errors.Wrap(err, "signSSHAddUser: error reading random number"),
			code: http.StatusInternalServerError,
		}
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
		return nil, &apiError{
			err:  errors.Wrap(err, "signSSHAddUser: error storing certificate in db"),
			code: http.StatusInternalServerError,
		}
	}

	return cert, nil
}

// CheckSSHHost checks the given principal has been registered before.
func (a *Authority) CheckSSHHost(principal string) (bool, error) {
	exists, err := a.db.IsSSHHost(principal)
	if err != nil {
		if err == db.ErrNotImplemented {
			return false, &apiError{
				err:  errors.Wrap(err, "checkSSHHost: isSSHHost is not implemented"),
				code: http.StatusNotImplemented,
			}
		}
		return false, &apiError{
			err:  errors.Wrap(err, "checkSSHHost: error checking if hosts exists"),
			code: http.StatusInternalServerError,
		}
	}

	return exists, nil
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
