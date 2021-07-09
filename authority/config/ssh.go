package config

import (
	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/provisioner"
	"go.step.sm/crypto/jose"
	"golang.org/x/crypto/ssh"
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

// HostTag are tagged with k,v pairs. These tags are how a user is ultimately
// associated with a host.
type HostTag struct {
	ID    string
	Name  string
	Value string
}

// Host defines expected attributes for an ssh host.
type Host struct {
	HostID   string    `json:"hid"`
	HostTags []HostTag `json:"host_tags"`
	Hostname string    `json:"hostname"`
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
