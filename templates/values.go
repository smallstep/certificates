package templates

import (
	"golang.org/x/crypto/ssh"
)

// Step represents the default variables available in the CA.
type Step struct {
	SSH StepSSH
}

type StepSSH struct {
	HostKey           ssh.PublicKey
	UserKey           ssh.PublicKey
	HostFederatedKeys []ssh.PublicKey
	UserFederatedKeys []ssh.PublicKey
}
