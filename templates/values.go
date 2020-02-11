package templates

import (
	"golang.org/x/crypto/ssh"
)

// Step represents the default variables available in the CA.
type Step struct {
	SSH StepSSH
}

// StepSSH holds SSH-related values for the CA.
type StepSSH struct {
	HostKey           ssh.PublicKey
	UserKey           ssh.PublicKey
	HostFederatedKeys []ssh.PublicKey
	UserFederatedKeys []ssh.PublicKey
}
