package policy

import (
	"golang.org/x/crypto/ssh"
)

type SSHNamePolicyEngine interface {
	IsSSHCertificateAllowed(cert *ssh.Certificate) error
}
