package policy

import (
	"golang.org/x/crypto/ssh"
)

type SSHNamePolicyEngine interface {
	ArePrincipalsAllowed(cert *ssh.Certificate) (bool, error)
}
