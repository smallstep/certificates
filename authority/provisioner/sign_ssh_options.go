package provisioner

import (
	"fmt"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

const (
	// SSHUserCert is the string used to represent ssh.UserCert.
	SSHUserCert = "user"

	// SSHHostCert is the string used to represent ssh.HostCert.
	SSHHostCert = "host"
)

// SSHCertificateModifier is the interface used to change properties in an SSH
// certificate.
type SSHCertificateModifier interface {
	SignOption
	Modify(cert *ssh.Certificate) error
}

// SSHCertificateOptionModifier is the interface used to add custom options used
// to modify the SSH certificate.
type SSHCertificateOptionModifier interface {
	SignOption
	Option(o SSHOptions) SSHCertificateModifier
}

// SSHCertificateValidator is the interface used to validate an SSH certificate.
type SSHCertificateValidator interface {
	SignOption
	Valid(crt *ssh.Certificate) error
}

// SSHCertificateOptionsValidator is the interface used to validate the custom
// options used to modify the SSH certificate.
type SSHCertificateOptionsValidator interface {
	SignOption
	Valid(got SSHOptions) error
}

// SSHOptions contains the options that can be passed to the SignSSH method.
type SSHOptions struct {
	CertType    string       `json:"certType"`
	Principals  []string     `json:"principals"`
	ValidAfter  TimeDuration `json:"validAfter,omitempty"`
	ValidBefore TimeDuration `json:"validBefore,omitempty"`
}

// Type returns the uint32 representation of the CertType.
func (o SSHOptions) Type() uint32 {
	return sshCertTypeUInt32(o.CertType)
}

// Modify implements SSHCertificateModifier and sets the SSHOption in the ssh.Certificate.
func (o SSHOptions) Modify(cert *ssh.Certificate) error {
	switch o.CertType {
	case "": // ignore
	case SSHUserCert:
		cert.CertType = ssh.UserCert
	case SSHHostCert:
		cert.CertType = ssh.HostCert
	default:
		return errors.Errorf("ssh certificate has an unknown type: %s", o.CertType)
	}
	cert.ValidPrincipals = o.Principals
	if !o.ValidAfter.IsZero() {
		cert.ValidAfter = uint64(o.ValidAfter.Time().Unix())
	}
	if !o.ValidBefore.IsZero() {
		cert.ValidBefore = uint64(o.ValidBefore.Time().Unix())
	}
	if cert.ValidAfter > 0 && cert.ValidBefore > 0 && cert.ValidAfter > cert.ValidBefore {
		return errors.New("ssh certificate valid after cannot be greater than valid before")
	}
	return nil
}

// match compares two SSHOptions and return an error if they don't match. It
// ignores zero values.
func (o SSHOptions) match(got SSHOptions) error {
	if o.CertType != "" && got.CertType != "" && o.CertType != got.CertType {
		return errors.Errorf("ssh certificate type does not match - got %v, want %v", got.CertType, o.CertType)
	}
	if len(o.Principals) > 0 && len(got.Principals) > 0 && !equalStringSlice(o.Principals, got.Principals) {
		return errors.Errorf("ssh certificate principals does not match - got %v, want %v", got.Principals, o.Principals)
	}
	if !o.ValidAfter.IsZero() && !got.ValidAfter.IsZero() && !o.ValidAfter.Equal(&got.ValidAfter) {
		return errors.Errorf("ssh certificate valid after does not match - got %v, want %v", got.ValidAfter, o.ValidAfter)
	}
	if !o.ValidBefore.IsZero() && !got.ValidBefore.IsZero() && !o.ValidBefore.Equal(&got.ValidBefore) {
		return errors.Errorf("ssh certificate valid before does not match - got %v, want %v", got.ValidBefore, o.ValidBefore)
	}
	return nil
}

// sshCertificateKeyIDModifier is an SSHCertificateModifier that sets the given
// Key ID in the SSH certificate.
type sshCertificateKeyIDModifier string

func (m sshCertificateKeyIDModifier) Modify(cert *ssh.Certificate) error {
	cert.KeyId = string(m)
	return nil
}

// sshCertificateCertTypeModifier is an SSHCertificateModifier that sets the
// certificate type to the SSH certificate.
type sshCertificateCertTypeModifier string

func (m sshCertificateCertTypeModifier) Modify(cert *ssh.Certificate) error {
	cert.CertType = sshCertTypeUInt32(string(m))
	return nil
}

// sshCertificatePrincipalsModifier is an SSHCertificateModifier that sets the
// principals to the SSH certificate.
type sshCertificatePrincipalsModifier []string

func (m sshCertificatePrincipalsModifier) Modify(cert *ssh.Certificate) error {
	cert.ValidPrincipals = []string(m)
	return nil
}

// sshCertificateValidAfterModifier is an SSHCertificateModifier that sets the
// ValidAfter in the SSH certificate.
type sshCertificateValidAfterModifier uint64

func (m sshCertificateValidAfterModifier) Modify(cert *ssh.Certificate) error {
	cert.ValidAfter = uint64(m)
	return nil
}

// sshCertificateValidBeforeModifier is an SSHCertificateModifier that sets the
// ValidBefore in the SSH certificate.
type sshCertificateValidBeforeModifier uint64

func (m sshCertificateValidBeforeModifier) Modify(cert *ssh.Certificate) error {
	cert.ValidBefore = uint64(m)
	return nil
}

// sshDefaultExtensionModifier implements an SSHCertificateModifier that sets
// the default extensions in an SSH certificate.
type sshDefaultExtensionModifier struct{}

func (m *sshDefaultExtensionModifier) Modify(cert *ssh.Certificate) error {
	if cert.Extensions == nil {
		cert.Extensions = make(map[string]string)
	}
	cert.Extensions["permit-X11-forwarding"] = ""
	cert.Extensions["permit-agent-forwarding"] = ""
	cert.Extensions["permit-port-forwarding"] = ""
	cert.Extensions["permit-pty"] = ""
	cert.Extensions["permit-user-rc"] = ""
	return nil
}

// sshCertificateValidityModifier is a SSHCertificateModifier checks the
// validity bounds, setting them if they are not provided. It will fail if a
// CertType has not been set or is not valid.
type sshCertificateValidityModifier struct {
	*Claimer
}

func (m *sshCertificateValidityModifier) Modify(cert *ssh.Certificate) error {
	var d, min, max time.Duration
	switch cert.CertType {
	case ssh.UserCert:
		d = m.DefaultUserSSHCertDuration()
		min = m.MinUserSSHCertDuration()
		max = m.MaxUserSSHCertDuration()
	case ssh.HostCert:
		d = m.DefaultHostSSHCertDuration()
		min = m.MinHostSSHCertDuration()
		max = m.MaxHostSSHCertDuration()
	case 0:
		return errors.New("ssh certificate type has not been set")
	default:
		return errors.Errorf("unknown ssh certificate type %d", cert.CertType)
	}

	if cert.ValidAfter == 0 {
		cert.ValidAfter = uint64(now().Unix())
	}
	if cert.ValidBefore == 0 {
		t := time.Unix(int64(cert.ValidAfter), 0)
		cert.ValidBefore = uint64(t.Add(d).Unix())
	}

	diff := time.Duration(cert.ValidBefore-cert.ValidAfter) * time.Second
	switch {
	case diff < min:
		return errors.Errorf("ssh certificate duration cannot be lower than %s", min)
	case diff > max:
		return errors.Errorf("ssh certificate duration cannot be greater than %s", max)
	default:
		return nil
	}
}

// sshCertificateOptionsValidator validates the user SSHOptions with the ones
// usually present in the token.
type sshCertificateOptionsValidator struct {
	Want *SSHOptions
}

// Valid implements SSHCertificateOptionsValidator and returns nil if both
// SSHOptions match.
func (v *sshCertificateOptionsValidator) Valid(got SSHOptions) error {
	if v.Want == nil {
		return nil
	}
	return v.Want.match(got)
}

// sshCertificateDefaultValidator implements a simple validator for all the
// fields in the SSH certificate.
type sshCertificateDefaultValidator struct{}

// Valid returns an error if the given certificate does not contain the necessary fields.
func (v *sshCertificateDefaultValidator) Valid(crt *ssh.Certificate) error {
	switch {
	case len(crt.Nonce) == 0:
		return errors.New("ssh certificate nonce cannot be empty")
	case crt.Key == nil:
		return errors.New("ssh certificate key cannot be nil")
	case crt.Serial == 0:
		return errors.New("ssh certificate serial cannot be 0")
	case crt.CertType != ssh.UserCert && crt.CertType != ssh.HostCert:
		return errors.Errorf("ssh certificate has an unknown type: %d", crt.CertType)
	case crt.KeyId == "":
		return errors.New("ssh certificate key id cannot be empty")
	case len(crt.ValidPrincipals) == 0:
		return errors.New("ssh certificate valid principals cannot be empty")
	case crt.ValidAfter == 0:
		return errors.New("ssh certificate valid after cannot be 0")
	case crt.ValidBefore == 0:
		return errors.New("ssh certificate valid before cannot be 0")
	case len(crt.Extensions) == 0:
		return errors.New("ssh certificate extensions cannot be empty")
	case crt.SignatureKey == nil:
		return errors.New("ssh certificate signature key cannot be nil")
	case crt.Signature == nil:
		return errors.New("ssh certificate signature cannot be nil")
	default:
		return nil
	}
}

// sshCertTypeName returns the string representation of the given ssh.CertType.
func sshCertTypeString(ct uint32) string {
	switch ct {
	case 0:
		return ""
	case ssh.UserCert:
		return SSHUserCert
	case ssh.HostCert:
		return SSHHostCert
	default:
		return fmt.Sprintf("unknown (%d)", ct)
	}
}

// sshCertTypeUInt32
func sshCertTypeUInt32(ct string) uint32 {
	switch ct {
	case SSHUserCert:
		return ssh.UserCert
	case SSHHostCert:
		return ssh.HostCert
	default:
		return 0
	}
}

func equalStringSlice(a, b []string) bool {
	var l int
	if l = len(a); l != len(b) {
		return false
	}
	visit := make(map[string]struct{}, l)
	for i := 0; i < l; i++ {
		visit[a[i]] = struct{}{}
	}
	for i := 0; i < l; i++ {
		if _, ok := visit[b[i]]; !ok {
			return false
		}
	}
	return true
}
