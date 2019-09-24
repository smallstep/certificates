package provisioner

import (
	"crypto/rsa"
	"encoding/binary"
	"math/big"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/keys"
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
	Valid(cert *ssh.Certificate) error
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
	if len(o.Principals) > 0 && len(got.Principals) > 0 && !containsAllMembers(o.Principals, got.Principals) {
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

// sshCertificateDefaultModifier implements a SSHCertificateModifier that
// modifies the certificate with the given options if they are not set.
type sshCertificateDefaultsModifier SSHOptions

// Modify implements the SSHCertificateModifier interface.
func (m sshCertificateDefaultsModifier) Modify(cert *ssh.Certificate) error {
	if cert.CertType == 0 {
		cert.CertType = sshCertTypeUInt32(m.CertType)
	}
	if len(cert.ValidPrincipals) == 0 {
		cert.ValidPrincipals = m.Principals
	}
	if cert.ValidAfter == 0 && !m.ValidAfter.IsZero() {
		cert.ValidAfter = uint64(m.ValidAfter.Unix())
	}
	if cert.ValidBefore == 0 && !m.ValidBefore.IsZero() {
		cert.ValidBefore = uint64(m.ValidBefore.Unix())
	}
	return nil
}

// sshDefaultExtensionModifier implements an SSHCertificateModifier that sets
// the default extensions in an SSH certificate.
type sshDefaultExtensionModifier struct{}

func (m *sshDefaultExtensionModifier) Modify(cert *ssh.Certificate) error {
	switch cert.CertType {
	// Default to no extensions for HostCert.
	case ssh.HostCert:
		return nil
	case ssh.UserCert:
		if cert.Extensions == nil {
			cert.Extensions = make(map[string]string)
		}
		cert.Extensions["permit-X11-forwarding"] = ""
		cert.Extensions["permit-agent-forwarding"] = ""
		cert.Extensions["permit-port-forwarding"] = ""
		cert.Extensions["permit-pty"] = ""
		cert.Extensions["permit-user-rc"] = ""
		return nil
	default:
		return errors.New("ssh certificate type has not been set or is invalid")
	}
}

// sshCertificateValidityModifier is a SSHCertificateModifier checks the
// validity bounds, setting them if they are not provided. It will fail if a
// CertType has not been set or is not valid.
type sshCertificateValidityModifier struct {
	*Claimer
	// RemainingProvisioningCredentialDuraion is the remaining duration on the
	// provisioning credential.
	// E.g. x5c provisioners use a certificate as a provisioning credential.
	// That certificate should not be able to provision new certificates with
	// a duration longer than the remaining duration on the provisioning
	// certificate.
	RemainingProvisioningCredentialDuraion time.Duration
}

func (m *sshCertificateValidityModifier) Modify(cert *ssh.Certificate) error {
	var (
		d, min, max time.Duration
		rem         = m.RemainingProvisioningCredentialDuraion
	)
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

	// Use the remaining duration from the provisioning duration to set bounds
	// and values if it is supplied.
	if rem > 0 {
		// If the remaining duration is less than the min duration for the requested
		// type of SSH certificate then return an error.
		if rem < min {
			return errors.New("remaining duration on X5C certificate in the token " +
				"is less than the minimum SSH duration on the X5C provisioner")
		}
		// If the remaining duration from the provisioning credential is less than
		// the max duration for the requested type of SSH certificate then we
		// reset our max bound.
		if rem < max {
			max = rem
		}
		// If the remaining duration from the provisioning credential is less than
		// the default duration for the requested type of SSH certificate then we
		// reset our default duration.
		if rem < d {
			d = rem
		}
	}

	if cert.ValidAfter == 0 {
		cert.ValidAfter = uint64(now().Truncate(time.Second).Unix())
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
type sshCertificateOptionsValidator SSHOptions

// Valid implements SSHCertificateOptionsValidator and returns nil if both
// SSHOptions match.
func (v sshCertificateOptionsValidator) Valid(got SSHOptions) error {
	want := SSHOptions(v)
	return want.match(got)
}

// sshCertificateDefaultValidator implements a simple validator for all the
// fields in the SSH certificate.
type sshCertificateDefaultValidator struct{}

// Valid returns an error if the given certificate does not contain the necessary fields.
func (v *sshCertificateDefaultValidator) Valid(cert *ssh.Certificate) error {
	switch {
	case len(cert.Nonce) == 0:
		return errors.New("ssh certificate nonce cannot be empty")
	case cert.Key == nil:
		return errors.New("ssh certificate key cannot be nil")
	case cert.Serial == 0:
		return errors.New("ssh certificate serial cannot be 0")
	case cert.CertType != ssh.UserCert && cert.CertType != ssh.HostCert:
		return errors.Errorf("ssh certificate has an unknown type: %d", cert.CertType)
	case cert.KeyId == "":
		return errors.New("ssh certificate key id cannot be empty")
	case len(cert.ValidPrincipals) == 0:
		return errors.New("ssh certificate valid principals cannot be empty")
	case cert.ValidAfter == 0:
		return errors.New("ssh certificate validAfter cannot be 0")
	case cert.ValidBefore < uint64(now().Unix()):
		return errors.New("ssh certificate validBefore cannot be in the past")
	case cert.ValidBefore < cert.ValidAfter:
		return errors.New("ssh certificate validBefore cannot be before validAfter")
	case cert.CertType == ssh.UserCert && len(cert.Extensions) == 0:
		return errors.New("ssh certificate extensions cannot be empty")
	case cert.SignatureKey == nil:
		return errors.New("ssh certificate signature key cannot be nil")
	case cert.Signature == nil:
		return errors.New("ssh certificate signature cannot be nil")
	default:
		return nil
	}
}

// sshDefaultPublicKeyValidator implements a validator for the certificate key.
type sshDefaultPublicKeyValidator struct{}

// Valid checks that certificate request common name matches the one configured.
func (v sshDefaultPublicKeyValidator) Valid(cert *ssh.Certificate) error {
	if cert.Key == nil {
		return errors.New("ssh certificate key cannot be nil")
	}
	switch cert.Key.Type() {
	case ssh.KeyAlgoRSA:
		_, in, ok := sshParseString(cert.Key.Marshal())
		if !ok {
			return errors.New("ssh certificate key is invalid")
		}
		key, err := sshParseRSAPublicKey(in)
		if err != nil {
			return err
		}
		if key.Size() < keys.MinRSAKeyBytes {
			return errors.Errorf("ssh certificate key must be at least %d bits (%d bytes)",
				8*keys.MinRSAKeyBytes, keys.MinRSAKeyBytes)
		}
		return nil
	case ssh.KeyAlgoDSA:
		return errors.New("ssh certificate key algorithm (DSA) is not supported")
	default:
		return nil
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

// containsAllMembers reports whether all members of subgroup are within group.
func containsAllMembers(group, subgroup []string) bool {
	lg, lsg := len(group), len(subgroup)
	if lsg > lg || (lg > 0 && lsg == 0) {
		return false
	}
	visit := make(map[string]struct{}, lg)
	for i := 0; i < lg; i++ {
		visit[group[i]] = struct{}{}
	}
	for i := 0; i < lsg; i++ {
		if _, ok := visit[subgroup[i]]; !ok {
			return false
		}
	}
	return true
}

func sshParseString(in []byte) (out, rest []byte, ok bool) {
	if len(in) < 4 {
		return
	}
	length := binary.BigEndian.Uint32(in)
	in = in[4:]
	if uint32(len(in)) < length {
		return
	}
	out = in[:length]
	rest = in[length:]
	ok = true
	return
}

func sshParseRSAPublicKey(in []byte) (*rsa.PublicKey, error) {
	var w struct {
		E    *big.Int
		N    *big.Int
		Rest []byte `ssh:"rest"`
	}
	if err := ssh.Unmarshal(in, &w); err != nil {
		return nil, errors.Wrap(err, "error unmarshalling public key")
	}
	if w.E.BitLen() > 24 {
		return nil, errors.New("invalid public key: exponent too large")
	}
	e := w.E.Int64()
	if e < 3 || e&1 == 0 {
		return nil, errors.New("invalid public key: incorrect exponent")
	}

	var key rsa.PublicKey
	key.E = int(e)
	key.N = w.N
	return &key, nil
}
