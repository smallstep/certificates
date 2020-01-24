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

// SSHCertModifier is the interface used to change properties in an SSH
// certificate.
type SSHCertModifier interface {
	SignOption
	Modify(cert *ssh.Certificate) error
}

// SSHCertOptionModifier is the interface used to add custom options used
// to modify the SSH certificate.
type SSHCertOptionModifier interface {
	SignOption
	Option(o SSHOptions) SSHCertModifier
}

// SSHCertValidator is the interface used to validate an SSH certificate.
type SSHCertValidator interface {
	SignOption
	Valid(cert *ssh.Certificate, opts SSHOptions) error
}

// SSHCertOptionsValidator is the interface used to validate the custom
// options used to modify the SSH certificate.
type SSHCertOptionsValidator interface {
	SignOption
	Valid(got SSHOptions) error
}

// sshModifierFunc is an adapter to allow the use of ordinary functions as SSH
// certificate modifiers.
type sshModifierFunc func(cert *ssh.Certificate) error

func (f sshModifierFunc) Modify(cert *ssh.Certificate) error {
	return f(cert)
}

// SSHOptions contains the options that can be passed to the SignSSH method.
type SSHOptions struct {
	CertType    string        `json:"certType"`
	KeyID       string        `json:"keyID"`
	Principals  []string      `json:"principals"`
	ValidAfter  TimeDuration  `json:"validAfter,omitempty"`
	ValidBefore TimeDuration  `json:"validBefore,omitempty"`
	Backdate    time.Duration `json:"-"`
}

// Type returns the uint32 representation of the CertType.
func (o SSHOptions) Type() uint32 {
	return sshCertTypeUInt32(o.CertType)
}

// Modify implements SSHCertModifier and sets the SSHOption in the ssh.Certificate.
func (o SSHOptions) Modify(cert *ssh.Certificate) error {
	switch o.CertType {
	case "": // ignore
	case SSHUserCert:
		cert.CertType = ssh.UserCert
	case SSHHostCert:
		cert.CertType = ssh.HostCert
	default:
		return errors.Errorf("ssh certificate has an unknown type - %s", o.CertType)
	}

	cert.KeyId = o.KeyID
	cert.ValidPrincipals = o.Principals

	t := now()
	if !o.ValidAfter.IsZero() {
		cert.ValidAfter = uint64(o.ValidAfter.RelativeTime(t).Unix())
	}
	if !o.ValidBefore.IsZero() {
		cert.ValidBefore = uint64(o.ValidBefore.RelativeTime(t).Unix())
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

// sshCertPrincipalsModifier is an SSHCertModifier that sets the
// principals to the SSH certificate.
type sshCertPrincipalsModifier []string

// Modify the ValidPrincipals value of the cert.
func (o sshCertPrincipalsModifier) Modify(cert *ssh.Certificate) error {
	cert.ValidPrincipals = []string(o)
	return nil
}

// sshCertKeyIDModifier is an SSHCertModifier that sets the given
// Key ID in the SSH certificate.
type sshCertKeyIDModifier string

func (m sshCertKeyIDModifier) Modify(cert *ssh.Certificate) error {
	cert.KeyId = string(m)
	return nil
}

// sshCertTypeModifier is an SSHCertModifier that sets the
// certificate type.
type sshCertTypeModifier string

// Modify sets the CertType for the ssh certificate.
func (m sshCertTypeModifier) Modify(cert *ssh.Certificate) error {
	cert.CertType = sshCertTypeUInt32(string(m))
	return nil
}

// sshCertValidAfterModifier is an SSHCertModifier that sets the
// ValidAfter in the SSH certificate.
type sshCertValidAfterModifier uint64

func (m sshCertValidAfterModifier) Modify(cert *ssh.Certificate) error {
	cert.ValidAfter = uint64(m)
	return nil
}

// sshCertValidBeforeModifier is an SSHCertModifier that sets the
// ValidBefore in the SSH certificate.
type sshCertValidBeforeModifier uint64

func (m sshCertValidBeforeModifier) Modify(cert *ssh.Certificate) error {
	cert.ValidBefore = uint64(m)
	return nil
}

// sshCertDefaultsModifier implements a SSHCertModifier that
// modifies the certificate with the given options if they are not set.
type sshCertDefaultsModifier SSHOptions

// Modify implements the SSHCertModifier interface.
func (m sshCertDefaultsModifier) Modify(cert *ssh.Certificate) error {
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

// sshDefaultExtensionModifier implements an SSHCertModifier that sets
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

// sshDefaultDuration is an SSHCertModifier that sets the certificate
// ValidAfter and ValidBefore if they have not been set. It will fail if a
// CertType has not been set or is not valid.
type sshDefaultDuration struct {
	*Claimer
}

func (m *sshDefaultDuration) Option(o SSHOptions) SSHCertModifier {
	return sshModifierFunc(func(cert *ssh.Certificate) error {
		d, err := m.DefaultSSHCertDuration(cert.CertType)
		if err != nil {
			return err
		}

		var backdate uint64
		if cert.ValidAfter == 0 {
			backdate = uint64(o.Backdate / time.Second)
			cert.ValidAfter = uint64(now().Truncate(time.Second).Unix())
		}
		if cert.ValidBefore == 0 {
			cert.ValidBefore = cert.ValidAfter + uint64(d/time.Second)
		}
		// Apply backdate safely
		if cert.ValidAfter > backdate {
			cert.ValidAfter -= backdate
		}
		return nil
	})
}

// sshLimitDuration adjusts the duration to min(default, remaining provisioning
// credential duration). E.g. if the default is 12hrs but the remaining validity
// of the provisioning credential is only 4hrs, this option will set the value
// to 4hrs (the min of the two values). It will fail if a CertType has not been
// set or is not valid.
type sshLimitDuration struct {
	*Claimer
	NotAfter time.Time
}

func (m *sshLimitDuration) Option(o SSHOptions) SSHCertModifier {
	if m.NotAfter.IsZero() {
		defaultDuration := &sshDefaultDuration{m.Claimer}
		return defaultDuration.Option(o)
	}

	return sshModifierFunc(func(cert *ssh.Certificate) error {
		d, err := m.DefaultSSHCertDuration(cert.CertType)
		if err != nil {
			return err
		}

		var backdate uint64
		if cert.ValidAfter == 0 {
			backdate = uint64(o.Backdate / time.Second)
			cert.ValidAfter = uint64(now().Truncate(time.Second).Unix())
		}

		certValidAfter := time.Unix(int64(cert.ValidAfter), 0)
		if certValidAfter.After(m.NotAfter) {
			return errors.Errorf("provisioning credential expiration (%s) is before requested certificate validAfter (%s)",
				m.NotAfter, certValidAfter)
		}

		if cert.ValidBefore == 0 {
			certValidBefore := certValidAfter.Add(d)
			if m.NotAfter.Before(certValidBefore) {
				certValidBefore = m.NotAfter
			}
			cert.ValidBefore = uint64(certValidBefore.Unix())
		} else {
			certValidBefore := time.Unix(int64(cert.ValidBefore), 0)
			if m.NotAfter.Before(certValidBefore) {
				return errors.Errorf("provisioning credential expiration (%s) is before requested certificate validBefore (%s)",
					m.NotAfter, certValidBefore)
			}
		}

		// Apply backdate safely
		if cert.ValidAfter > backdate {
			cert.ValidAfter -= backdate
		}

		return nil
	})
}

// sshCertOptionsValidator validates the user SSHOptions with the ones
// usually present in the token.
type sshCertOptionsValidator SSHOptions

// Valid implements SSHCertOptionsValidator and returns nil if both
// SSHOptions match.
func (v sshCertOptionsValidator) Valid(got SSHOptions) error {
	want := SSHOptions(v)
	return want.match(got)
}

type sshCertValidityValidator struct {
	*Claimer
}

func (v *sshCertValidityValidator) Valid(cert *ssh.Certificate, opts SSHOptions) error {
	switch {
	case cert.ValidAfter == 0:
		return errors.New("ssh certificate validAfter cannot be 0")
	case cert.ValidBefore < uint64(now().Unix()):
		return errors.New("ssh certificate validBefore cannot be in the past")
	case cert.ValidBefore < cert.ValidAfter:
		return errors.New("ssh certificate validBefore cannot be before validAfter")
	}

	var min, max time.Duration
	switch cert.CertType {
	case ssh.UserCert:
		min = v.MinUserSSHCertDuration()
		max = v.MaxUserSSHCertDuration()
	case ssh.HostCert:
		min = v.MinHostSSHCertDuration()
		max = v.MaxHostSSHCertDuration()
	case 0:
		return errors.New("ssh certificate type has not been set")
	default:
		return errors.Errorf("unknown ssh certificate type %d", cert.CertType)
	}

	// To not take into account the backdate, time.Now() will be used to
	// calculate the duration if ValidAfter is in the past.
	dur := time.Duration(cert.ValidBefore-cert.ValidAfter) * time.Second

	switch {
	case dur < min:
		return errors.Errorf("requested duration of %s is less than minimum "+
			"accepted duration for selected provisioner of %s", dur, min)
	case dur > max+opts.Backdate:
		return errors.Errorf("requested duration of %s is greater than maximum "+
			"accepted duration for selected provisioner of %s", dur, max+opts.Backdate)
	default:
		return nil
	}
}

// sshCertDefaultValidator implements a simple validator for all the
// fields in the SSH certificate.
type sshCertDefaultValidator struct{}

// Valid returns an error if the given certificate does not contain the necessary fields.
func (v *sshCertDefaultValidator) Valid(cert *ssh.Certificate, o SSHOptions) error {
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
func (v sshDefaultPublicKeyValidator) Valid(cert *ssh.Certificate, o SSHOptions) error {
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

// sshCertKeyIDValidator implements a validator for the KeyId attribute.
type sshCertKeyIDValidator string

// Valid returns an error if the given certificate does not contain the necessary fields.
func (v sshCertKeyIDValidator) Valid(cert *ssh.Certificate, o SSHOptions) error {
	if string(v) != cert.KeyId {
		return errors.Errorf("invalid ssh certificate KeyId; want %s, but got %s", string(v), cert.KeyId)
	}
	return nil
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
