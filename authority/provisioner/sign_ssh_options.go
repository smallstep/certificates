package provisioner

import (
	"crypto/rsa"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/policy"
	"github.com/smallstep/certificates/errs"
	"go.step.sm/crypto/keyutil"
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
	Modify(cert *ssh.Certificate, opts SignSSHOptions) error
}

// SSHCertValidator is the interface used to validate an SSH certificate.
type SSHCertValidator interface {
	SignOption
	Valid(cert *ssh.Certificate, opts SignSSHOptions) error
}

// SSHCertOptionsValidator is the interface used to validate the custom
// options used to modify the SSH certificate.
type SSHCertOptionsValidator interface {
	SignOption
	Valid(got SignSSHOptions) error
}

// SignSSHOptions contains the options that can be passed to the SignSSH method.
type SignSSHOptions struct {
	CertType     string          `json:"certType"`
	KeyID        string          `json:"keyID"`
	Principals   []string        `json:"principals"`
	ValidAfter   TimeDuration    `json:"validAfter,omitempty"`
	ValidBefore  TimeDuration    `json:"validBefore,omitempty"`
	TemplateData json.RawMessage `json:"templateData,omitempty"`
	Backdate     time.Duration   `json:"-"`
}

// Validate validates the given SignSSHOptions.
func (o SignSSHOptions) Validate() error {
	if o.CertType != "" && o.CertType != SSHUserCert && o.CertType != SSHHostCert {
		return errs.BadRequest("certType '%s' is not valid", o.CertType)
	}
	for _, p := range o.Principals {
		if p == "" {
			return errs.BadRequest("principals cannot contain empty values")
		}
	}
	return nil
}

// Type returns the uint32 representation of the CertType.
func (o SignSSHOptions) Type() uint32 {
	return sshCertTypeUInt32(o.CertType)
}

// Modify implements SSHCertModifier and sets the SSHOption in the ssh.Certificate.
func (o SignSSHOptions) Modify(cert *ssh.Certificate, _ SignSSHOptions) error {
	switch o.CertType {
	case "": // ignore
	case SSHUserCert:
		cert.CertType = ssh.UserCert
	case SSHHostCert:
		cert.CertType = ssh.HostCert
	default:
		return errs.BadRequest("ssh certificate has an unknown type '%s'", o.CertType)
	}

	cert.KeyId = o.KeyID
	cert.ValidPrincipals = o.Principals

	return o.ModifyValidity(cert)
}

// ModifyValidity modifies only the ValidAfter and ValidBefore on the given
// ssh.Certificate.
func (o SignSSHOptions) ModifyValidity(cert *ssh.Certificate) error {
	t := now()
	if !o.ValidAfter.IsZero() {
		cert.ValidAfter = uint64(o.ValidAfter.RelativeTime(t).Unix())
	}
	if !o.ValidBefore.IsZero() {
		cert.ValidBefore = uint64(o.ValidBefore.RelativeTime(t).Unix())
	}
	if cert.ValidAfter > 0 && cert.ValidBefore > 0 && cert.ValidAfter > cert.ValidBefore {
		return errs.BadRequest("ssh certificate validAfter cannot be greater than validBefore")
	}
	return nil
}

// match compares two SSHOptions and return an error if they don't match. It
// ignores zero values.
func (o SignSSHOptions) match(got SignSSHOptions) error {
	if o.CertType != "" && got.CertType != "" && o.CertType != got.CertType {
		return errs.Forbidden("ssh certificate type does not match - got %v, want %v", got.CertType, o.CertType)
	}
	if len(o.Principals) > 0 && len(got.Principals) > 0 && !containsAllMembers(o.Principals, got.Principals) {
		return errs.Forbidden("ssh certificate principals does not match - got %v, want %v", got.Principals, o.Principals)
	}
	if !o.ValidAfter.IsZero() && !got.ValidAfter.IsZero() && !o.ValidAfter.Equal(&got.ValidAfter) {
		return errs.Forbidden("ssh certificate validAfter does not match - got %v, want %v", got.ValidAfter, o.ValidAfter)
	}
	if !o.ValidBefore.IsZero() && !got.ValidBefore.IsZero() && !o.ValidBefore.Equal(&got.ValidBefore) {
		return errs.Forbidden("ssh certificate validBefore does not match - got %v, want %v", got.ValidBefore, o.ValidBefore)
	}
	return nil
}

// sshCertValidAfterModifier is an SSHCertModifier that sets the
// ValidAfter in the SSH certificate.
type sshCertValidAfterModifier uint64

func (m sshCertValidAfterModifier) Modify(cert *ssh.Certificate, _ SignSSHOptions) error {
	cert.ValidAfter = uint64(m)
	return nil
}

// sshCertValidBeforeModifier is an SSHCertModifier that sets the
// ValidBefore in the SSH certificate.
type sshCertValidBeforeModifier uint64

func (m sshCertValidBeforeModifier) Modify(cert *ssh.Certificate, _ SignSSHOptions) error {
	cert.ValidBefore = uint64(m)
	return nil
}

// sshDefaultDuration is an SSHCertModifier that sets the certificate
// ValidAfter and ValidBefore if they have not been set. It will fail if a
// CertType has not been set or is not valid.
type sshDefaultDuration struct {
	*Claimer
}

// Modify implements SSHCertModifier and sets the validity if it has not been
// set, but it always applies the backdate.
func (m *sshDefaultDuration) Modify(cert *ssh.Certificate, o SignSSHOptions) error {
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

// Modify implements SSHCertModifier and modifies the validity of the
// certificate to expire before the configured limit.
func (m *sshLimitDuration) Modify(cert *ssh.Certificate, o SignSSHOptions) error {
	if m.NotAfter.IsZero() {
		defaultDuration := &sshDefaultDuration{m.Claimer}
		return defaultDuration.Modify(cert, o)
	}

	// Make sure the duration is within the limits.
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
		return errs.Forbidden("provisioning credential expiration (%s) is before requested certificate validAfter (%s)",
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
			return errs.Forbidden("provisioning credential expiration (%s) is before requested certificate validBefore (%s)",
				m.NotAfter, certValidBefore)
		}
	}

	// Apply backdate safely
	if cert.ValidAfter > backdate {
		cert.ValidAfter -= backdate
	}

	return nil
}

// sshCertOptionsValidator validates the user SSHOptions with the ones
// usually present in the token.
type sshCertOptionsValidator SignSSHOptions

// Valid implements SSHCertOptionsValidator and returns nil if both
// SSHOptions match.
func (v sshCertOptionsValidator) Valid(got SignSSHOptions) error {
	want := SignSSHOptions(v)
	return want.match(got)
}

// sshCertOptionsRequireValidator defines which elements in the SignSSHOptions are required.
type sshCertOptionsRequireValidator struct {
	CertType   bool
	KeyID      bool
	Principals bool
}

func (v *sshCertOptionsRequireValidator) Valid(got SignSSHOptions) error {
	switch {
	case v.CertType && got.CertType == "":
		return errs.BadRequest("ssh certificate certType cannot be empty")
	case v.KeyID && got.KeyID == "":
		return errs.BadRequest("ssh certificate keyID cannot be empty")
	case v.Principals && len(got.Principals) == 0:
		return errs.BadRequest("ssh certificate principals cannot be empty")
	default:
		return nil
	}
}

type sshCertValidityValidator struct {
	*Claimer
}

func (v *sshCertValidityValidator) Valid(cert *ssh.Certificate, opts SignSSHOptions) error {
	switch {
	case cert.ValidAfter == 0:
		return errs.BadRequest("ssh certificate validAfter cannot be 0")
	case cert.ValidBefore < uint64(now().Unix()):
		return errs.BadRequest("ssh certificate validBefore cannot be in the past")
	case cert.ValidBefore < cert.ValidAfter:
		return errs.BadRequest("ssh certificate validBefore cannot be before validAfter")
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
		return errs.BadRequest("ssh certificate type has not been set")
	default:
		return errs.BadRequest("ssh certificate has an unknown type '%d'", cert.CertType)
	}

	// To not take into account the backdate, time.Now() will be used to
	// calculate the duration if ValidAfter is in the past.
	dur := time.Duration(cert.ValidBefore-cert.ValidAfter) * time.Second

	switch {
	case dur < min:
		return errs.Forbidden("requested duration of %s is less than minimum accepted duration for selected provisioner of %s", dur, min)
	case dur > max+opts.Backdate:
		return errs.Forbidden("requested duration of %s is greater than maximum accepted duration for selected provisioner of %s", dur, max+opts.Backdate)
	default:
		return nil
	}
}

// sshCertDefaultValidator implements a simple validator for all the
// fields in the SSH certificate.
type sshCertDefaultValidator struct{}

// Valid returns an error if the given certificate does not contain the
// necessary fields. We skip ValidPrincipals and Extensions as with custom
// templates you can set them empty.
func (v *sshCertDefaultValidator) Valid(cert *ssh.Certificate, _ SignSSHOptions) error {
	switch {
	case len(cert.Nonce) == 0:
		return errs.Forbidden("ssh certificate nonce cannot be empty")
	case cert.Key == nil:
		return errs.Forbidden("ssh certificate key cannot be nil")
	case cert.Serial == 0:
		return errs.Forbidden("ssh certificate serial cannot be 0")
	case cert.CertType != ssh.UserCert && cert.CertType != ssh.HostCert:
		return errs.Forbidden("ssh certificate has an unknown type '%d'", cert.CertType)
	case cert.KeyId == "":
		return errs.Forbidden("ssh certificate key id cannot be empty")
	case cert.ValidAfter == 0:
		return errs.Forbidden("ssh certificate validAfter cannot be 0")
	case cert.ValidBefore < uint64(now().Unix()):
		return errs.Forbidden("ssh certificate validBefore cannot be in the past")
	case cert.ValidBefore < cert.ValidAfter:
		return errs.Forbidden("ssh certificate validBefore cannot be before validAfter")
	case cert.SignatureKey == nil:
		return errs.Forbidden("ssh certificate signature key cannot be nil")
	case cert.Signature == nil:
		return errs.Forbidden("ssh certificate signature cannot be nil")
	default:
		return nil
	}
}

// sshDefaultPublicKeyValidator implements a validator for the certificate key.
type sshDefaultPublicKeyValidator struct{}

// Valid checks that certificate request common name matches the one configured.
//
// TODO: this is the only validator that checks the key type. We should execute
// this before the signing. We should add a new validations interface or extend
// SSHCertOptionsValidator with the key.
func (v sshDefaultPublicKeyValidator) Valid(cert *ssh.Certificate, _ SignSSHOptions) error {
	if cert.Key == nil {
		return errs.BadRequest("ssh certificate key cannot be nil")
	}
	switch cert.Key.Type() {
	case ssh.KeyAlgoRSA:
		_, in, ok := sshParseString(cert.Key.Marshal())
		if !ok {
			return errs.BadRequest("ssh certificate key is invalid")
		}
		key, err := sshParseRSAPublicKey(in)
		if err != nil {
			return errs.BadRequestErr(err, "error parsing public key")
		}
		if key.Size() < keyutil.MinRSAKeyBytes {
			return errs.Forbidden("ssh certificate key must be at least %d bits (%d bytes)",
				8*keyutil.MinRSAKeyBytes, keyutil.MinRSAKeyBytes)
		}
		return nil
	case ssh.KeyAlgoDSA:
		return errs.BadRequest("ssh certificate key algorithm (DSA) is not supported")
	default:
		return nil
	}
}

// sshNamePolicyValidator validates that the certificate (to be signed)
// contains only allowed principals.
type sshNamePolicyValidator struct {
	hostPolicyEngine policy.HostPolicy
	userPolicyEngine policy.UserPolicy
}

// newSSHNamePolicyValidator return a new SSH allow/deny validator.
func newSSHNamePolicyValidator(host policy.HostPolicy, user policy.UserPolicy) *sshNamePolicyValidator {
	return &sshNamePolicyValidator{
		hostPolicyEngine: host,
		userPolicyEngine: user,
	}
}

// Valid validates that the certificate (to be signed) contains only allowed principals.
func (v *sshNamePolicyValidator) Valid(cert *ssh.Certificate, _ SignSSHOptions) error {
	if v.hostPolicyEngine == nil && v.userPolicyEngine == nil {
		// no policy configured at all; allow anything
		return nil
	}

	// Check the policy type to execute based on type of the certificate.
	// We don't allow user certs if only a host policy engine is configured and
	// the same for host certs: if only a user policy engine is configured, host
	// certs are denied. When both policy engines are configured, the type of
	// cert determines which policy engine is used.
	switch cert.CertType {
	case ssh.HostCert:
		// when no host policy engine is configured, but a user policy engine is
		// configured, the host certificate is denied.
		if v.hostPolicyEngine == nil && v.userPolicyEngine != nil {
			return errors.New("SSH host certificate not authorized")
		}
		return v.hostPolicyEngine.IsSSHCertificateAllowed(cert)
	case ssh.UserCert:
		// when no user policy engine is configured, but a host policy engine is
		// configured, the user certificate is denied.
		if v.userPolicyEngine == nil && v.hostPolicyEngine != nil {
			return errors.New("SSH user certificate not authorized")
		}
		return v.userPolicyEngine.IsSSHCertificateAllowed(cert)
	default:
		return fmt.Errorf("unexpected SSH certificate type %d", cert.CertType) // satisfy return; shouldn't happen
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
		visit[strings.ToLower(group[i])] = struct{}{}
	}
	for i := 0; i < lsg; i++ {
		if _, ok := visit[strings.ToLower(subgroup[i])]; !ok {
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
