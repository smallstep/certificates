package provisioner

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net"
	"reflect"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/x509util"
	"golang.org/x/crypto/ed25519"
)

// Options contains the options that can be passed to the Sign method. Backdate
// is automatically filled and can only be configured in the CA.
type Options struct {
	NotAfter  TimeDuration  `json:"notAfter"`
	NotBefore TimeDuration  `json:"notBefore"`
	Backdate  time.Duration `json:"-"`
}

// SignOption is the interface used to collect all extra options used in the
// Sign method.
type SignOption interface{}

// CertificateValidator is the interface used to validate a X.509 certificate.
type CertificateValidator interface {
	SignOption
	Valid(cert *x509.Certificate, o Options) error
}

// CertificateRequestValidator is the interface used to validate a X.509
// certificate request.
type CertificateRequestValidator interface {
	SignOption
	Valid(req *x509.CertificateRequest) error
}

// ProfileModifier is the interface used to add custom options to the profile
// constructor. The options are used to modify the final certificate.
type ProfileModifier interface {
	SignOption
	Option(o Options) x509util.WithOption
}

// CertificateEnforcer is the interface used to modify a certificate after
// validation.
type CertificateEnforcer interface {
	SignOption
	Enforce(cert *x509.Certificate) error
}

// profileWithOption is a wrapper against x509util.WithOption to conform the
// interface.
type profileWithOption x509util.WithOption

func (v profileWithOption) Option(Options) x509util.WithOption {
	return x509util.WithOption(v)
}

// emailOnlyIdentity is a CertificateRequestValidator that checks that the only
// SAN provided is the given email address.
type emailOnlyIdentity string

func (e emailOnlyIdentity) Valid(req *x509.CertificateRequest) error {
	switch {
	case len(req.DNSNames) > 0:
		return errors.New("certificate request cannot contain DNS names")
	case len(req.IPAddresses) > 0:
		return errors.New("certificate request cannot contain IP addresses")
	case len(req.URIs) > 0:
		return errors.New("certificate request cannot contain URIs")
	case len(req.EmailAddresses) == 0:
		return errors.New("certificate request does not contain any email address")
	case len(req.EmailAddresses) > 1:
		return errors.New("certificate request contains too many email addresses")
	case req.EmailAddresses[0] == "":
		return errors.New("certificate request cannot contain an empty email address")
	case req.EmailAddresses[0] != string(e):
		return errors.Errorf("certificate request does not contain the valid email address, got %s, want %s", req.EmailAddresses[0], e)
	default:
		return nil
	}
}

// defaultPublicKeyValidator validates the public key of a certificate request.
type defaultPublicKeyValidator struct{}

// Valid checks that certificate request common name matches the one configured.
func (v defaultPublicKeyValidator) Valid(req *x509.CertificateRequest) error {
	switch k := req.PublicKey.(type) {
	case *rsa.PublicKey:
		if k.Size() < 256 {
			return errors.New("rsa key in CSR must be at least 2048 bits (256 bytes)")
		}
	case *ecdsa.PublicKey, ed25519.PublicKey:
	default:
		return errors.Errorf("unrecognized public key of type '%T' in CSR", k)
	}
	return nil
}

// commonNameValidator validates the common name of a certificate request.
type commonNameValidator string

// Valid checks that certificate request common name matches the one configured.
// An empty common name is considered valid.
func (v commonNameValidator) Valid(req *x509.CertificateRequest) error {
	if req.Subject.CommonName == "" {
		return nil
	}
	if req.Subject.CommonName != string(v) {
		return errors.Errorf("certificate request does not contain the valid common name; requested common name = %s, token subject = %s", req.Subject.CommonName, v)
	}
	return nil
}

// commonNameSliceValidator validates thats the common name of a certificate
// request is present in the slice. An empty common name is considered valid.
type commonNameSliceValidator []string

func (v commonNameSliceValidator) Valid(req *x509.CertificateRequest) error {
	if req.Subject.CommonName == "" {
		return nil
	}
	for _, cn := range v {
		if req.Subject.CommonName == cn {
			return nil
		}
	}
	return errors.Errorf("certificate request does not contain the valid common name, got %s, want %s", req.Subject.CommonName, v)
}

// dnsNamesValidator validates the DNS names SAN of a certificate request.
type dnsNamesValidator []string

// Valid checks that certificate request DNS Names match those configured in
// the bootstrap (token) flow.
func (v dnsNamesValidator) Valid(req *x509.CertificateRequest) error {
	want := make(map[string]bool)
	for _, s := range v {
		want[s] = true
	}
	got := make(map[string]bool)
	for _, s := range req.DNSNames {
		got[s] = true
	}
	if !reflect.DeepEqual(want, got) {
		return errors.Errorf("certificate request does not contain the valid DNS names - got %v, want %v", req.DNSNames, v)
	}
	return nil
}

// ipAddressesValidator validates the IP addresses SAN of a certificate request.
type ipAddressesValidator []net.IP

// Valid checks that certificate request IP Addresses match those configured in
// the bootstrap (token) flow.
func (v ipAddressesValidator) Valid(req *x509.CertificateRequest) error {
	want := make(map[string]bool)
	for _, ip := range v {
		want[ip.String()] = true
	}
	got := make(map[string]bool)
	for _, ip := range req.IPAddresses {
		got[ip.String()] = true
	}
	if !reflect.DeepEqual(want, got) {
		return errors.Errorf("IP Addresses claim failed - got %v, want %v", req.IPAddresses, v)
	}
	return nil
}

// emailAddressesValidator validates the email address SANs of a certificate request.
type emailAddressesValidator []string

// Valid checks that certificate request IP Addresses match those configured in
// the bootstrap (token) flow.
func (v emailAddressesValidator) Valid(req *x509.CertificateRequest) error {
	want := make(map[string]bool)
	for _, s := range v {
		want[s] = true
	}
	got := make(map[string]bool)
	for _, s := range req.EmailAddresses {
		got[s] = true
	}
	if !reflect.DeepEqual(want, got) {
		return errors.Errorf("certificate request does not contain the valid Email Addresses - got %v, want %v", req.EmailAddresses, v)
	}
	return nil
}

// profileDefaultDuration is a wrapper against x509util.WithOption to conform
// the SignOption interface.
type profileDefaultDuration time.Duration

func (v profileDefaultDuration) Option(so Options) x509util.WithOption {
	var backdate time.Duration
	notBefore := so.NotBefore.Time()
	if notBefore.IsZero() {
		notBefore = now()
		backdate = -1 * so.Backdate
	}
	notAfter := so.NotAfter.RelativeTime(notBefore)
	return func(p x509util.Profile) error {
		fn := x509util.WithNotBeforeAfterDuration(notBefore, notAfter, time.Duration(v))
		if err := fn(p); err != nil {
			return err
		}
		crt := p.Subject()
		crt.NotBefore = crt.NotBefore.Add(backdate)
		return nil
	}
}

// profileLimitDuration is an x509 profile option that modifies an x509 validity
// period according to an imposed expiration time.
type profileLimitDuration struct {
	def      time.Duration
	notAfter time.Time
}

// Option returns an x509util option that limits the validity period of a
// certificate to one that is superficially imposed.
func (v profileLimitDuration) Option(so Options) x509util.WithOption {
	return func(p x509util.Profile) error {
		var backdate time.Duration
		n := now()
		notBefore := so.NotBefore.Time()
		if notBefore.IsZero() {
			notBefore = n
			backdate = -1 * so.Backdate
		}
		if notBefore.After(v.notAfter) {
			return errors.Errorf("provisioning credential expiration (%s) is before "+
				"requested certificate notBefore (%s)", v.notAfter, notBefore)
		}

		notAfter := so.NotAfter.RelativeTime(notBefore)
		if notAfter.After(v.notAfter) {
			return errors.Errorf("provisioning credential expiration (%s) is before "+
				"requested certificate notAfter (%s)", v.notAfter, notBefore)
		}
		if notAfter.IsZero() {
			t := notBefore.Add(v.def)
			if t.After(v.notAfter) {
				notAfter = v.notAfter
			} else {
				notAfter = t
			}
		}
		crt := p.Subject()
		crt.NotBefore = notBefore.Add(backdate)
		crt.NotAfter = notAfter
		return nil
	}
}

// validityValidator validates the certificate validity settings.
type validityValidator struct {
	min time.Duration
	max time.Duration
}

// newValidityValidator return a new validity validator.
func newValidityValidator(min, max time.Duration) *validityValidator {
	return &validityValidator{min: min, max: max}
}

// Valid validates the certificate validity settings (notBefore/notAfter) and
// and total duration.
func (v *validityValidator) Valid(cert *x509.Certificate, o Options) error {
	var (
		na  = cert.NotAfter.Truncate(time.Second)
		nb  = cert.NotBefore.Truncate(time.Second)
		now = time.Now().Truncate(time.Second)
	)

	d := na.Sub(nb)

	if na.Before(now) {
		return errors.Errorf("notAfter cannot be in the past; na=%v", na)
	}
	if na.Before(nb) {
		return errors.Errorf("notAfter cannot be before notBefore; na=%v, nb=%v", na, nb)
	}
	if d < v.min {
		return errors.Errorf("requested duration of %v is less than the authorized minimum certificate duration of %v",
			d, v.min)
	}
	// NOTE: this check is not "technically correct". We're allowing the max
	// duration of a cert to be "max + backdate" and not all certificates will
	// be backdated (e.g. if a user passes the NotBefore value then we do not
	// apply a backdate). This is good enough.
	if d > v.max+o.Backdate {
		return errors.Errorf("requested duration of %v is more than the authorized maximum certificate duration of %v",
			d, v.max+o.Backdate)
	}
	return nil
}

var (
	stepOIDRoot        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64}
	stepOIDProvisioner = append(asn1.ObjectIdentifier(nil), append(stepOIDRoot, 1)...)
)

type stepProvisionerASN1 struct {
	Type          int
	Name          []byte
	CredentialID  []byte
	KeyValuePairs []string `asn1:"optional,omitempty"`
}

type provisionerExtensionOption struct {
	Type          int
	Name          string
	CredentialID  string
	KeyValuePairs []string
}

func newProvisionerExtensionOption(typ Type, name, credentialID string, keyValuePairs ...string) *provisionerExtensionOption {
	return &provisionerExtensionOption{
		Type:          int(typ),
		Name:          name,
		CredentialID:  credentialID,
		KeyValuePairs: keyValuePairs,
	}
}

func (o *provisionerExtensionOption) Option(Options) x509util.WithOption {
	return func(p x509util.Profile) error {
		crt := p.Subject()
		ext, err := createProvisionerExtension(o.Type, o.Name, o.CredentialID, o.KeyValuePairs...)
		if err != nil {
			return err
		}
		crt.ExtraExtensions = append(crt.ExtraExtensions, ext)
		return nil
	}
}

func createProvisionerExtension(typ int, name, credentialID string, keyValuePairs ...string) (pkix.Extension, error) {
	b, err := asn1.Marshal(stepProvisionerASN1{
		Type:          typ,
		Name:          []byte(name),
		CredentialID:  []byte(credentialID),
		KeyValuePairs: keyValuePairs,
	})
	if err != nil {
		return pkix.Extension{}, errors.Wrapf(err, "error marshaling provisioner extension")
	}
	return pkix.Extension{
		Id:       stepOIDProvisioner,
		Critical: false,
		Value:    b,
	}, nil
}

func init() {
	// Avoid dead-code warning in profileWithOption
	_ = profileWithOption(nil)
}
