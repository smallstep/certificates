package provisioner

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"time"

	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/x509util"

	"github.com/smallstep/certificates/authority/policy"
	"github.com/smallstep/certificates/errs"
)

// DefaultCertValidity is the default validity for a certificate if none is specified.
const DefaultCertValidity = 24 * time.Hour

// SignOptions contains the options that can be passed to the Sign method. Backdate
// is automatically filled and can only be configured in the CA.
type SignOptions struct {
	NotAfter     TimeDuration    `json:"notAfter"`
	NotBefore    TimeDuration    `json:"notBefore"`
	TemplateData json.RawMessage `json:"templateData"`
	Backdate     time.Duration   `json:"-"`
}

// SignOption is the interface used to collect all extra options used in the
// Sign method.
type SignOption interface{}

// CertificateValidator is an interface used to validate a given X.509 certificate.
type CertificateValidator interface {
	Valid(cert *x509.Certificate, opts SignOptions) error
}

// CertificateRequestValidator is an interface used to validate a given X.509 certificate request.
type CertificateRequestValidator interface {
	Valid(cr *x509.CertificateRequest) error
}

// CertificateModifier is an interface used to modify a given X.509 certificate.
// Types implementing this interface will be validated with a
// CertificateValidator.
type CertificateModifier interface {
	Modify(cert *x509.Certificate, opts SignOptions) error
}

// CertificateEnforcer is an interface used to modify a given X.509 certificate.
// Types implemented this interface will NOT be validated with a
// CertificateValidator.
type CertificateEnforcer interface {
	Enforce(cert *x509.Certificate) error
}

// CertificateModifierFunc allows to create simple certificate modifiers just
// with a function.
type CertificateModifierFunc func(cert *x509.Certificate, opts SignOptions) error

// Modify implements CertificateModifier and just calls the defined function.
func (fn CertificateModifierFunc) Modify(cert *x509.Certificate, opts SignOptions) error {
	return fn(cert, opts)
}

// CertificateEnforcerFunc allows to create simple certificate enforcer just
// with a function.
type CertificateEnforcerFunc func(cert *x509.Certificate) error

// Enforce implements CertificateEnforcer and just calls the defined function.
func (fn CertificateEnforcerFunc) Enforce(cert *x509.Certificate) error {
	return fn(cert)
}

// AttestationData is a SignOption used to pass attestation information to the
// sign methods.
type AttestationData struct {
	PermanentIdentifier string
}

// defaultPublicKeyValidator validates the public key of a certificate request.
type defaultPublicKeyValidator struct{}

// Valid checks that certificate request common name matches the one configured.
func (v defaultPublicKeyValidator) Valid(req *x509.CertificateRequest) error {
	switch k := req.PublicKey.(type) {
	case *rsa.PublicKey:
		if k.Size() < keyutil.MinRSAKeyBytes {
			return errs.Forbidden("certificate request RSA key must be at least %d bits (%d bytes)",
				8*keyutil.MinRSAKeyBytes, keyutil.MinRSAKeyBytes)
		}
	case *ecdsa.PublicKey, ed25519.PublicKey:
	default:
		return errs.BadRequest("certificate request key of type '%T' is not supported", k)
	}
	return nil
}

// publicKeyMinimumLengthValidator validates the length (in bits) of the public key
// of a certificate request is at least a certain length
type publicKeyMinimumLengthValidator struct {
	length int
}

// newPublicKeyMinimumLengthValidator creates a new publicKeyMinimumLengthValidator
// with the given length as its minimum value
// TODO: change the defaultPublicKeyValidator to have a configurable length instead?
func newPublicKeyMinimumLengthValidator(length int) publicKeyMinimumLengthValidator {
	return publicKeyMinimumLengthValidator{
		length: length,
	}
}

// Valid checks that certificate request common name matches the one configured.
func (v publicKeyMinimumLengthValidator) Valid(req *x509.CertificateRequest) error {
	switch k := req.PublicKey.(type) {
	case *rsa.PublicKey:
		minimumLengthInBytes := v.length / 8
		if k.Size() < minimumLengthInBytes {
			return errs.Forbidden("certificate request RSA key must be at least %d bits (%d bytes)",
				v.length, minimumLengthInBytes)
		}
	case *ecdsa.PublicKey, ed25519.PublicKey:
	default:
		return errs.BadRequest("certificate request key of type '%T' is not supported", k)
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
		return errs.Forbidden("certificate request does not contain the valid common name - got %s, want %s", req.Subject.CommonName, v)
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
	return errs.Forbidden("certificate request does not contain the valid common name - got %s, want %s", req.Subject.CommonName, v)
}

// dnsNamesValidator validates the DNS names SAN of a certificate request.
type dnsNamesValidator []string

// Valid checks that certificate request DNS Names match those configured in
// the bootstrap (token) flow.
func (v dnsNamesValidator) Valid(req *x509.CertificateRequest) error {
	if len(req.DNSNames) == 0 {
		return nil
	}
	want := make(map[string]bool)
	for _, s := range v {
		want[s] = true
	}
	got := make(map[string]bool)
	for _, s := range req.DNSNames {
		got[s] = true
	}
	if !reflect.DeepEqual(want, got) {
		return errs.Forbidden("certificate request does not contain the valid DNS names - got %v, want %v", req.DNSNames, v)
	}
	return nil
}

// ipAddressesValidator validates the IP addresses SAN of a certificate request.
type ipAddressesValidator []net.IP

// Valid checks that certificate request IP Addresses match those configured in
// the bootstrap (token) flow.
func (v ipAddressesValidator) Valid(req *x509.CertificateRequest) error {
	if len(req.IPAddresses) == 0 {
		return nil
	}
	want := make(map[string]bool)
	for _, ip := range v {
		want[ip.String()] = true
	}
	got := make(map[string]bool)
	for _, ip := range req.IPAddresses {
		got[ip.String()] = true
	}
	if !reflect.DeepEqual(want, got) {
		return errs.Forbidden("certificate request does not contain the valid IP addresses - got %v, want %v", req.IPAddresses, v)
	}
	return nil
}

// emailAddressesValidator validates the email address SANs of a certificate request.
type emailAddressesValidator []string

// Valid checks that certificate request IP Addresses match those configured in
// the bootstrap (token) flow.
func (v emailAddressesValidator) Valid(req *x509.CertificateRequest) error {
	if len(req.EmailAddresses) == 0 {
		return nil
	}
	want := make(map[string]bool)
	for _, s := range v {
		want[s] = true
	}
	got := make(map[string]bool)
	for _, s := range req.EmailAddresses {
		got[s] = true
	}
	if !reflect.DeepEqual(want, got) {
		return errs.Forbidden("certificate request does not contain the valid email addresses - got %v, want %v", req.EmailAddresses, v)
	}
	return nil
}

// urisValidator validates the URI SANs of a certificate request.
type urisValidator []*url.URL

// Valid checks that certificate request IP Addresses match those configured in
// the bootstrap (token) flow.
func (v urisValidator) Valid(req *x509.CertificateRequest) error {
	if len(req.URIs) == 0 {
		return nil
	}
	want := make(map[string]bool)
	for _, u := range v {
		want[u.String()] = true
	}
	got := make(map[string]bool)
	for _, u := range req.URIs {
		got[u.String()] = true
	}
	if !reflect.DeepEqual(want, got) {
		return errs.Forbidden("certificate request does not contain the valid URIs - got %v, want %v", req.URIs, v)
	}
	return nil
}

// defaultsSANsValidator stores a set of SANs to eventually validate 1:1 against
// the SANs in an x509 certificate request.
type defaultSANsValidator []string

// Valid verifies that the SANs stored in the validator match 1:1 with those
// requested in the x509 certificate request.
func (v defaultSANsValidator) Valid(req *x509.CertificateRequest) (err error) {
	dnsNames, ips, emails, uris := x509util.SplitSANs(v)
	if err = dnsNamesValidator(dnsNames).Valid(req); err != nil {
		return
	} else if err = emailAddressesValidator(emails).Valid(req); err != nil {
		return
	} else if err = ipAddressesValidator(ips).Valid(req); err != nil {
		return
	} else if err = urisValidator(uris).Valid(req); err != nil {
		return
	}
	return
}

// profileDefaultDuration is a modifier that sets the certificate
// duration.
type profileDefaultDuration time.Duration

func (v profileDefaultDuration) Modify(cert *x509.Certificate, so SignOptions) error {
	var backdate time.Duration
	notBefore := so.NotBefore.Time()
	if notBefore.IsZero() {
		notBefore = now()
		backdate = -1 * so.Backdate
	}
	notAfter := so.NotAfter.RelativeTime(notBefore)
	if notAfter.IsZero() {
		if v != 0 {
			notAfter = notBefore.Add(time.Duration(v))
		} else {
			notAfter = notBefore.Add(DefaultCertValidity)
		}
	}

	cert.NotBefore = notBefore.Add(backdate)
	cert.NotAfter = notAfter
	return nil
}

// profileLimitDuration is an x509 profile option that modifies an x509 validity
// period according to an imposed expiration time.
type profileLimitDuration struct {
	def                 time.Duration
	notBefore, notAfter time.Time
}

// Option returns an x509util option that limits the validity period of a
// certificate to one that is superficially imposed.
func (v profileLimitDuration) Modify(cert *x509.Certificate, so SignOptions) error {
	var backdate time.Duration
	notBefore := so.NotBefore.Time()
	if notBefore.IsZero() {
		notBefore = now()
		backdate = -1 * so.Backdate
	}
	if notBefore.Before(v.notBefore) {
		return errs.Forbidden(
			"requested certificate notBefore (%s) is before the active validity window of the provisioning credential (%s)",
			notBefore, v.notBefore)
	}

	notAfter := so.NotAfter.RelativeTime(notBefore)
	if notAfter.After(v.notAfter) {
		return errs.Forbidden(
			"requested certificate notAfter (%s) is after the expiration of the provisioning credential (%s)",
			notAfter, v.notAfter)
	}
	if notAfter.IsZero() {
		t := notBefore.Add(v.def)
		if t.After(v.notAfter) {
			notAfter = v.notAfter
		} else {
			notAfter = t
		}
	}

	cert.NotBefore = notBefore.Add(backdate)
	cert.NotAfter = notAfter
	return nil
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
// total duration.
func (v *validityValidator) Valid(cert *x509.Certificate, o SignOptions) error {
	var (
		na  = cert.NotAfter.Truncate(time.Second)
		nb  = cert.NotBefore.Truncate(time.Second)
		now = time.Now().Truncate(time.Second)
	)

	d := na.Sub(nb)

	if na.Before(now) {
		return errs.BadRequest("notAfter cannot be in the past; na=%v", na)
	}
	if na.Before(nb) {
		return errs.BadRequest("notAfter cannot be before notBefore; na=%v, nb=%v", na, nb)
	}
	if d < v.min {
		return errs.Forbidden("requested duration of %v is less than the authorized minimum certificate duration of %v", d, v.min)
	}
	// NOTE: this check is not "technically correct". We're allowing the max
	// duration of a cert to be "max + backdate" and not all certificates will
	// be backdated (e.g. if a user passes the NotBefore value then we do not
	// apply a backdate). This is good enough.
	if d > v.max+o.Backdate {
		return errs.Forbidden("requested duration of %v is more than the authorized maximum certificate duration of %v", d, v.max+o.Backdate)
	}
	return nil
}

// x509NamePolicyValidator validates that the certificate (to be signed)
// contains only allowed SANs.
type x509NamePolicyValidator struct {
	policyEngine policy.X509Policy
}

// newX509NamePolicyValidator return a new SANs allow/deny validator.
func newX509NamePolicyValidator(engine policy.X509Policy) *x509NamePolicyValidator {
	return &x509NamePolicyValidator{
		policyEngine: engine,
	}
}

// Valid validates that the certificate (to be signed) contains only allowed SANs.
func (v *x509NamePolicyValidator) Valid(cert *x509.Certificate, _ SignOptions) error {
	if v.policyEngine == nil {
		return nil
	}
	return v.policyEngine.IsX509CertificateAllowed(cert)
}

type forceCNOption struct {
	ForceCN bool
}

func newForceCNOption(forceCN bool) *forceCNOption {
	return &forceCNOption{forceCN}
}

func (o *forceCNOption) Modify(cert *x509.Certificate, _ SignOptions) error {
	if !o.ForceCN {
		return nil
	}

	// Force the common name to be the first DNS if not provided.
	if cert.Subject.CommonName == "" {
		if len(cert.DNSNames) == 0 {
			return errs.BadRequest("cannot force common name, DNS names is empty")
		}
		cert.Subject.CommonName = cert.DNSNames[0]
	}

	return nil
}

type provisionerExtensionOption struct {
	Extension
	Disabled bool
}

func newProvisionerExtensionOption(typ Type, name, credentialID string, keyValuePairs ...string) *provisionerExtensionOption {
	return &provisionerExtensionOption{
		Extension: Extension{
			Type:          typ,
			Name:          name,
			CredentialID:  credentialID,
			KeyValuePairs: keyValuePairs,
		},
	}
}

// WithControllerOptions updates the provisionerExtensionOption with options
// from the controller. Currently only the DisableSmallstepExtensions
// provisioner claim is used.
func (o *provisionerExtensionOption) WithControllerOptions(c *Controller) *provisionerExtensionOption {
	o.Disabled = c.Claimer.IsDisableSmallstepExtensions()
	return o
}

func (o *provisionerExtensionOption) Modify(cert *x509.Certificate, _ SignOptions) error {
	if o.Disabled {
		return nil
	}

	ext, err := o.ToExtension()
	if err != nil {
		return errs.NewError(http.StatusInternalServerError, err, "error creating certificate")
	}
	// Replace or append the provisioner extension to avoid the inclusions of
	// malicious stepOIDProvisioner using templates.
	for i, e := range cert.ExtraExtensions {
		if e.Id.Equal(StepOIDProvisioner) {
			cert.ExtraExtensions[i] = ext
			return nil
		}
	}
	cert.ExtraExtensions = append(cert.ExtraExtensions, ext)
	return nil
}
