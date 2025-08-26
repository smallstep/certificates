package provisioner

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/acme/wire"
	"github.com/smallstep/linkedca"
)

// ACMEChallenge represents the supported acme challenges.
type ACMEChallenge string

//nolint:staticcheck,revive // better names
const (
	// HTTP_01 is the http-01 ACME challenge.
	HTTP_01 ACMEChallenge = "http-01"
	// DNS_01 is the dns-01 ACME challenge.
	DNS_01 ACMEChallenge = "dns-01"
	// TLS_ALPN_01 is the tls-alpn-01 ACME challenge.
	TLS_ALPN_01 ACMEChallenge = "tls-alpn-01"
	// DEVICE_ATTEST_01 is the device-attest-01 ACME challenge.
	DEVICE_ATTEST_01 ACMEChallenge = "device-attest-01"
	// WIREOIDC_01 is the Wire OIDC challenge.
	WIREOIDC_01 ACMEChallenge = "wire-oidc-01"
	// WIREDPOP_01 is the Wire DPoP challenge.
	WIREDPOP_01 ACMEChallenge = "wire-dpop-01"
)

// String returns a normalized version of the challenge.
func (c ACMEChallenge) String() string {
	return strings.ToLower(string(c))
}

// Validate returns an error if the acme challenge is not a valid one.
func (c ACMEChallenge) Validate() error {
	switch ACMEChallenge(c.String()) {
	case HTTP_01, DNS_01, TLS_ALPN_01, DEVICE_ATTEST_01, WIREOIDC_01, WIREDPOP_01:
		return nil
	default:
		return fmt.Errorf("acme challenge %q is not supported", c)
	}
}

// ACMEAttestationFormat represents the format used on a device-attest-01
// challenge.
type ACMEAttestationFormat string

const (
	// APPLE is the format used to enable device-attest-01 on Apple devices.
	ANDROID ACMEAttestationFormat = "android-key"

	// APPLE is the format used to enable device-attest-01 on Apple devices.
	APPLE ACMEAttestationFormat = "apple"

	// STEP is the format used to enable device-attest-01 on devices that
	// provide attestation certificates like the PIV interface on YubiKeys.
	//
	// TODO(mariano): should we rename this to something else.
	STEP ACMEAttestationFormat = "step"

	// TPM is the format used to enable device-attest-01 with TPMs.
	TPM ACMEAttestationFormat = "tpm"
)

// String returns a normalized version of the attestation format.
func (f ACMEAttestationFormat) String() string {
	return strings.ToLower(string(f))
}

// Validate returns an error if the attestation format is not a valid one.
func (f ACMEAttestationFormat) Validate() error {
	switch ACMEAttestationFormat(f.String()) {
	case APPLE, STEP, TPM, ANDROID:
		return nil
	default:
		return fmt.Errorf("acme attestation format %q is not supported", f)
	}
}

// ACME is the acme provisioner type, an entity that can authorize the ACME
// provisioning flow.
type ACME struct {
	*base
	ID      string `json:"-"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	ForceCN bool   `json:"forceCN,omitempty"`
	// TermsOfService contains a URL pointing to the ACME server's
	// terms of service. Defaults to empty.
	TermsOfService string `json:"termsOfService,omitempty"`
	// Website contains an URL pointing to more information about
	// the ACME server. Defaults to empty.
	Website string `json:"website,omitempty"`
	// CaaIdentities is an array of hostnames that the ACME server
	// identifies itself with. These hostnames can be used by ACME
	// clients to determine the correct issuer domain name to use
	// when configuring CAA records. Defaults to empty array.
	CaaIdentities []string `json:"caaIdentities,omitempty"`
	// RequireEAB makes the provisioner require ACME EAB to be provided
	// by clients when creating a new Account. If set to true, the provided
	// EAB will be verified. If set to false and an EAB is provided, it is
	// not verified. Defaults to false.
	RequireEAB bool `json:"requireEAB,omitempty"`
	// Challenges contains the enabled challenges for this provisioner. If this
	// value is not set the default http-01, dns-01 and tls-alpn-01 challenges
	// will be enabled, device-attest-01, wire-oidc-01 and wire-dpop-01 will be
	// disabled.
	Challenges []ACMEChallenge `json:"challenges,omitempty"`
	// AttestationFormats contains the enabled attestation formats for this
	// provisioner. If this value is not set the default apple, step and tpm
	// will be used.
	AttestationFormats []ACMEAttestationFormat `json:"attestationFormats,omitempty"`
	// AttestationRoots contains a bundle of root certificates in PEM format
	// that will be used to verify the attestation certificates. If provided,
	// this bundle will be used even for well-known CAs like Apple and Yubico.
	AttestationRoots    []byte   `json:"attestationRoots,omitempty"`
	Claims              *Claims  `json:"claims,omitempty"`
	Options             *Options `json:"options,omitempty"`
	RootCRLs            []string `json:"rootCRLs,omitempty"`
	androidCRLTimeout   time.Time
	attestationRootPool *x509.CertPool
	ctl                 *Controller
}

// GetID returns the provisioner unique identifier.
func (p ACME) GetID() string {
	if p.ID != "" {
		return p.ID
	}
	return p.GetIDForToken()
}

// GetIDForToken returns an identifier that will be used to load the provisioner
// from a token.
func (p *ACME) GetIDForToken() string {
	return "acme/" + p.Name
}

// GetTokenID returns the identifier of the token.
func (p *ACME) GetTokenID(string) (string, error) {
	return "", errors.New("acme provisioner does not implement GetTokenID")
}

// GetName returns the name of the provisioner.
func (p *ACME) GetName() string {
	return p.Name
}

// GetType returns the type of provisioner.
func (p *ACME) GetType() Type {
	return TypeACME
}

// GetEncryptedKey returns the base provisioner encrypted key if it's defined.
func (p *ACME) GetEncryptedKey() (string, string, bool) {
	return "", "", false
}

// GetOptions returns the configured provisioner options.
func (p *ACME) GetOptions() *Options {
	return p.Options
}

// DefaultTLSCertDuration returns the default TLS cert duration enforced by
// the provisioner.
func (p *ACME) DefaultTLSCertDuration() time.Duration {
	return p.ctl.Claimer.DefaultTLSCertDuration()
}

// Init initializes and validates the fields of an ACME type.
func (p *ACME) Init(config Config) (err error) {
	switch {
	case p.Type == "":
		return errors.New("provisioner type cannot be empty")
	case p.Name == "":
		return errors.New("provisioner name cannot be empty")
	}

	for _, c := range p.Challenges {
		if err := c.Validate(); err != nil {
			return err
		}
	}
	for _, f := range p.AttestationFormats {
		if err := f.Validate(); err != nil {
			return err
		}
	}

	// Parse attestation roots.
	// The pool will be nil if there are no roots.
	if rest := p.AttestationRoots; len(rest) > 0 {
		var block *pem.Block
		var hasCert bool
		p.attestationRootPool = x509.NewCertPool()
		for rest != nil {
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return errors.New("error parsing attestationRoots: malformed certificate")
			}
			p.attestationRootPool.AddCert(cert)
			hasCert = true
		}
		if !hasCert {
			return errors.New("error parsing attestationRoots: no certificates found")
		}
	}

	if err := p.initializeWireOptions(); err != nil {
		return fmt.Errorf("failed initializing Wire options: %w", err)
	}

	if slices.Contains(p.AttestationFormats, "android-key") && len(p.RootCRLs) == 0 {
		p.initializeAndroidCRL()
	}

	p.ctl, err = NewController(p, p.Claims, config, p.Options)
	return
}

const ANDROID_ATTESTATION_STATUS_URL = "https://android.googleapis.com/attestation/status"

// fetch CRL https://android.googleapis.com/attestation/status and build a list of revoked serial numbers
func (p *ACME) fetchAndroidCRL() error {
	log.Printf("Updating Android CRL list for %s ACME provisioner", p.Name)
	var CRLResponse struct {
		Entries map[string]struct {
			Status string `json:"status"`
			Reason string `json:"reason"`
		} `json:"entries"`
	}
	res, err := http.Get(ANDROID_ATTESTATION_STATUS_URL)
	if err != nil {
		return fmt.Errorf("client: error making Android CRL request: %s\n", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(res.Body)
		return fmt.Errorf("unexpected Android CRL response %d: %s", res.StatusCode, string(bodyBytes))
	}

	if err := json.NewDecoder(res.Body).Decode(&crlResponse); err != nil {
		return fmt.Errorf("error decoding Android CRL JSON: %w", err)
	}

	// Extract keys into a slice
	keys := make([]string, 0, len(crlResponse.Entries))
	for k := range crlResponse.Entries {
		keys = append(keys, k)
	}
	p.RootCRLs = keys
	p.androidCRLTimeout = time.Now().Add(24 * time.Hour)
	return nil
}

// initializeWireOptions initializes the options for the ACME Wire
// integration. It'll return early if no Wire challenge types are
// enabled.
func (p *ACME) initializeWireOptions() error {
	hasWireChallenges := false
	for _, c := range p.Challenges {
		if c == WIREOIDC_01 || c == WIREDPOP_01 {
			hasWireChallenges = true
			break
		}
	}
	if !hasWireChallenges {
		return nil
	}

	w, err := p.GetOptions().GetWireOptions()
	if err != nil {
		return fmt.Errorf("failed getting Wire options: %w", err)
	}

	if err := w.Validate(); err != nil {
		return fmt.Errorf("failed validating Wire options: %w", err)
	}

	// at this point the Wire options have been validated, and (mostly)
	// initialized. Remote keys will be loaded upon the first verification,
	// currently.
	// TODO(hs): can/should we "prime" the underlying remote keyset, to verify
	// auto discovery works as expected? Because of the current way provisioners
	// are initialized, doing that as part of the initialization isn't the best
	// time to do it, because it could result in operations not resulting in the
	// expected result in all cases.

	return nil
}

// ACMEIdentifierType encodes ACME Identifier types
type ACMEIdentifierType string

const (
	// IP is the ACME ip identifier type
	IP ACMEIdentifierType = "ip"
	// DNS is the ACME dns identifier type
	DNS ACMEIdentifierType = "dns"
	// WireUser is the Wire user identifier type
	WireUser ACMEIdentifierType = "wireapp-user"
	// WireDevice is the Wire device identifier type
	WireDevice ACMEIdentifierType = "wireapp-device"
)

// ACMEIdentifier encodes ACME Order Identifiers
type ACMEIdentifier struct {
	Type  ACMEIdentifierType
	Value string
}

// AuthorizeOrderIdentifier verifies the provisioner is allowed to issue a
// certificate for an ACME Order Identifier.
func (p *ACME) AuthorizeOrderIdentifier(_ context.Context, identifier ACMEIdentifier) error {
	x509Policy := p.ctl.getPolicy().getX509()

	// identifier is allowed if no policy is configured
	if x509Policy == nil {
		return nil
	}

	// assuming only valid identifiers (IP or DNS) are provided
	var err error
	switch identifier.Type {
	case IP:
		err = x509Policy.IsIPAllowed(net.ParseIP(identifier.Value))
	case DNS:
		err = x509Policy.IsDNSAllowed(identifier.Value)
	case WireUser:
		var wireID wire.UserID
		if wireID, err = wire.ParseUserID(identifier.Value); err != nil {
			return fmt.Errorf("failed parsing Wire SANs: %w", err)
		}
		err = x509Policy.AreSANsAllowed([]string{wireID.Handle})
	case WireDevice:
		var wireID wire.DeviceID
		if wireID, err = wire.ParseDeviceID(identifier.Value); err != nil {
			return fmt.Errorf("failed parsing Wire SANs: %w", err)
		}
		err = x509Policy.AreSANsAllowed([]string{wireID.ClientID})
	default:
		err = fmt.Errorf("invalid ACME identifier type '%s' provided", identifier.Type)
	}

	return err
}

// AuthorizeSign does not do any validation, because all validation is handled
// in the ACME protocol. This method returns a list of modifiers / constraints
// on the resulting certificate.
func (p *ACME) AuthorizeSign(context.Context, string) ([]SignOption, error) {
	opts := []SignOption{
		p,
		// modifiers / withOptions
		newProvisionerExtensionOption(TypeACME, p.Name, "").WithControllerOptions(p.ctl),
		newForceCNOption(p.ForceCN),
		profileDefaultDuration(p.ctl.Claimer.DefaultTLSCertDuration()),
		// validators
		defaultPublicKeyValidator{},
		newValidityValidator(p.ctl.Claimer.MinTLSCertDuration(), p.ctl.Claimer.MaxTLSCertDuration()),
		newX509NamePolicyValidator(p.ctl.getPolicy().getX509()),
		p.ctl.newWebhookController(nil, linkedca.Webhook_X509),
	}

	return opts, nil
}

// AuthorizeRevoke is called just before the certificate is to be revoked by
// the CA. It can be used to authorize revocation of a certificate. With the
// ACME protocol, revocation authorization is specified and performed as part
// of the client/server interaction, so this is a no-op.
func (p *ACME) AuthorizeRevoke(context.Context, string) error {
	return nil
}

// AuthorizeRenew returns an error if the renewal is disabled.
// NOTE: This method does not actually validate the certificate or check its
// revocation status. Just confirms that the provisioner that created the
// certificate was configured to allow renewals.
func (p *ACME) AuthorizeRenew(ctx context.Context, cert *x509.Certificate) error {
	return p.ctl.AuthorizeRenew(ctx, cert)
}

// IsChallengeEnabled checks if the given challenge is enabled. By default
// http-01, dns-01 and tls-alpn-01 are enabled, to disable any of them the
// Challenge provisioner property should have at least one element.
func (p *ACME) IsChallengeEnabled(_ context.Context, challenge ACMEChallenge) bool {
	enabledChallenges := []ACMEChallenge{
		HTTP_01, DNS_01, TLS_ALPN_01,
	}
	if len(p.Challenges) > 0 {
		enabledChallenges = p.Challenges
	}
	for _, ch := range enabledChallenges {
		if strings.EqualFold(string(ch), string(challenge)) {
			return true
		}
	}
	return false
}

// IsAttestationFormatEnabled checks if the given attestation format is enabled.
// By default apple, step and tpm are enabled, to disable any of them the
// AttestationFormat provisioner property should have at least one element.
func (p *ACME) IsAttestationFormatEnabled(_ context.Context, format ACMEAttestationFormat) bool {
	enabledFormats := []ACMEAttestationFormat{
		APPLE, STEP, TPM, ANDROID,
	}
	if len(p.AttestationFormats) > 0 {
		enabledFormats = p.AttestationFormats
	}
	for _, f := range enabledFormats {
		if strings.EqualFold(string(f), string(format)) {
			return true
		}
	}
	return false
}

// GetAttestationRoots returns certificate pool with the configured attestation
// roots and reports if the pool contains at least one certificate.
//
// TODO(hs): we may not want to expose the root pool like this; call into an
// interface function instead to authorize?
func (p *ACME) GetAttestationRoots() (*x509.CertPool, bool) {
	return p.attestationRootPool, p.attestationRootPool != nil
}

// IsRootRevoked return a true if the serialNumber is part of the list
// It will also be in charge of updating the list periodically if no CRL list is provided at configuration.
func (p *ACME) IsRootRevoked(serialNumber string) bool {
	if slices.Contains(p.AttestationFormats, "android-key") && !p.androidCRLTimeout.IsZero() && time.Now().After(p.androidCRLTimeout) {
		p.initializeAndroidCRL()
	}
	return len(p.RootCRLs) > 0 && slices.Contains(p.RootCRLs, serialNumber)
}
