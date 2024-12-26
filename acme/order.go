package acme

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/x509util"

	"github.com/smallstep/certificates/acme/wire"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/webhook"
)

type IdentifierType string

const (
	// IP is the ACME ip identifier type
	IP IdentifierType = "ip"
	// DNS is the ACME dns identifier type
	DNS IdentifierType = "dns"
	// PermanentIdentifier is the ACME permanent-identifier identifier type
	// defined in https://datatracker.ietf.org/doc/html/draft-bweeks-acme-device-attest-00
	PermanentIdentifier IdentifierType = "permanent-identifier"
	// WireUser is the Wire user identifier type
	WireUser IdentifierType = "wireapp-user"
	// WireDevice is the Wire device identifier type
	WireDevice IdentifierType = "wireapp-device"
)

// Identifier encodes the type that an order pertains to.
type Identifier struct {
	Type  IdentifierType `json:"type"`
	Value string         `json:"value"`
}

// Order contains order metadata for the ACME protocol order type.
type Order struct {
	ID                string       `json:"id"`
	AccountID         string       `json:"-"`
	ProvisionerID     string       `json:"-"`
	Status            Status       `json:"status"`
	ExpiresAt         time.Time    `json:"expires"`
	Identifiers       []Identifier `json:"identifiers"`
	NotBefore         time.Time    `json:"notBefore"`
	NotAfter          time.Time    `json:"notAfter"`
	Error             *Error       `json:"error,omitempty"`
	AuthorizationIDs  []string     `json:"-"`
	AuthorizationURLs []string     `json:"authorizations"`
	FinalizeURL       string       `json:"finalize"`
	CertificateID     string       `json:"-"`
	CertificateURL    string       `json:"certificate,omitempty"`
}

// ToLog enables response logging.
func (o *Order) ToLog() (interface{}, error) {
	b, err := json.Marshal(o)
	if err != nil {
		return nil, WrapErrorISE(err, "error marshaling order for logging")
	}
	return string(b), nil
}

// UpdateStatus updates the ACME Order Status if necessary.
// Changes to the order are saved using the database interface.
func (o *Order) UpdateStatus(ctx context.Context, db DB) error {
	now := clock.Now()

	switch o.Status {
	case StatusInvalid:
		return nil
	case StatusValid:
		return nil
	case StatusReady:
		// Check expiry
		if now.After(o.ExpiresAt) {
			o.Status = StatusInvalid
			o.Error = NewError(ErrorMalformedType, "order has expired")
			break
		}
		return nil
	case StatusPending:
		// Check expiry
		if now.After(o.ExpiresAt) {
			o.Status = StatusInvalid
			o.Error = NewError(ErrorMalformedType, "order has expired")
			break
		}

		var count = map[Status]int{
			StatusValid:   0,
			StatusInvalid: 0,
			StatusPending: 0,
		}
		for _, azID := range o.AuthorizationIDs {
			az, err := db.GetAuthorization(ctx, azID)
			if err != nil {
				return WrapErrorISE(err, "error getting authorization ID %s", azID)
			}
			if err = az.UpdateStatus(ctx, db); err != nil {
				return WrapErrorISE(err, "error updating authorization ID %s", azID)
			}
			st := az.Status
			count[st]++
		}
		switch {
		case count[StatusInvalid] > 0:
			o.Status = StatusInvalid

		// No change in the order status, so just return the order as is -
		// without writing any changes.
		case count[StatusPending] > 0:
			return nil

		case count[StatusValid] == len(o.AuthorizationIDs):
			o.Status = StatusReady

		default:
			return NewErrorISE("unexpected authz status")
		}
	default:
		return NewErrorISE("unrecognized order status: %s", o.Status)
	}

	if err := db.UpdateOrder(ctx, o); err != nil {
		return WrapErrorISE(err, "error updating order")
	}

	return nil
}

// getAuthorizationFingerprint returns a fingerprint from the list of authorizations. This
// fingerprint is used on the device-attest-01 flow to verify the attestation
// certificate public key with the CSR public key.
//
// There's no point on reading all the authorizations as there will be only one
// for a permanent identifier.
func (o *Order) getAuthorizationFingerprint(ctx context.Context, db DB) (string, error) {
	for _, azID := range o.AuthorizationIDs {
		az, err := db.GetAuthorization(ctx, azID)
		if err != nil {
			return "", WrapErrorISE(err, "error getting authorization %q", azID)
		}
		// There's no point on reading all the authorizations as there will
		// be only one for a permanent identifier.
		if az.Fingerprint != "" {
			return az.Fingerprint, nil
		}
	}
	return "", nil
}

// Finalize signs a certificate if the necessary conditions for Order completion
// have been met.
//
// TODO(mariano): Here or in the challenge validation we should perform some
// external validation using the identifier value and the attestation data. From
// a validation service we can get the list of SANs to set in the final
// certificate.
func (o *Order) Finalize(ctx context.Context, db DB, csr *x509.CertificateRequest, auth CertificateAuthority, p Provisioner) error {
	if err := o.UpdateStatus(ctx, db); err != nil {
		return err
	}

	switch o.Status {
	case StatusInvalid:
		return NewError(ErrorOrderNotReadyType, "order %s has been abandoned", o.ID)
	case StatusValid:
		return nil
	case StatusPending:
		return NewError(ErrorOrderNotReadyType, "order %s is not ready", o.ID)
	case StatusReady:
		break
	default:
		return NewErrorISE("unexpected status %s for order %s", o.Status, o.ID)
	}

	// Get key fingerprint if any. And then compare it with the CSR fingerprint.
	//
	// In device-attest-01 challenges we should check that the keys in the CSR
	// and the attestation certificate are the same.
	fingerprint, err := o.getAuthorizationFingerprint(ctx, db)
	if err != nil {
		return err
	}
	if fingerprint != "" {
		fp, err := keyutil.Fingerprint(csr.PublicKey)
		if err != nil {
			return WrapErrorISE(err, "error calculating key fingerprint")
		}
		if subtle.ConstantTimeCompare([]byte(fingerprint), []byte(fp)) == 0 {
			return NewError(ErrorUnauthorizedType, "order %s csr does not match the attested key", o.ID)
		}
	}

	// canonicalize the CSR to allow for comparison
	csr = canonicalize(csr)

	// Template data
	data := x509util.NewTemplateData()
	if o.containsWireIdentifiers() {
		wireDB, ok := db.(WireDB)
		if !ok {
			return fmt.Errorf("db %T is not a WireDB", db)
		}
		subject, err := createWireSubject(o, csr)
		if err != nil {
			return fmt.Errorf("failed creating Wire subject: %w", err)
		}
		data.SetSubject(subject)

		// Inject Wire's custom challenges into the template once they have been validated
		dpop, err := wireDB.GetDpopToken(ctx, o.ID)
		if err != nil {
			return fmt.Errorf("failed getting Wire DPoP token: %w", err)
		}
		data.Set("Dpop", dpop)

		oidc, err := wireDB.GetOidcToken(ctx, o.ID)
		if err != nil {
			return fmt.Errorf("failed getting Wire OIDC token: %w", err)
		}
		data.Set("Oidc", oidc)
	} else {
		data.SetCommonName(csr.Subject.CommonName)
	}

	// Custom sign options passed to authority.Sign
	var extraOptions []provisioner.SignOption

	// TODO: support for multiple identifiers?
	var permanentIdentifier string
	for i := range o.Identifiers {
		if o.Identifiers[i].Type == PermanentIdentifier {
			permanentIdentifier = o.Identifiers[i].Value
			// the first (and only) Permanent Identifier that gets added to the certificate
			// should be equal to the Subject Common Name if it's set. If not equal, the CSR
			// is rejected, because the Common Name hasn't been challenged in that case. This
			// could result in unauthorized access if a relying system relies on the Common
			// Name in its authorization logic.
			if csr.Subject.CommonName != "" && csr.Subject.CommonName != permanentIdentifier {
				return NewError(ErrorBadCSRType, "CSR Subject Common Name does not match identifiers exactly: "+
					"CSR Subject Common Name = %s, Order Permanent Identifier = %s", csr.Subject.CommonName, permanentIdentifier)
			}
			break
		}
	}

	var defaultTemplate string
	if permanentIdentifier != "" {
		defaultTemplate = x509util.DefaultAttestedLeafTemplate
		data.SetSubjectAlternativeNames(x509util.SubjectAlternativeName{
			Type:  x509util.PermanentIdentifierType,
			Value: permanentIdentifier,
		})
		extraOptions = append(extraOptions, provisioner.AttestationData{
			PermanentIdentifier: permanentIdentifier,
		})
	} else {
		defaultTemplate = x509util.DefaultLeafTemplate
		sans, err := o.sans(csr)
		if err != nil {
			return err
		}
		data.SetSubjectAlternativeNames(sans...)
	}

	// Get authorizations from the ACME provisioner.
	ctx = provisioner.NewContextWithMethod(ctx, provisioner.SignMethod)
	signOps, err := p.AuthorizeSign(ctx, "")
	if err != nil {
		return WrapErrorISE(err, "error retrieving authorization options from ACME provisioner")
	}
	// Unlike most of the provisioners, ACME's AuthorizeSign method doesn't
	// define the templates, and the template data used in WebHooks is not
	// available.
	for _, signOp := range signOps {
		if wc, ok := signOp.(*provisioner.WebhookController); ok {
			wc.TemplateData = data
		}
	}

	templateOptions, err := provisioner.CustomTemplateOptions(p.GetOptions(), data, defaultTemplate)
	if err != nil {
		return WrapErrorISE(err, "error creating template options from ACME provisioner")
	}

	// Build extra signing options.
	signOps = append(signOps, templateOptions)
	signOps = append(signOps, extraOptions...)

	// Sign a new certificate.
	certChain, err := auth.SignWithContext(ctx, csr, provisioner.SignOptions{
		NotBefore: provisioner.NewTimeDuration(o.NotBefore),
		NotAfter:  provisioner.NewTimeDuration(o.NotAfter),
	}, signOps...)
	if err != nil {
		// Add subproblem for webhook errors, others can be added later.
		var webhookErr *webhook.Error
		if errors.As(err, &webhookErr) {
			//nolint:govet // ignore non-constant format string
			acmeError := NewDetailedError(ErrorUnauthorizedType, webhookErr.Error())
			acmeError.AddSubproblems(Subproblem{
				Type:   fmt.Sprintf("urn:smallstep:acme:error:%s", webhookErr.Code),
				Detail: webhookErr.Message,
			})
			return acmeError
		}

		return WrapErrorISE(err, "error signing certificate for order %s", o.ID)
	}

	cert := &Certificate{
		AccountID:     o.AccountID,
		OrderID:       o.ID,
		Leaf:          certChain[0],
		Intermediates: certChain[1:],
	}
	if err := db.CreateCertificate(ctx, cert); err != nil {
		return WrapErrorISE(err, "error creating certificate for order %s", o.ID)
	}

	o.CertificateID = cert.ID
	o.Status = StatusValid

	if err = db.UpdateOrder(ctx, o); err != nil {
		return WrapErrorISE(err, "error updating order %s", o.ID)
	}

	return nil
}

// containsWireIdentifiers checks if [Order] contains ACME
// identifiers for the WireUser or WireDevice types.
func (o *Order) containsWireIdentifiers() bool {
	for _, i := range o.Identifiers {
		if i.Type == WireUser || i.Type == WireDevice {
			return true
		}
	}
	return false
}

// createWireSubject creates the subject for an [Order] with WireUser identifiers.
func createWireSubject(o *Order, csr *x509.CertificateRequest) (subject x509util.Subject, err error) {
	wireUserIDs, wireDeviceIDs, otherIDs := 0, 0, 0
	for _, identifier := range o.Identifiers {
		switch identifier.Type {
		case WireUser:
			wireID, err := wire.ParseUserID(identifier.Value)
			if err != nil {
				return subject, NewErrorISE("unmarshal wireID: %s", err)
			}

			// TODO: temporarily using a custom OIDC for carrying the display name without having it listed as a DNS SAN.
			// reusing LDAP's OID for diplay name see http://oid-info.com/get/2.16.840.1.113730.3.1.241
			displayNameOid := asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 3, 1, 241}
			var foundDisplayName = false
			for _, entry := range csr.Subject.Names {
				if entry.Type.Equal(displayNameOid) {
					foundDisplayName = true
					displayName := entry.Value.(string)
					if displayName != wireID.Name {
						return subject, NewErrorISE("expected displayName %v, found %v", wireID.Name, displayName)
					}
				}
			}
			if !foundDisplayName {
				return subject, NewErrorISE("CSR must contain the display name in '2.16.840.1.113730.3.1.241' OID")
			}

			if len(csr.Subject.Organization) == 0 || !strings.EqualFold(csr.Subject.Organization[0], wireID.Domain) {
				return subject, NewErrorISE("expected Organization [%s], found %v", wireID.Domain, csr.Subject.Organization)
			}
			subject.CommonName = wireID.Name
			subject.Organization = []string{wireID.Domain}
			wireUserIDs++
		case WireDevice:
			wireDeviceIDs++
		default:
			otherIDs++
		}
	}

	if otherIDs > 0 || wireUserIDs != 1 && wireDeviceIDs != 1 {
		return subject, NewErrorISE("order must have exactly one WireUser and WireDevice identifier")
	}

	return
}

func (o *Order) sans(csr *x509.CertificateRequest) ([]x509util.SubjectAlternativeName, error) {
	var sans []x509util.SubjectAlternativeName
	if len(csr.EmailAddresses) > 0 {
		return sans, NewError(ErrorBadCSRType, "Only DNS names and IP addresses are allowed")
	}

	// order the DNS names and IP addresses, so that they can be compared against the canonicalized CSR
	orderNames := make([]string, numberOfIdentifierType(DNS, o.Identifiers))
	orderIPs := make([]net.IP, numberOfIdentifierType(IP, o.Identifiers))
	orderPIDs := make([]string, numberOfIdentifierType(PermanentIdentifier, o.Identifiers))
	tmpOrderURIs := make([]*url.URL, numberOfIdentifierType(WireUser, o.Identifiers)+numberOfIdentifierType(WireDevice, o.Identifiers))
	indexDNS, indexIP, indexPID, indexURI := 0, 0, 0, 0
	for _, n := range o.Identifiers {
		switch n.Type {
		case DNS:
			orderNames[indexDNS] = n.Value
			indexDNS++
		case IP:
			orderIPs[indexIP] = net.ParseIP(n.Value) // NOTE: this assumes are all valid IPs at this time; or will result in nil entries
			indexIP++
		case PermanentIdentifier:
			orderPIDs[indexPID] = n.Value
			indexPID++
		case WireUser:
			wireID, err := wire.ParseUserID(n.Value)
			if err != nil {
				return sans, NewErrorISE("unsupported identifier value in order: %s", n.Value)
			}
			handle, err := url.Parse(wireID.Handle)
			if err != nil {
				return sans, NewErrorISE("handle must be a URI: %s", wireID.Handle)
			}
			tmpOrderURIs[indexURI] = handle
			indexURI++
		case WireDevice:
			wireID, err := wire.ParseDeviceID(n.Value)
			if err != nil {
				return sans, NewErrorISE("unsupported identifier value in order: %s", n.Value)
			}
			clientID, err := url.Parse(wireID.ClientID)
			if err != nil {
				return sans, NewErrorISE("clientId must be a URI: %s", wireID.ClientID)
			}
			tmpOrderURIs[indexURI] = clientID
			indexURI++
		default:
			return sans, NewErrorISE("unsupported identifier type in order: %s", n.Type)
		}
	}
	orderNames = uniqueSortedLowerNames(orderNames)
	orderIPs = uniqueSortedIPs(orderIPs)
	orderURIs := uniqueSortedURIStrings(tmpOrderURIs)

	totalNumberOfSANs := len(csr.DNSNames) + len(csr.IPAddresses) + len(csr.URIs)
	sans = make([]x509util.SubjectAlternativeName, totalNumberOfSANs)
	index := 0

	// Validate identifier names against CSR alternative names.
	//
	// Note that with certificate templates we are not going to check for the
	// absence of other SANs as they will only be set if the template allows
	// them.
	if len(csr.DNSNames) != len(orderNames) {
		return sans, NewError(ErrorBadCSRType, "CSR names do not match identifiers exactly: "+
			"CSR names = %v, Order names = %v", csr.DNSNames, orderNames)
	}

	for i := range csr.DNSNames {
		if csr.DNSNames[i] != orderNames[i] {
			return sans, NewError(ErrorBadCSRType, "CSR names do not match identifiers exactly: "+
				"CSR names = %v, Order names = %v", csr.DNSNames, orderNames)
		}
		sans[index] = x509util.SubjectAlternativeName{
			Type:  x509util.DNSType,
			Value: csr.DNSNames[i],
		}
		index++
	}

	if len(csr.IPAddresses) != len(orderIPs) {
		return sans, NewError(ErrorBadCSRType, "CSR IPs do not match identifiers exactly: "+
			"CSR IPs = %v, Order IPs = %v", csr.IPAddresses, orderIPs)
	}

	for i := range csr.IPAddresses {
		if !ipsAreEqual(csr.IPAddresses[i], orderIPs[i]) {
			return sans, NewError(ErrorBadCSRType, "CSR IPs do not match identifiers exactly: "+
				"CSR IPs = %v, Order IPs = %v", csr.IPAddresses, orderIPs)
		}
		sans[index] = x509util.SubjectAlternativeName{
			Type:  x509util.IPType,
			Value: csr.IPAddresses[i].String(),
		}
		index++
	}

	if len(csr.URIs) != len(tmpOrderURIs) {
		return sans, NewError(ErrorBadCSRType, "CSR URIs do not match identifiers exactly: "+
			"CSR URIs = %v, Order URIs = %v", csr.URIs, tmpOrderURIs)
	}

	// sort URI list
	csrURIs := uniqueSortedURIStrings(csr.URIs)

	for i := range csrURIs {
		if csrURIs[i] != orderURIs[i] {
			return sans, NewError(ErrorBadCSRType, "CSR URIs do not match identifiers exactly: "+
				"CSR URIs = %v, Order URIs = %v", csr.URIs, tmpOrderURIs)
		}
		sans[index] = x509util.SubjectAlternativeName{
			Type:  x509util.URIType,
			Value: orderURIs[i],
		}
		index++
	}

	return sans, nil
}

// numberOfIdentifierType returns the number of Identifiers that
// are of type typ.
func numberOfIdentifierType(typ IdentifierType, ids []Identifier) int {
	c := 0
	for _, id := range ids {
		if id.Type == typ {
			c++
		}
	}
	return c
}

// canonicalize canonicalizes a CSR so that it can be compared against an Order
// NOTE: this effectively changes the order of SANs in the CSR, which may be OK,
// but may not be expected. It also adds a Subject Common Name to either the IP
// addresses or DNS names slice, depending on whether it can be parsed as an IP
// or not. This might result in an additional SAN in the final certificate.
func canonicalize(csr *x509.CertificateRequest) (canonicalized *x509.CertificateRequest) {
	// for clarity only; we're operating on the same object by pointer
	canonicalized = csr

	// RFC8555: The CSR MUST indicate the exact same set of requested
	// identifiers as the initial newOrder request. Identifiers of type "dns"
	// MUST appear either in the commonName portion of the requested subject
	// name or in an extensionRequest attribute [RFC2985] requesting a
	// subjectAltName extension, or both. Subject Common Names that can be
	// parsed as an IP are included as an IP address for the equality check.
	// If these were excluded, a certificate could contain an IP as the
	// common name without having been challenged.
	if csr.Subject.CommonName != "" {
		if ip := net.ParseIP(csr.Subject.CommonName); ip != nil {
			canonicalized.IPAddresses = append(canonicalized.IPAddresses, ip)
		} else {
			canonicalized.DNSNames = append(canonicalized.DNSNames, csr.Subject.CommonName)
		}
	}

	canonicalized.DNSNames = uniqueSortedLowerNames(canonicalized.DNSNames)
	canonicalized.IPAddresses = uniqueSortedIPs(canonicalized.IPAddresses)

	return canonicalized
}

// ipsAreEqual compares IPs to be equal. Nil values (i.e. invalid IPs) are
// not considered equal. IPv6 representations of IPv4 addresses are
// considered equal to the IPv4 address in this implementation, which is
// standard Go behavior. An example is "::ffff:192.168.42.42", which
// is equal to "192.168.42.42". This is considered a known issue within
// step and is tracked here too: https://github.com/golang/go/issues/37921.
func ipsAreEqual(x, y net.IP) bool {
	if x == nil || y == nil {
		return false
	}
	return x.Equal(y)
}

// uniqueSortedLowerNames returns the set of all unique names in the input after all
// of them are lowercased. The returned names will be in their lowercased form
// and sorted alphabetically.
func uniqueSortedLowerNames(names []string) (unique []string) {
	nameMap := make(map[string]int, len(names))
	for _, name := range names {
		nameMap[strings.ToLower(name)] = 1
	}
	unique = make([]string, 0, len(nameMap))
	for name := range nameMap {
		if name != "" {
			unique = append(unique, name)
		}
	}
	sort.Strings(unique)
	return
}

func uniqueSortedURIStrings(uris []*url.URL) (unique []string) {
	uriMap := make(map[string]struct{}, len(uris))
	for _, name := range uris {
		uriMap[name.String()] = struct{}{}
	}
	unique = make([]string, 0, len(uriMap))
	for name := range uriMap {
		unique = append(unique, name)
	}
	sort.Strings(unique)
	return
}

// uniqueSortedIPs returns the set of all unique net.IPs in the input. They
// are sorted by their bytes (octet) representation.
func uniqueSortedIPs(ips []net.IP) (unique []net.IP) {
	type entry struct {
		ip net.IP
	}
	ipEntryMap := make(map[string]entry, len(ips))
	for _, ip := range ips {
		// reparsing the IP results in the IP being represented using 16 bytes
		// for both IPv4 as well as IPv6, even when the ips slice contains IPs that
		// are represented by 4 bytes. This ensures a fair comparison and thus ordering.
		ipEntryMap[ip.String()] = entry{ip: net.ParseIP(ip.String())}
	}
	unique = make([]net.IP, 0, len(ipEntryMap))
	for _, entry := range ipEntryMap {
		unique = append(unique, entry.ip)
	}
	sort.Slice(unique, func(i, j int) bool {
		return bytes.Compare(unique[i], unique[j]) < 0
	})
	return
}
