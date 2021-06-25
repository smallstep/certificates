package acme

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/smallstep/certificates/authority/provisioner"
	"go.step.sm/crypto/x509util"
)

type IdentifierType string

const (
	IP  IdentifierType = "ip"
	DNS IdentifierType = "dns"
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

// Finalize signs a certificate if the necessary conditions for Order completion
// have been met.
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

	// canonicalize the CSR to allow for comparison
	csr = canonicalize(csr)

	// retrieve the requested SANs for the Order
	sans, err := o.sans(csr)
	if err != nil {
		return err
	}

	// Get authorizations from the ACME provisioner.
	ctx = provisioner.NewContextWithMethod(ctx, provisioner.SignMethod)
	signOps, err := p.AuthorizeSign(ctx, "")
	if err != nil {
		return WrapErrorISE(err, "error retrieving authorization options from ACME provisioner")
	}

	// Template data
	data := x509util.NewTemplateData()
	data.SetCommonName(csr.Subject.CommonName)
	data.Set(x509util.SANsKey, sans)

	templateOptions, err := provisioner.TemplateOptions(p.GetOptions(), data)
	if err != nil {
		return WrapErrorISE(err, "error creating template options from ACME provisioner")
	}
	signOps = append(signOps, templateOptions)

	// Sign a new certificate.
	certChain, err := auth.Sign(csr, provisioner.SignOptions{
		NotBefore: provisioner.NewTimeDuration(o.NotBefore),
		NotAfter:  provisioner.NewTimeDuration(o.NotAfter),
	}, signOps...)
	if err != nil {
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

func (o *Order) sans(csr *x509.CertificateRequest) ([]x509util.SubjectAlternativeName, error) {

	var sans []x509util.SubjectAlternativeName

	// order the DNS names and IP addresses, so that they can be compared against the canonicalized CSR
	orderNames := make([]string, numberOfIdentifierType(DNS, o.Identifiers))
	orderIPs := make([]net.IP, numberOfIdentifierType(IP, o.Identifiers))
	indexDNS, indexIP := 0, 0
	for _, n := range o.Identifiers {
		switch n.Type {
		case DNS:
			orderNames[indexDNS] = n.Value
			indexDNS++
		case IP:
			orderIPs[indexIP] = net.ParseIP(n.Value) // NOTE: this assumes are all valid IPs at this time; or will result in nil entries
			indexIP++
		default:
			return sans, NewErrorISE("unsupported identifier type in order: %s", n.Type)
		}
	}
	orderNames = uniqueSortedLowerNames(orderNames)
	orderIPs = uniqueSortedIPs(orderIPs)

	totalNumberOfSANs := len(csr.DNSNames) + len(csr.IPAddresses)
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
// but may not be expected.
func canonicalize(csr *x509.CertificateRequest) (canonicalized *x509.CertificateRequest) {

	// for clarity only; we're operating on the same object by pointer
	canonicalized = csr

	// RFC8555: The CSR MUST indicate the exact same set of requested
	// identifiers as the initial newOrder request. Identifiers of type "dns"
	// MUST appear either in the commonName portion of the requested subject
	// name or in an extensionRequest attribute [RFC2985] requesting a
	// subjectAltName extension, or both.
	if csr.Subject.CommonName != "" {
		canonicalized.DNSNames = append(csr.DNSNames, csr.Subject.CommonName)
	}
	canonicalized.DNSNames = uniqueSortedLowerNames(csr.DNSNames)
	canonicalized.IPAddresses = uniqueSortedIPs(csr.IPAddresses)

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
		ipEntryMap[ip.String()] = entry{ip: ip}
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
