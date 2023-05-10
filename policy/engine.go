package policy

import (
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"go.step.sm/crypto/x509util"
	"golang.org/x/crypto/ssh"

	"github.com/smallstep/certificates/errs"
)

type NamePolicyReason int

const (
	// NotAllowed results when an instance of NamePolicyEngine
	// determines that there's a constraint which doesn't permit
	// a DNS or another type of SAN to be signed (or otherwise used).
	NotAllowed NamePolicyReason = iota + 1
	// CannotParseDomain is returned when an error occurs
	// when parsing the domain part of SAN or subject.
	CannotParseDomain
	// CannotParseRFC822Name is returned when an error
	// occurs when parsing an email address.
	CannotParseRFC822Name
	// CannotMatch is the type of error returned when
	// an error happens when matching SAN types.
	CannotMatchNameToConstraint
)

type NameType string

const (
	CNNameType        NameType = "cn"
	DNSNameType       NameType = "dns"
	IPNameType        NameType = "ip"
	EmailNameType     NameType = "email"
	URINameType       NameType = "uri"
	PrincipalNameType NameType = "principal"
)

type NamePolicyError struct {
	Reason   NamePolicyReason
	NameType NameType
	Name     string
	detail   string
}

func (e *NamePolicyError) Error() string {
	switch e.Reason {
	case NotAllowed:
		return fmt.Sprintf("%s name %q not allowed", e.NameType, e.Name)
	case CannotParseDomain:
		return fmt.Sprintf("cannot parse %s domain %q", e.NameType, e.Name)
	case CannotParseRFC822Name:
		return fmt.Sprintf("cannot parse %s rfc822Name %q", e.NameType, e.Name)
	case CannotMatchNameToConstraint:
		return fmt.Sprintf("error matching %s name %q to constraint", e.NameType, e.Name)
	default:
		return fmt.Sprintf("unknown error reason (%d): %s", e.Reason, e.detail)
	}
}

// As implements the As(any) bool interface and allows to use "errors.As()" to
// convert a NotAllowed NamePolicyError to an errs.Error.
func (e *NamePolicyError) As(v any) bool {
	if e.Reason == NotAllowed {
		if err, ok := v.(**errs.Error); ok {
			*err = &errs.Error{
				Status: http.StatusForbidden,
				Msg:    fmt.Sprintf("The request was forbidden by the certificate authority: %s", e.Error()),
				Err:    e,
			}
			return true
		}
	}
	return false
}

func (e *NamePolicyError) Detail() string {
	return e.detail
}

// NamePolicyEngine can be used to check that a CSR or Certificate meets all allowed and
// denied names before a CA creates and/or signs the Certificate.
// TODO(hs): the X509 RFC also defines name checks on directory name; support that?
// TODO(hs): implement Stringer interface: describe the contents of the NamePolicyEngine?
// TODO(hs): implement matching URI schemes, paths, etc; not just the domain part of URI domains

type NamePolicyEngine struct {
	// verifySubjectCommonName is set when Subject Common Name must be verified
	verifySubjectCommonName bool
	// allowLiteralWildcardNames allows literal wildcard DNS domains
	allowLiteralWildcardNames bool

	// permitted and exluded constraints similar to x509 Name Constraints
	permittedCommonNames    []string
	excludedCommonNames     []string
	permittedDNSDomains     []string
	excludedDNSDomains      []string
	permittedIPRanges       []*net.IPNet
	excludedIPRanges        []*net.IPNet
	permittedEmailAddresses []string
	excludedEmailAddresses  []string
	permittedURIDomains     []string
	excludedURIDomains      []string
	permittedPrincipals     []string
	excludedPrincipals      []string

	// some internal counts for housekeeping
	numberOfCommonNameConstraints     int
	numberOfDNSDomainConstraints      int
	numberOfIPRangeConstraints        int
	numberOfEmailAddressConstraints   int
	numberOfURIDomainConstraints      int
	numberOfPrincipalConstraints      int
	totalNumberOfPermittedConstraints int
	totalNumberOfExcludedConstraints  int
	totalNumberOfConstraints          int
}

// NewNamePolicyEngine creates a new NamePolicyEngine with NamePolicyOptions
func New(opts ...NamePolicyOption) (*NamePolicyEngine, error) {
	e := &NamePolicyEngine{}
	for _, option := range opts {
		if err := option(e); err != nil {
			return nil, err
		}
	}

	e.permittedCommonNames = removeDuplicates(e.permittedCommonNames)
	e.permittedDNSDomains = removeDuplicates(e.permittedDNSDomains)
	e.permittedIPRanges = removeDuplicateIPNets(e.permittedIPRanges)
	e.permittedEmailAddresses = removeDuplicates(e.permittedEmailAddresses)
	e.permittedURIDomains = removeDuplicates(e.permittedURIDomains)
	e.permittedPrincipals = removeDuplicates(e.permittedPrincipals)

	e.excludedCommonNames = removeDuplicates(e.excludedCommonNames)
	e.excludedDNSDomains = removeDuplicates(e.excludedDNSDomains)
	e.excludedIPRanges = removeDuplicateIPNets(e.excludedIPRanges)
	e.excludedEmailAddresses = removeDuplicates(e.excludedEmailAddresses)
	e.excludedURIDomains = removeDuplicates(e.excludedURIDomains)
	e.excludedPrincipals = removeDuplicates(e.excludedPrincipals)

	e.numberOfCommonNameConstraints = len(e.permittedCommonNames) + len(e.excludedCommonNames)
	e.numberOfDNSDomainConstraints = len(e.permittedDNSDomains) + len(e.excludedDNSDomains)
	e.numberOfIPRangeConstraints = len(e.permittedIPRanges) + len(e.excludedIPRanges)
	e.numberOfEmailAddressConstraints = len(e.permittedEmailAddresses) + len(e.excludedEmailAddresses)
	e.numberOfURIDomainConstraints = len(e.permittedURIDomains) + len(e.excludedURIDomains)
	e.numberOfPrincipalConstraints = len(e.permittedPrincipals) + len(e.excludedPrincipals)

	e.totalNumberOfPermittedConstraints = len(e.permittedCommonNames) + len(e.permittedDNSDomains) +
		len(e.permittedIPRanges) + len(e.permittedEmailAddresses) + len(e.permittedURIDomains) +
		len(e.permittedPrincipals)

	e.totalNumberOfExcludedConstraints = len(e.excludedCommonNames) + len(e.excludedDNSDomains) +
		len(e.excludedIPRanges) + len(e.excludedEmailAddresses) + len(e.excludedURIDomains) +
		len(e.excludedPrincipals)

	e.totalNumberOfConstraints = e.totalNumberOfPermittedConstraints + e.totalNumberOfExcludedConstraints

	return e, nil
}

// removeDuplicates returns a new slice of strings with
// duplicate values removed. It retains the order of elements
// in the source slice.
func removeDuplicates(items []string) (ret []string) {
	// no need to remove dupes; return original
	if len(items) <= 1 {
		return items
	}

	keys := make(map[string]struct{}, len(items))

	ret = make([]string, 0, len(items))
	for _, item := range items {
		if _, ok := keys[item]; ok {
			continue
		}

		keys[item] = struct{}{}
		ret = append(ret, item)
	}

	return
}

// removeDuplicateIPNets returns a new slice of net.IPNets with
// duplicate values removed. It retains the order of elements in
// the source slice. An IPNet is considered duplicate if its CIDR
// notation exists multiple times in the slice.
func removeDuplicateIPNets(items []*net.IPNet) (ret []*net.IPNet) {
	// no need to remove dupes; return original
	if len(items) <= 1 {
		return items
	}

	keys := make(map[string]struct{}, len(items))

	ret = make([]*net.IPNet, 0, len(items))
	for _, item := range items {
		key := item.String() // use CIDR notation as key
		if _, ok := keys[key]; ok {
			continue
		}

		keys[key] = struct{}{}
		ret = append(ret, item)
	}

	// TODO(hs): implement filter of fully overlapping ranges,
	// so that the smaller ones are automatically removed?

	return
}

// IsX509CertificateAllowed verifies that all SANs in a Certificate are allowed.
func (e *NamePolicyEngine) IsX509CertificateAllowed(cert *x509.Certificate) error {
	if err := e.validateNames(cert.DNSNames, cert.IPAddresses, cert.EmailAddresses, cert.URIs, []string{}); err != nil {
		return err
	}

	if e.verifySubjectCommonName {
		return e.validateCommonName(cert.Subject.CommonName)
	}

	return nil
}

// IsX509CertificateRequestAllowed verifies that all names in the CSR are allowed.
func (e *NamePolicyEngine) IsX509CertificateRequestAllowed(csr *x509.CertificateRequest) error {
	if err := e.validateNames(csr.DNSNames, csr.IPAddresses, csr.EmailAddresses, csr.URIs, []string{}); err != nil {
		return err
	}

	if e.verifySubjectCommonName {
		return e.validateCommonName(csr.Subject.CommonName)
	}

	return nil
}

// AreSANsAllowed verifies that all names in the slice of SANs are allowed.
// The SANs are first split into DNS names, IPs, email addresses and URIs.
func (e *NamePolicyEngine) AreSANsAllowed(sans []string) error {
	dnsNames, ips, emails, uris := x509util.SplitSANs(sans)
	return e.validateNames(dnsNames, ips, emails, uris, []string{})
}

// IsDNSAllowed verifies a single DNS domain is allowed.
func (e *NamePolicyEngine) IsDNSAllowed(dns string) error {
	return e.validateNames([]string{dns}, []net.IP{}, []string{}, []*url.URL{}, []string{})
}

// IsIPAllowed verifies a single IP domain is allowed.
func (e *NamePolicyEngine) IsIPAllowed(ip net.IP) error {
	return e.validateNames([]string{}, []net.IP{ip}, []string{}, []*url.URL{}, []string{})
}

// IsSSHCertificateAllowed verifies that all principals in an SSH certificate are allowed.
func (e *NamePolicyEngine) IsSSHCertificateAllowed(cert *ssh.Certificate) error {
	dnsNames, ips, emails, principals, err := splitSSHPrincipals(cert)
	if err != nil {
		return err
	}
	return e.validateNames(dnsNames, ips, emails, []*url.URL{}, principals)
}

// splitPrincipals splits SSH certificate principals into DNS names, emails and usernames.
func splitSSHPrincipals(cert *ssh.Certificate) (dnsNames []string, ips []net.IP, emails, principals []string, err error) {
	dnsNames = []string{}
	ips = []net.IP{}
	emails = []string{}
	principals = []string{}
	var uris []*url.URL
	switch cert.CertType {
	case ssh.HostCert:
		dnsNames, ips, emails, uris = x509util.SplitSANs(cert.ValidPrincipals)
		if len(uris) > 0 {
			err = fmt.Errorf("URL principals %v not expected in SSH host certificate ", uris)
		}
	case ssh.UserCert:
		// re-using SplitSANs results in anything that can't be parsed as an IP, URI or email
		// to be considered a username principal. This allows usernames like h.slatman to be present
		// in the SSH certificate. We're exluding URIs, because they can be confusing
		// when used in a SSH user certificate.
		principals, ips, emails, uris = x509util.SplitSANs(cert.ValidPrincipals)
		if len(ips) > 0 {
			err = fmt.Errorf("IP principals %v not expected in SSH user certificate ", ips)
		}
		if len(uris) > 0 {
			err = fmt.Errorf("URL principals %v not expected in SSH user certificate ", uris)
		}
	default:
		err = fmt.Errorf("unexpected SSH certificate type %d", cert.CertType)
	}

	return
}
