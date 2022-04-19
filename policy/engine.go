package policy

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"net/url"

	"golang.org/x/crypto/ssh"

	"go.step.sm/crypto/x509util"
)

type NamePolicyReason int

const (
	// NotAuthorizedForThisName results when an instance of
	// NamePolicyEngine determines that there's a constraint which
	// doesn't permit a DNS or another type of SAN to be signed
	// (or otherwise used).
	NotAuthorizedForThisName NamePolicyReason = iota
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

type NamePolicyError struct {
	Reason NamePolicyReason
	Detail string
}

func (e *NamePolicyError) Error() string {
	switch e.Reason {
	case NotAuthorizedForThisName:
		return "not authorized to sign for this name: " + e.Detail
	case CannotParseDomain:
		return "cannot parse domain: " + e.Detail
	case CannotParseRFC822Name:
		return "cannot parse rfc822Name: " + e.Detail
	case CannotMatchNameToConstraint:
		return "error matching name to constraint: " + e.Detail
	default:
		return "unknown error: " + e.Detail
	}
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

	e.permittedDNSDomains = removeDuplicates(e.permittedDNSDomains)
	e.permittedIPRanges = removeDuplicateIPRanges(e.permittedIPRanges)
	e.permittedEmailAddresses = removeDuplicates(e.permittedEmailAddresses)
	e.permittedURIDomains = removeDuplicates(e.permittedURIDomains)
	e.permittedPrincipals = removeDuplicates(e.permittedPrincipals)

	e.excludedDNSDomains = removeDuplicates(e.excludedDNSDomains)
	e.excludedIPRanges = removeDuplicateIPRanges(e.excludedIPRanges)
	e.excludedEmailAddresses = removeDuplicates(e.excludedEmailAddresses)
	e.excludedURIDomains = removeDuplicates(e.excludedURIDomains)
	e.excludedPrincipals = removeDuplicates(e.excludedPrincipals)

	e.numberOfDNSDomainConstraints = len(e.permittedDNSDomains) + len(e.excludedDNSDomains)
	e.numberOfIPRangeConstraints = len(e.permittedIPRanges) + len(e.excludedIPRanges)
	e.numberOfEmailAddressConstraints = len(e.permittedEmailAddresses) + len(e.excludedEmailAddresses)
	e.numberOfURIDomainConstraints = len(e.permittedURIDomains) + len(e.excludedURIDomains)
	e.numberOfPrincipalConstraints = len(e.permittedPrincipals) + len(e.excludedPrincipals)

	e.totalNumberOfPermittedConstraints = len(e.permittedDNSDomains) + len(e.permittedIPRanges) +
		len(e.permittedEmailAddresses) + len(e.permittedURIDomains) + len(e.permittedPrincipals)

	e.totalNumberOfExcludedConstraints = len(e.excludedDNSDomains) + len(e.excludedIPRanges) +
		len(e.excludedEmailAddresses) + len(e.excludedURIDomains) + len(e.excludedPrincipals)

	e.totalNumberOfConstraints = e.totalNumberOfPermittedConstraints + e.totalNumberOfExcludedConstraints

	return e, nil
}

func removeDuplicates(strSlice []string) []string {
	if len(strSlice) == 0 {
		return nil
	}
	keys := make(map[string]bool)
	result := []string{}
	for _, item := range strSlice {
		if _, value := keys[item]; !value && item != "" { // skip empty constraints
			keys[item] = true
			result = append(result, item)
		}
	}
	return result
}

func removeDuplicateIPRanges(ipRanges []*net.IPNet) []*net.IPNet {
	if len(ipRanges) == 0 {
		return nil
	}
	keys := make(map[string]bool)
	result := []*net.IPNet{}
	for _, item := range ipRanges {
		key := item.String()
		if _, value := keys[key]; !value {
			keys[key] = true
			result = append(result, item)
		}
	}
	return result
}

// IsX509CertificateAllowed verifies that all SANs in a Certificate are allowed.
func (e *NamePolicyEngine) IsX509CertificateAllowed(cert *x509.Certificate) (bool, error) {
	dnsNames, ips, emails, uris := cert.DNSNames, cert.IPAddresses, cert.EmailAddresses, cert.URIs
	// when Subject Common Name must be verified in addition to the SANs, it is
	// added to the appropriate slice of names.
	if e.verifySubjectCommonName {
		appendSubjectCommonName(cert.Subject, &dnsNames, &ips, &emails, &uris)
	}
	if err := e.validateNames(dnsNames, ips, emails, uris, []string{}); err != nil {
		return false, err
	}
	return true, nil
}

// IsX509CertificateRequestAllowed verifies that all names in the CSR are allowed.
func (e *NamePolicyEngine) IsX509CertificateRequestAllowed(csr *x509.CertificateRequest) (bool, error) {
	dnsNames, ips, emails, uris := csr.DNSNames, csr.IPAddresses, csr.EmailAddresses, csr.URIs
	// when Subject Common Name must be verified in addition to the SANs, it is
	// added to the appropriate slice of names.
	if e.verifySubjectCommonName {
		appendSubjectCommonName(csr.Subject, &dnsNames, &ips, &emails, &uris)
	}
	if err := e.validateNames(dnsNames, ips, emails, uris, []string{}); err != nil {
		return false, err
	}
	return true, nil
}

// AreSANSAllowed verifies that all names in the slice of SANs are allowed.
// The SANs are first split into DNS names, IPs, email addresses and URIs.
func (e *NamePolicyEngine) AreSANsAllowed(sans []string) (bool, error) {
	dnsNames, ips, emails, uris := x509util.SplitSANs(sans)
	if err := e.validateNames(dnsNames, ips, emails, uris, []string{}); err != nil {
		return false, err
	}
	return true, nil
}

// IsDNSAllowed verifies a single DNS domain is allowed.
func (e *NamePolicyEngine) IsDNSAllowed(dns string) (bool, error) {
	if err := e.validateNames([]string{dns}, []net.IP{}, []string{}, []*url.URL{}, []string{}); err != nil {
		return false, err
	}
	return true, nil
}

// IsIPAllowed verifies a single IP domain is allowed.
func (e *NamePolicyEngine) IsIPAllowed(ip net.IP) (bool, error) {
	if err := e.validateNames([]string{}, []net.IP{ip}, []string{}, []*url.URL{}, []string{}); err != nil {
		return false, err
	}
	return true, nil
}

// IsSSHCertificateAllowed verifies that all principals in an SSH certificate are allowed.
func (e *NamePolicyEngine) IsSSHCertificateAllowed(cert *ssh.Certificate) (bool, error) {
	dnsNames, ips, emails, principals, err := splitSSHPrincipals(cert)
	if err != nil {
		return false, err
	}
	if err := e.validateNames(dnsNames, ips, emails, []*url.URL{}, principals); err != nil {
		return false, err
	}
	return true, nil
}

// appendSubjectCommonName appends the Subject Common Name to the appropriate slice of names. The logic is
// similar as x509util.SplitSANs: if the subject can be parsed as an IP, it's added to the ips. If it can
// be parsed as an URL, it is added to the URIs. If it contains an @, it is added to emails. When it's none
// of these, it's added to the DNS names.
func appendSubjectCommonName(subject pkix.Name, dnsNames *[]string, ips *[]net.IP, emails *[]string, uris *[]*url.URL) {
	commonName := subject.CommonName
	if commonName == "" {
		return
	}
	subjectDNSNames, subjectIPs, subjectEmails, subjectURIs := x509util.SplitSANs([]string{commonName})
	*dnsNames = append(*dnsNames, subjectDNSNames...)
	*ips = append(*ips, subjectIPs...)
	*emails = append(*emails, subjectEmails...)
	*uris = append(*uris, subjectURIs...)
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