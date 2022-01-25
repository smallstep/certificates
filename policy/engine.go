package policy

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"strings"

	"github.com/pkg/errors"
	"go.step.sm/crypto/x509util"
	"golang.org/x/crypto/ssh"
)

type NamePolicyReason int

const (
	// NotAuthorizedForThisName results when an instance of
	// NamePolicyEngine determines that there's a constraint which
	// doesn't permit a DNS or another type of SAN to be signed
	// (or otherwise used).
	NotAuthorizedForThisName NamePolicyReason = iota
)

type NamePolicyError struct {
	Reason NamePolicyReason
	Detail string
}

func (e NamePolicyError) Error() string {
	if e.Reason == NotAuthorizedForThisName {
		return "not authorized to sign for this name: " + e.Detail
	}
	return "unknown error"
}

// NamePolicyEngine can be used to check that a CSR or Certificate meets all allowed and
// denied names before a CA creates and/or signs the Certificate.
// TODO(hs): the X509 RFC also defines name checks on directory name; support that?
// TODO(hs): implement Stringer interface: describe the contents of the NamePolicyEngine?
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

// AreCertificateNamesAllowed verifies that all SANs in a Certificate are allowed.
func (e *NamePolicyEngine) AreCertificateNamesAllowed(cert *x509.Certificate) (bool, error) {
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

// AreCSRNamesAllowed verifies that all names in the CSR are allowed.
func (e *NamePolicyEngine) AreCSRNamesAllowed(csr *x509.CertificateRequest) (bool, error) {
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

// ArePrincipalsAllowed verifies that all principals in an SSH certificate are allowed.
func (e *NamePolicyEngine) ArePrincipalsAllowed(cert *ssh.Certificate) (bool, error) {
	dnsNames, ips, emails, usernames, err := splitSSHPrincipals(cert)
	if err != nil {
		return false, err
	}
	if err := e.validateNames(dnsNames, ips, emails, []*url.URL{}, usernames); err != nil {
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
func splitSSHPrincipals(cert *ssh.Certificate) (dnsNames []string, ips []net.IP, emails, usernames []string, err error) {
	dnsNames = []string{}
	ips = []net.IP{}
	emails = []string{}
	usernames = []string{}
	var uris []*url.URL
	switch cert.CertType {
	case ssh.HostCert:
		dnsNames, ips, emails, uris = x509util.SplitSANs(cert.ValidPrincipals)
		switch {
		case len(emails) > 0:
			err = fmt.Errorf("Email(-like) principals %v not expected in SSH Host certificate ", emails)
		case len(uris) > 0:
			err = fmt.Errorf("URL principals %v not expected in SSH Host certificate ", uris)
		}
	case ssh.UserCert:
		// re-using SplitSANs results in anything that can't be parsed as an IP, URI or email
		// to be considered a username. This allows usernames like h.slatman to be present
		// in the SSH certificate. We're exluding IPs and URIs, because they can be confusing
		// when used in a SSH user certificate.
		usernames, ips, emails, uris = x509util.SplitSANs(cert.ValidPrincipals)
		switch {
		case len(ips) > 0:
			err = fmt.Errorf("IP principals %v not expected in SSH User certificate ", ips)
		case len(uris) > 0:
			err = fmt.Errorf("URL principals %v not expected in SSH User certificate ", uris)
		}
	default:
		err = fmt.Errorf("unexpected SSH certificate type %d", cert.CertType)
	}

	return
}

// validateNames verifies that all names are allowed.
// Its logic follows that of (a large part of) the (c *Certificate) isValid() function
// in https://cs.opensource.google/go/go/+/refs/tags/go1.17.5:src/crypto/x509/verify.go
func (e *NamePolicyEngine) validateNames(dnsNames []string, ips []net.IP, emailAddresses []string, uris []*url.URL, usernames []string) error {

	// nothing to compare against; return early
	if e.totalNumberOfConstraints == 0 {
		return nil
	}

	// TODO: implement check that requires at least a single name in all of the SANs + subject?

	// TODO: set limit on total of all names validated? In x509 there's a limit on the number of comparisons
	// that protects the CA from a DoS (i.e. many heavy comparisons). The x509 implementation takes
	// this number as a total of all checks and keeps a (pointer to a) counter of the number of checks
	// executed so far.

	// TODO: implement matching URI schemes, paths, etc; not just the domain

	// TODO: gather all errors, or return early? Currently we return early on the first wrong name; check might fail for multiple names.
	// Perhaps make that an option?
	for _, dns := range dnsNames {
		// if there are DNS names to check, no DNS constraints set, but there are other permitted constraints,
		// then return error, because DNS should be explicitly configured to be allowed in that case. In case there are
		// (other) excluded constraints, we'll allow a DNS (implicit allow; currently).
		if e.numberOfDNSDomainConstraints == 0 && e.totalNumberOfPermittedConstraints > 0 {
			return NamePolicyError{
				Reason: NotAuthorizedForThisName,
				Detail: fmt.Sprintf("dns %q is not explicitly permitted by any constraint", dns),
			}
		}
		if _, ok := domainToReverseLabels(dns); !ok {
			return errors.Errorf("cannot parse dns %q", dns)
		}
		if err := checkNameConstraints("dns", dns, dns,
			func(parsedName, constraint interface{}) (bool, error) {
				return e.matchDomainConstraint(parsedName.(string), constraint.(string))
			}, e.permittedDNSDomains, e.excludedDNSDomains); err != nil {
			return err
		}
	}

	for _, ip := range ips {
		if e.numberOfIPRangeConstraints == 0 && e.totalNumberOfPermittedConstraints > 0 {
			return NamePolicyError{
				Reason: NotAuthorizedForThisName,
				Detail: fmt.Sprintf("ip %q is not explicitly permitted by any constraint", ip.String()),
			}
		}
		if err := checkNameConstraints("ip", ip.String(), ip,
			func(parsedName, constraint interface{}) (bool, error) {
				return matchIPConstraint(parsedName.(net.IP), constraint.(*net.IPNet))
			}, e.permittedIPRanges, e.excludedIPRanges); err != nil {
			return err
		}
	}

	for _, email := range emailAddresses {
		if e.numberOfEmailAddressConstraints == 0 && e.totalNumberOfPermittedConstraints > 0 {
			return NamePolicyError{
				Reason: NotAuthorizedForThisName,
				Detail: fmt.Sprintf("email %q is not explicitly permitted by any constraint", email),
			}
		}
		mailbox, ok := parseRFC2821Mailbox(email)
		if !ok {
			return fmt.Errorf("cannot parse rfc822Name %q", mailbox)
		}
		if err := checkNameConstraints("email", email, mailbox,
			func(parsedName, constraint interface{}) (bool, error) {
				return e.matchEmailConstraint(parsedName.(rfc2821Mailbox), constraint.(string))
			}, e.permittedEmailAddresses, e.excludedEmailAddresses); err != nil {
			return err
		}
	}

	for _, uri := range uris {
		if e.numberOfURIDomainConstraints == 0 && e.totalNumberOfPermittedConstraints > 0 {
			return NamePolicyError{
				Reason: NotAuthorizedForThisName,
				Detail: fmt.Sprintf("uri %q is not explicitly permitted by any constraint", uri.String()),
			}
		}
		if err := checkNameConstraints("uri", uri.String(), uri,
			func(parsedName, constraint interface{}) (bool, error) {
				return e.matchURIConstraint(parsedName.(*url.URL), constraint.(string))
			}, e.permittedURIDomains, e.excludedURIDomains); err != nil {
			return err
		}
	}

	for _, username := range usernames {
		if e.numberOfPrincipalConstraints == 0 && e.totalNumberOfPermittedConstraints > 0 {
			return NamePolicyError{
				Reason: NotAuthorizedForThisName,
				Detail: fmt.Sprintf("username principal %q is not explicitly permitted by any constraint", username),
			}
		}
		// TODO: some validation? I.e. allowed characters?
		if err := checkNameConstraints("username", username, username,
			func(parsedName, constraint interface{}) (bool, error) {
				return matchUsernameConstraint(parsedName.(string), constraint.(string))
			}, e.permittedPrincipals, e.excludedPrincipals); err != nil {
			return err
		}
	}

	// TODO(hs): when the error is not nil and returned up in the above, we can add
	// additional context to it (i.e. the cert or csr that was inspected).

	// TODO(hs): validate other types of SANs? The Go std library skips those.
	// These could be custom checkers.

	// if all checks out, all SANs are allowed
	return nil
}

// checkNameConstraints checks that a name, of type nameType is permitted.
// The argument parsedName contains the parsed form of name, suitable for passing
// to the match function.
// SOURCE: https://cs.opensource.google/go/go/+/refs/tags/go1.17.5:src/crypto/x509/verify.go
func checkNameConstraints(
	nameType string,
	name string,
	parsedName interface{},
	match func(parsedName, constraint interface{}) (match bool, err error),
	permitted, excluded interface{}) error {

	excludedValue := reflect.ValueOf(excluded)

	for i := 0; i < excludedValue.Len(); i++ {
		constraint := excludedValue.Index(i).Interface()
		match, err := match(parsedName, constraint)
		if err != nil {
			return NamePolicyError{
				Reason: NotAuthorizedForThisName,
				Detail: err.Error(),
			}
		}

		if match {
			return NamePolicyError{
				Reason: NotAuthorizedForThisName,
				Detail: fmt.Sprintf("%s %q is excluded by constraint %q", nameType, name, constraint),
			}
		}
	}

	permittedValue := reflect.ValueOf(permitted)

	ok := true
	for i := 0; i < permittedValue.Len(); i++ {
		constraint := permittedValue.Index(i).Interface()
		var err error
		if ok, err = match(parsedName, constraint); err != nil {
			return NamePolicyError{
				Reason: NotAuthorizedForThisName,
				Detail: err.Error(),
			}
		}

		if ok {
			break
		}
	}

	if !ok {
		return NamePolicyError{
			Reason: NotAuthorizedForThisName,
			Detail: fmt.Sprintf("%s %q is not permitted by any constraint", nameType, name),
		}
	}

	return nil
}

// domainToReverseLabels converts a textual domain name like foo.example.com to
// the list of labels in reverse order, e.g. ["com", "example", "foo"].
// SOURCE: https://cs.opensource.google/go/go/+/refs/tags/go1.17.5:src/crypto/x509/verify.go
func domainToReverseLabels(domain string) (reverseLabels []string, ok bool) {
	for len(domain) > 0 {
		if i := strings.LastIndexByte(domain, '.'); i == -1 {
			reverseLabels = append(reverseLabels, domain)
			domain = ""
		} else {
			reverseLabels = append(reverseLabels, domain[i+1:])
			domain = domain[:i]
		}
	}

	if len(reverseLabels) > 0 && reverseLabels[0] == "" {
		// An empty label at the end indicates an absolute value.
		return nil, false
	}

	for _, label := range reverseLabels {
		if label == "" {
			// Empty labels are otherwise invalid.
			return nil, false
		}

		for _, c := range label {
			if c < 33 || c > 126 {
				// Invalid character.
				return nil, false
			}
		}
	}

	return reverseLabels, true
}

// rfc2821Mailbox represents a “mailbox” (which is an email address to most
// people) by breaking it into the “local” (i.e. before the '@') and “domain”
// parts.
// SOURCE: https://cs.opensource.google/go/go/+/refs/tags/go1.17.5:src/crypto/x509/verify.go
type rfc2821Mailbox struct {
	local, domain string
}

// parseRFC2821Mailbox parses an email address into local and domain parts,
// based on the ABNF for a “Mailbox” from RFC 2821. According to RFC 5280,
// Section 4.2.1.6 that's correct for an rfc822Name from a certificate: “The
// format of an rfc822Name is a "Mailbox" as defined in RFC 2821, Section 4.1.2”.
// SOURCE: https://cs.opensource.google/go/go/+/refs/tags/go1.17.5:src/crypto/x509/verify.go
func parseRFC2821Mailbox(in string) (mailbox rfc2821Mailbox, ok bool) {
	if in == "" {
		return mailbox, false
	}

	localPartBytes := make([]byte, 0, len(in)/2)

	if in[0] == '"' {
		// Quoted-string = DQUOTE *qcontent DQUOTE
		// non-whitespace-control = %d1-8 / %d11 / %d12 / %d14-31 / %d127
		// qcontent = qtext / quoted-pair
		// qtext = non-whitespace-control /
		//         %d33 / %d35-91 / %d93-126
		// quoted-pair = ("\" text) / obs-qp
		// text = %d1-9 / %d11 / %d12 / %d14-127 / obs-text
		//
		// (Names beginning with “obs-” are the obsolete syntax from RFC 2822,
		// Section 4. Since it has been 16 years, we no longer accept that.)
		in = in[1:]
	QuotedString:
		for {
			if in == "" {
				return mailbox, false
			}
			c := in[0]
			in = in[1:]

			switch {
			case c == '"':
				break QuotedString

			case c == '\\':
				// quoted-pair
				if in == "" {
					return mailbox, false
				}
				if in[0] == 11 ||
					in[0] == 12 ||
					(1 <= in[0] && in[0] <= 9) ||
					(14 <= in[0] && in[0] <= 127) {
					localPartBytes = append(localPartBytes, in[0])
					in = in[1:]
				} else {
					return mailbox, false
				}

			case c == 11 ||
				c == 12 ||
				// Space (char 32) is not allowed based on the
				// BNF, but RFC 3696 gives an example that
				// assumes that it is. Several “verified”
				// errata continue to argue about this point.
				// We choose to accept it.
				c == 32 ||
				c == 33 ||
				c == 127 ||
				(1 <= c && c <= 8) ||
				(14 <= c && c <= 31) ||
				(35 <= c && c <= 91) ||
				(93 <= c && c <= 126):
				// qtext
				localPartBytes = append(localPartBytes, c)

			default:
				return mailbox, false
			}
		}
	} else {
		// Atom ("." Atom)*
	NextChar:
		for len(in) > 0 {
			// atext from RFC 2822, Section 3.2.4
			c := in[0]

			switch {
			case c == '\\':
				// Examples given in RFC 3696 suggest that
				// escaped characters can appear outside of a
				// quoted string. Several “verified” errata
				// continue to argue the point. We choose to
				// accept it.
				in = in[1:]
				if in == "" {
					return mailbox, false
				}
				fallthrough

			case ('0' <= c && c <= '9') ||
				('a' <= c && c <= 'z') ||
				('A' <= c && c <= 'Z') ||
				c == '!' || c == '#' || c == '$' || c == '%' ||
				c == '&' || c == '\'' || c == '*' || c == '+' ||
				c == '-' || c == '/' || c == '=' || c == '?' ||
				c == '^' || c == '_' || c == '`' || c == '{' ||
				c == '|' || c == '}' || c == '~' || c == '.':
				localPartBytes = append(localPartBytes, in[0])
				in = in[1:]

			default:
				break NextChar
			}
		}

		if len(localPartBytes) == 0 {
			return mailbox, false
		}

		// From RFC 3696, Section 3:
		// “period (".") may also appear, but may not be used to start
		// or end the local part, nor may two or more consecutive
		// periods appear.”
		twoDots := []byte{'.', '.'}
		if localPartBytes[0] == '.' ||
			localPartBytes[len(localPartBytes)-1] == '.' ||
			bytes.Contains(localPartBytes, twoDots) {
			return mailbox, false
		}
	}

	if in == "" || in[0] != '@' {
		return mailbox, false
	}
	in = in[1:]

	// The RFC species a format for domains, but that's known to be
	// violated in practice so we accept that anything after an '@' is the
	// domain part.
	if _, ok := domainToReverseLabels(in); !ok {
		return mailbox, false
	}

	mailbox.local = string(localPartBytes)
	mailbox.domain = in
	return mailbox, true
}

// SOURCE: https://cs.opensource.google/go/go/+/refs/tags/go1.17.5:src/crypto/x509/verify.go
func (e *NamePolicyEngine) matchDomainConstraint(domain, constraint string) (bool, error) {
	// The meaning of zero length constraints is not specified, but this
	// code follows NSS and accepts them as matching everything.
	if constraint == "" {
		return true, nil
	}

	// A single whitespace seems to be considered a valid domain, but we don't allow it.
	if domain == " " {
		return false, nil
	}

	// Block domains that start with just a period
	if domain[0] == '.' {
		return false, nil
	}

	// Block wildcard domains that don't start with exactly "*." (i.e. double wildcards and such)
	if domain[0] == '*' && domain[1] != '.' {
		return false, nil
	}

	// Check if the domain starts with a wildcard and return early if not allowed
	if strings.HasPrefix(domain, "*.") && !e.allowLiteralWildcardNames {
		return false, nil
	}

	// Only allow asterisk at the start of the domain; we don't allow them as part of a domain label or as a (sub)domain label (currently)
	if strings.LastIndex(domain, "*") > 0 {
		return false, nil
	}

	// Don't allow constraints with empty labels in any position
	if strings.Contains(constraint, "..") {
		return false, nil
	}

	domainLabels, ok := domainToReverseLabels(domain)
	if !ok {
		return false, fmt.Errorf("cannot parse domain %q", domain)
	}

	// RFC 5280 says that a leading period in a domain name means that at
	// least one label must be prepended, but only for URI and email
	// constraints, not DNS constraints. The code also supports that
	// behavior for DNS constraints. In our adaptation of the original
	// Go stdlib x509 Name Constraint implementation we look for exactly
	// one subdomain, currently.

	mustHaveSubdomains := false
	if constraint[0] == '.' {
		mustHaveSubdomains = true
		constraint = constraint[1:]
	}

	constraintLabels, ok := domainToReverseLabels(constraint)
	if !ok {
		return false, fmt.Errorf("cannot parse domain constraint %q", constraint)
	}

	// fmt.Println(mustHaveSubdomains)
	// fmt.Println(constraintLabels)
	// fmt.Println(domainLabels)

	expectedNumberOfLabels := len(constraintLabels)
	if mustHaveSubdomains {
		// we expect exactly one more label if it starts with the "canonical" x509 "wildcard": "."
		// in the future we could extend this to support multiple additional labels and/or more
		// complex matching.
		expectedNumberOfLabels++
	}

	if len(domainLabels) != expectedNumberOfLabels {
		return false, nil
	}

	for i, constraintLabel := range constraintLabels {
		if !strings.EqualFold(constraintLabel, domainLabels[i]) {
			return false, nil
		}
	}

	return true, nil
}

// SOURCE: https://cs.opensource.google/go/go/+/refs/tags/go1.17.5:src/crypto/x509/verify.go
func matchIPConstraint(ip net.IP, constraint *net.IPNet) (bool, error) {

	// TODO(hs): this is code from Go library, but I got some unexpected result:
	// with permitted net 127.0.0.0/24, 127.0.0.1 is NOT allowed. When parsing 127.0.0.1 as net.IP
	// which is in the IPAddresses slice, the underlying length is 16. The contraint.IP has a length
	// of 4 instead. I currently don't believe that this is a bug in Go now, but why is it like that?
	// Is there a difference because we're not operating on a sans []string slice? Or is the Go
	// implementation stricter regarding IPv4 vs. IPv6? I've been bitten by some unfortunate differences
	// between the two before (i.e. IPv4 in IPv6; IP SANS in ACME)
	// if len(ip) != len(constraint.IP) {
	// 	return false, nil
	// }

	// for i := range ip {
	// 	if mask := constraint.Mask[i]; ip[i]&mask != constraint.IP[i]&mask {
	// 		return false, nil
	// 	}
	// }

	contained := constraint.Contains(ip) // TODO(hs): validate that this is the correct behavior; also check IPv4-in-IPv6 (again)

	return contained, nil
}

// SOURCE: https://cs.opensource.google/go/go/+/refs/tags/go1.17.5:src/crypto/x509/verify.go
func (e *NamePolicyEngine) matchEmailConstraint(mailbox rfc2821Mailbox, constraint string) (bool, error) {
	// TODO(hs): handle literal wildcard case for emails? Does that even make sense?
	// If the constraint contains an @, then it specifies an exact mailbox name (currently)
	if strings.Contains(constraint, "*") {
		return false, fmt.Errorf("email constraint %q cannot contain asterisk", constraint)
	}
	if strings.Contains(constraint, "@") {
		constraintMailbox, ok := parseRFC2821Mailbox(constraint)
		if !ok {
			return false, fmt.Errorf("cannot parse constraint %q", constraint)
		}
		return mailbox.local == constraintMailbox.local && strings.EqualFold(mailbox.domain, constraintMailbox.domain), nil
	}

	// Otherwise the constraint is like a DNS constraint of the domain part
	// of the mailbox.
	return e.matchDomainConstraint(mailbox.domain, constraint)
}

// SOURCE: https://cs.opensource.google/go/go/+/refs/tags/go1.17.5:src/crypto/x509/verify.go
func (e *NamePolicyEngine) matchURIConstraint(uri *url.URL, constraint string) (bool, error) {
	// From RFC 5280, Section 4.2.1.10:
	// “a uniformResourceIdentifier that does not include an authority
	// component with a host name specified as a fully qualified domain
	// name (e.g., if the URI either does not include an authority
	// component or includes an authority component in which the host name
	// is specified as an IP address), then the application MUST reject the
	// certificate.”

	host := uri.Host
	if host == "" {
		return false, fmt.Errorf("URI with empty host (%q) cannot be matched against constraints", uri.String())
	}

	// Block hosts with the wildcard character; no exceptions, also not when wildcards allowed.
	if strings.Contains(host, "*") {
		return false, fmt.Errorf("URI host %q cannot contain asterisk", uri.String())
	}

	if strings.Contains(host, ":") && !strings.HasSuffix(host, "]") {
		var err error
		host, _, err = net.SplitHostPort(uri.Host)
		if err != nil {
			return false, err
		}
	}

	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") ||
		net.ParseIP(host) != nil {
		return false, fmt.Errorf("URI with IP %q cannot be matched against constraints", uri.String())
	}

	// TODO(hs): add checks for scheme, path, etc.; either here, or in a different constraint matcher (to keep this one simple)

	return e.matchDomainConstraint(host, constraint)
}

// matchUsernameConstraint performs a string literal match against a constraint.
func matchUsernameConstraint(username, constraint string) (bool, error) {
	// allow any plain principal username
	if constraint == "*" {
		return true, nil
	}
	return strings.EqualFold(username, constraint), nil
}
