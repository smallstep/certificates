// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// The code in this file is an adapted version of the code in
// https://cs.opensource.google/go/go/+/refs/tags/go1.17.5:src/crypto/x509/verify.go
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"strings"

	"golang.org/x/net/idna"

	"go.step.sm/crypto/x509util"
)

// validateNames verifies that all names are allowed.
func (e *NamePolicyEngine) validateNames(dnsNames []string, ips []net.IP, emailAddresses []string, uris []*url.URL, principals []string) error {
	// nothing to compare against; return early
	if e.totalNumberOfConstraints == 0 {
		return nil
	}

	// TODO: set limit on total of all names validated? In x509 there's a limit on the number of comparisons
	// that protects the CA from a DoS (i.e. many heavy comparisons). The x509 implementation takes
	// this number as a total of all checks and keeps a (pointer to a) counter of the number of checks
	// executed so far.

	// TODO: gather all errors, or return early? Currently we return early on the first wrong name; check might fail for multiple names.
	// Perhaps make that an option?
	for _, dns := range dnsNames {
		// if there are DNS names to check, no DNS constraints set, but there are other permitted constraints,
		// then return error, because DNS should be explicitly configured to be allowed in that case. In case there are
		// (other) excluded constraints, we'll allow a DNS (implicit allow; currently).
		if e.numberOfDNSDomainConstraints == 0 && e.totalNumberOfPermittedConstraints > 0 {
			return &NamePolicyError{
				Reason:   NotAllowed,
				NameType: DNSNameType,
				Name:     dns,
				detail:   fmt.Sprintf("dns %q is not explicitly permitted by any constraint", dns),
			}
		}
		didCutWildcard := false
		parsedDNS := dns
		if strings.HasPrefix(parsedDNS, "*.") {
			parsedDNS = parsedDNS[1:]
			didCutWildcard = true
		}
		// TODO(hs): fix this above; we need separate rule for Subject Common Name?
		parsedDNS, err := idna.Lookup.ToASCII(parsedDNS)
		if err != nil {
			return &NamePolicyError{
				Reason:   CannotParseDomain,
				NameType: DNSNameType,
				Name:     dns,
				detail:   fmt.Sprintf("dns %q cannot be converted to ASCII", dns),
			}
		}
		if didCutWildcard {
			parsedDNS = "*" + parsedDNS
		}
		if _, ok := domainToReverseLabels(parsedDNS); !ok { // TODO(hs): this also fails with spaces
			return &NamePolicyError{
				Reason:   CannotParseDomain,
				NameType: DNSNameType,
				Name:     dns,
				detail:   fmt.Sprintf("cannot parse dns %q", dns),
			}
		}
		if err := checkNameConstraints(DNSNameType, dns, parsedDNS,
			func(parsedName, constraint interface{}) (bool, error) {
				return e.matchDomainConstraint(parsedName.(string), constraint.(string))
			}, e.permittedDNSDomains, e.excludedDNSDomains); err != nil {
			return err
		}
	}

	for _, ip := range ips {
		if e.numberOfIPRangeConstraints == 0 && e.totalNumberOfPermittedConstraints > 0 {
			return &NamePolicyError{
				Reason:   NotAllowed,
				NameType: IPNameType,
				Name:     ip.String(),
				detail:   fmt.Sprintf("ip %q is not explicitly permitted by any constraint", ip.String()),
			}
		}
		if err := checkNameConstraints(IPNameType, ip.String(), ip,
			func(parsedName, constraint interface{}) (bool, error) {
				return matchIPConstraint(parsedName.(net.IP), constraint.(*net.IPNet))
			}, e.permittedIPRanges, e.excludedIPRanges); err != nil {
			return err
		}
	}

	for _, email := range emailAddresses {
		if e.numberOfEmailAddressConstraints == 0 && e.totalNumberOfPermittedConstraints > 0 {
			return &NamePolicyError{
				Reason:   NotAllowed,
				NameType: EmailNameType,
				Name:     email,
				detail:   fmt.Sprintf("email %q is not explicitly permitted by any constraint", email),
			}
		}
		mailbox, ok := parseRFC2821Mailbox(email)
		if !ok {
			return &NamePolicyError{
				Reason:   CannotParseRFC822Name,
				NameType: EmailNameType,
				Name:     email,
				detail:   fmt.Sprintf("invalid rfc822Name %q", mailbox),
			}
		}
		// According to RFC 5280, section 7.5, emails are considered to match if the local part is
		// an exact match and the host (domain) part matches the ASCII representation (case-insensitive):
		// https://datatracker.ietf.org/doc/html/rfc5280#section-7.5
		domainASCII, err := idna.ToASCII(mailbox.domain)
		if err != nil {
			return &NamePolicyError{
				Reason:   CannotParseDomain,
				NameType: EmailNameType,
				Name:     email,
				detail:   fmt.Errorf("cannot parse email domain %q: %w", email, err).Error(),
			}
		}
		mailbox.domain = domainASCII
		if err := checkNameConstraints(EmailNameType, email, mailbox,
			func(parsedName, constraint interface{}) (bool, error) {
				return e.matchEmailConstraint(parsedName.(rfc2821Mailbox), constraint.(string))
			}, e.permittedEmailAddresses, e.excludedEmailAddresses); err != nil {
			return err
		}
	}

	// TODO(hs): fix internationalization for URIs (IRIs)

	for _, uri := range uris {
		if e.numberOfURIDomainConstraints == 0 && e.totalNumberOfPermittedConstraints > 0 {
			return &NamePolicyError{
				Reason:   NotAllowed,
				NameType: URINameType,
				Name:     uri.String(),
				detail:   fmt.Sprintf("uri %q is not explicitly permitted by any constraint", uri.String()),
			}
		}
		// TODO(hs): ideally we'd like the uri.String() to be the original contents; now
		// it's transformed into ASCII. Prevent that here?
		if err := checkNameConstraints(URINameType, uri.String(), uri,
			func(parsedName, constraint interface{}) (bool, error) {
				return e.matchURIConstraint(parsedName.(*url.URL), constraint.(string))
			}, e.permittedURIDomains, e.excludedURIDomains); err != nil {
			return err
		}
	}

	for _, principal := range principals {
		if e.numberOfPrincipalConstraints == 0 && e.totalNumberOfPermittedConstraints > 0 {
			return &NamePolicyError{
				Reason:   NotAllowed,
				NameType: PrincipalNameType,
				Name:     principal,
				detail:   fmt.Sprintf("username principal %q is not explicitly permitted by any constraint", principal),
			}
		}
		// TODO: some validation? I.e. allowed characters?
		if err := checkNameConstraints(PrincipalNameType, principal, principal,
			func(parsedName, constraint interface{}) (bool, error) {
				return matchPrincipalConstraint(parsedName.(string), constraint.(string))
			}, e.permittedPrincipals, e.excludedPrincipals); err != nil {
			return err
		}
	}

	// if all checks out, all SANs are allowed
	return nil
}

// validateCommonName verifies that the Subject Common Name is allowed
func (e *NamePolicyEngine) validateCommonName(commonName string) error {
	// nothing to compare against; return early
	if e.totalNumberOfConstraints == 0 {
		return nil
	}

	// empty common names are not validated
	if commonName == "" {
		return nil
	}

	if e.numberOfCommonNameConstraints > 0 {
		// Check the Common Name using its dedicated matcher if constraints have been
		// configured. If no error is returned from matching, the Common Name was
		// explicitly allowed and nil is returned immediately.
		if err := checkNameConstraints(CNNameType, commonName, commonName,
			func(parsedName, constraint interface{}) (bool, error) {
				return matchCommonNameConstraint(parsedName.(string), constraint.(string))
			}, e.permittedCommonNames, e.excludedCommonNames); err == nil {
			return nil
		}
	}

	// When an error was returned or when no constraints were configured for Common Names,
	// the Common Name should be validated against the other types of constraints too,
	// according to what type it is.
	dnsNames, ips, emails, uris := x509util.SplitSANs([]string{commonName})

	err := e.validateNames(dnsNames, ips, emails, uris, []string{})

	var pe *NamePolicyError
	if errors.As(err, &pe) {
		// override the name type with CN
		pe.NameType = CNNameType
	}

	return err
}

// checkNameConstraints checks that a name, of type nameType is permitted.
// The argument parsedName contains the parsed form of name, suitable for passing
// to the match function.
func checkNameConstraints(
	nameType NameType,
	name string,
	parsedName interface{},
	match func(parsedName, constraint interface{}) (match bool, err error),
	permitted, excluded interface{}) error {
	excludedValue := reflect.ValueOf(excluded)

	for i := 0; i < excludedValue.Len(); i++ {
		constraint := excludedValue.Index(i).Interface()
		match, err := match(parsedName, constraint)
		if err != nil {
			return &NamePolicyError{
				Reason:   CannotMatchNameToConstraint,
				NameType: nameType,
				Name:     name,
				detail:   err.Error(),
			}
		}

		if match {
			return &NamePolicyError{
				Reason:   NotAllowed,
				NameType: nameType,
				Name:     name,
				detail:   fmt.Sprintf("%s %q is excluded by constraint %q", nameType, name, constraint),
			}
		}
	}

	permittedValue := reflect.ValueOf(permitted)

	ok := true
	for i := 0; i < permittedValue.Len(); i++ {
		constraint := permittedValue.Index(i).Interface()
		var err error
		if ok, err = match(parsedName, constraint); err != nil {
			return &NamePolicyError{
				Reason:   CannotMatchNameToConstraint,
				NameType: nameType,
				Name:     name,
				detail:   err.Error(),
			}
		}

		if ok {
			break
		}
	}

	if !ok {
		return &NamePolicyError{
			Reason:   NotAllowed,
			NameType: nameType,
			Name:     name,
			detail:   fmt.Sprintf("%s %q is not permitted by any constraint", nameType, name),
		}
	}

	return nil
}

// domainToReverseLabels converts a textual domain name like foo.example.com to
// the list of labels in reverse order, e.g. ["com", "example", "foo"].
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
type rfc2821Mailbox struct {
	local, domain string
}

// parseRFC2821Mailbox parses an email address into local and domain parts,
// based on the ABNF for a “Mailbox” from RFC 2821. According to RFC 5280,
// Section 4.2.1.6 that's correct for an rfc822Name from a certificate: “The
// format of an rfc822Name is a "Mailbox" as defined in RFC 2821, Section 4.1.2”.
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

// matchDomainConstraint matches a domain against the given constraint
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

// matchURIConstraint matches an URL against a constraint
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
		host, _, err = net.SplitHostPort(host)
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

// matchPrincipalConstraint performs a string literal equality check against a constraint.
func matchPrincipalConstraint(principal, constraint string) (bool, error) {
	// allow any plain principal when wildcard constraint is used
	if constraint == "*" {
		return true, nil
	}
	return strings.EqualFold(principal, constraint), nil
}

// matchCommonNameConstraint performs a string literal equality check against constraint.
func matchCommonNameConstraint(commonName, constraint string) (bool, error) {
	// wildcard constraint is (currently) not supported for common names
	if constraint == "*" {
		return false, nil
	}
	return strings.EqualFold(commonName, constraint), nil
}
