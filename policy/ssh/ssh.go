package sshpolicy

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"reflect"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

type CertificateInvalidError struct {
	Reason x509.InvalidReason
	Detail string
}

func (e CertificateInvalidError) Error() string {
	switch e.Reason {
	// TODO: include logical errors for this package; exlude ones that don't make sense for its current use case?
	// TODO: currently only CANotAuthorizedForThisName is used by this package; we're not checking the other things in CSRs in this package.
	case x509.NotAuthorizedToSign:
		return "not authorized to sign other certificates" // TODO: this one doesn't make sense for this pkg
	case x509.Expired:
		return "csr has expired or is not yet valid: " + e.Detail
	case x509.CANotAuthorizedForThisName:
		return "not authorized to sign for this name: " + e.Detail
	case x509.CANotAuthorizedForExtKeyUsage:
		return "not authorized for an extended key usage: " + e.Detail
	case x509.TooManyIntermediates:
		return "too many intermediates for path length constraint"
	case x509.IncompatibleUsage:
		return "csr specifies an incompatible key usage"
	case x509.NameMismatch:
		return "issuer name does not match subject from issuing certificate"
	case x509.NameConstraintsWithoutSANs:
		return "issuer has name constraints but csr doesn't have a SAN extension"
	case x509.UnconstrainedName:
		return "issuer has name constraints but csr contains unknown or unconstrained name: " + e.Detail
	}
	return "unknown error"
}

type NamePolicyEngine struct {
	options                 []NamePolicyOption
	permittedDNSDomains     []string
	excludedDNSDomains      []string
	permittedEmailAddresses []string
	excludedEmailAddresses  []string
	permittedPrincipals     []string // TODO: rename to usernames, as principals can be host, user@ (like mail) and usernames?
	excludedPrincipals      []string
}

func New(opts ...NamePolicyOption) (*NamePolicyEngine, error) {

	e := &NamePolicyEngine{} // TODO: embed an x509 engine instead of building it again?
	e.options = append(e.options, opts...)
	for _, option := range e.options {
		if err := option(e); err != nil {
			return nil, err
		}
	}

	return e, nil
}

func (e *NamePolicyEngine) ArePrincipalsAllowed(cert *ssh.Certificate) (bool, error) {
	dnsNames, emails, userNames := splitPrincipals(cert.ValidPrincipals)
	if err := e.validateNames(dnsNames, emails, userNames); err != nil {
		return false, err
	}
	return true, nil
}

func (e *NamePolicyEngine) validateNames(dnsNames, emails, userNames []string) error {
	//"dns": ["*.smallstep.com"],
	//"email": ["@smallstep.com", "@google.com"],
	//"principal": ["max", "mariano", "mike"]
	/* No regexes for now. But if we ever implement them, they'd probably look like this */
	/*"principal": ["foo.smallstep.com", "/^*\.smallstep\.com$/"]*/

	// Principals can be single user names (mariano, max, mike, ...), hostnames/domains (*.smallstep.com, host.smallstep.com, ...) and emails (max@smallstep.com, @smallstep.com, ...)
	// All ValidPrincipals can thus be any one of those, and they can be mixed (mike@smallstep.com, mike, ...); we need to split this?
	// Should we assume a generic engine, or can we do it host vs. user based? If host vs. user based, then it becomes easier w.r.t. dns; hosts will only be DNS, right?
	// If we assume generic, we _may_ have a harder time distinguishing host vs. user certs. We propose to use host + user specific provisioners, though...
	// Perhaps we can do some heuristics on the principal names vs. hostnames (i.e. when only a single label and no dot, then it's a user principal)

	for _, dns := range dnsNames {
		if _, ok := domainToReverseLabels(dns); !ok {
			return errors.Errorf("cannot parse dns %q", dns)
		}
		if err := checkNameConstraints("dns", dns, dns,
			func(parsedName, constraint interface{}) (bool, error) {
				return matchDomainConstraint(parsedName.(string), constraint.(string))
			}, e.permittedDNSDomains, e.excludedDNSDomains); err != nil {
			return err
		}
	}

	for _, email := range emails {
		mailbox, ok := parseRFC2821Mailbox(email)
		if !ok {
			return fmt.Errorf("cannot parse rfc822Name %q", mailbox)
		}
		if err := checkNameConstraints("email", email, mailbox,
			func(parsedName, constraint interface{}) (bool, error) {
				return matchEmailConstraint(parsedName.(rfc2821Mailbox), constraint.(string))
			}, e.permittedEmailAddresses, e.excludedEmailAddresses); err != nil {
			return err
		}
	}

	for _, userName := range userNames {
		// TODO: some validation? I.e. allowed characters?
		if err := checkNameConstraints("username", userName, userName,
			func(parsedName, constraint interface{}) (bool, error) {
				return matchUserNameConstraint(parsedName.(string), constraint.(string))
			}, e.permittedPrincipals, e.excludedPrincipals); err != nil {
			return err
		}
	}

	return nil
}

// splitPrincipals splits SSH certificate principals into DNS names, emails and user names.
func splitPrincipals(principals []string) (dnsNames, emails, userNames []string) {
	dnsNames = []string{}
	emails = []string{}
	userNames = []string{}
	for _, principal := range principals {
		if strings.Contains(principal, "@") {
			emails = append(emails, principal)
		} else if len(strings.Split(principal, ".")) > 1 {
			dnsNames = append(dnsNames, principal)
		} else {
			userNames = append(userNames, principal)
		}
	}
	return
}

// checkNameConstraints checks that c permits a child certificate to claim the
// given name, of type nameType. The argument parsedName contains the parsed
// form of name, suitable for passing to the match function. The total number
// of comparisons is tracked in the given count and should not exceed the given
// limit.
// SOURCE: https://cs.opensource.google/go/go/+/refs/tags/go1.17.5:src/crypto/x509/verify.go
func checkNameConstraints(
	nameType string,
	name string,
	parsedName interface{},
	match func(parsedName, constraint interface{}) (match bool, err error),
	permitted, excluded interface{}) error {

	excludedValue := reflect.ValueOf(excluded)

	// *count += excludedValue.Len()
	// if *count > maxConstraintComparisons {
	// 	return x509.CertificateInvalidError{c, x509.TooManyConstraints, ""}
	// }

	// TODO: fix the errors; return our own, because we don't have cert ...

	for i := 0; i < excludedValue.Len(); i++ {
		constraint := excludedValue.Index(i).Interface()
		match, err := match(parsedName, constraint)
		if err != nil {
			return CertificateInvalidError{
				Reason: x509.CANotAuthorizedForThisName,
				Detail: err.Error(),
			}
		}

		if match {
			return CertificateInvalidError{
				Reason: x509.CANotAuthorizedForThisName,
				Detail: fmt.Sprintf("%s %q is excluded by constraint %q", nameType, name, constraint),
			}
		}
	}

	permittedValue := reflect.ValueOf(permitted)

	// *count += permittedValue.Len()
	// if *count > maxConstraintComparisons {
	// 	return x509.CertificateInvalidError{c, x509.TooManyConstraints, ""}
	// }

	ok := true
	for i := 0; i < permittedValue.Len(); i++ {
		constraint := permittedValue.Index(i).Interface()
		var err error
		if ok, err = match(parsedName, constraint); err != nil {
			return CertificateInvalidError{
				Reason: x509.CANotAuthorizedForThisName,
				Detail: err.Error(),
			}
		}

		if ok {
			break
		}
	}

	if !ok {
		return CertificateInvalidError{
			Reason: x509.CANotAuthorizedForThisName,
			Detail: fmt.Sprintf("%s %q is not permitted by any constraint", nameType, name),
		}
	}

	return nil
}

// SOURCE: https://cs.opensource.google/go/go/+/refs/tags/go1.17.5:src/crypto/x509/verify.go
func matchDomainConstraint(domain, constraint string) (bool, error) {
	// The meaning of zero length constraints is not specified, but this
	// code follows NSS and accepts them as matching everything.
	if constraint == "" {
		return true, nil
	}

	domainLabels, ok := domainToReverseLabels(domain)
	if !ok {
		return false, fmt.Errorf("cannot parse domain %q", domain)
	}

	// RFC 5280 says that a leading period in a domain name means that at
	// least one label must be prepended, but only for URI and email
	// constraints, not DNS constraints. The code also supports that
	// behavior for DNS constraints.

	mustHaveSubdomains := false
	if constraint[0] == '.' {
		mustHaveSubdomains = true
		constraint = constraint[1:]
	}

	constraintLabels, ok := domainToReverseLabels(constraint)
	if !ok {
		return false, fmt.Errorf("cannot parse domain %q", constraint)
	}

	if len(domainLabels) < len(constraintLabels) ||
		(mustHaveSubdomains && len(domainLabels) == len(constraintLabels)) {
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
func matchEmailConstraint(mailbox rfc2821Mailbox, constraint string) (bool, error) {
	// If the constraint contains an @, then it specifies an exact mailbox name.
	if strings.Contains(constraint, "@") {
		constraintMailbox, ok := parseRFC2821Mailbox(constraint)
		if !ok {
			return false, fmt.Errorf("cannot parse constraint %q", constraint)
		}
		return mailbox.local == constraintMailbox.local && strings.EqualFold(mailbox.domain, constraintMailbox.domain), nil
	}

	// Otherwise the constraint is like a DNS constraint of the domain part
	// of the mailbox.
	return matchDomainConstraint(mailbox.domain, constraint)
}

// matchUserNameConstraint performs a string literal match against a constraint
func matchUserNameConstraint(userName, constraint string) (bool, error) {
	return userName == constraint, nil
}

// TODO: decrease code duplication: single policy engine again, with principals added, but not used in x509?
// Not sure how I'd like to model that in Go, though: use (embedded) structs? interfaces? An x509 name policy engine
// interface could expose the methods that are useful to x509; the SSH name policy engine interfaces could do the
// same for SSH ones. One interface for both (with no methods?); then two, so that not all name policy options
// can be executed on both types? The shared ones could then maybe use the one with no methods? But we need protect
// it from being applied to just any type, of course. Not sure if Go allows us to do something like that, though.
// Maybe some kind of dummy function helps there?

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
