// Copyright (c) 2009 The Go Authors. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package constraints

import (
	"bytes"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"strings"
)

func checkNameConstraints(nameType, name string, parsedName, permitted, excluded any, match func(name, constraint any) (bool, error)) error {
	excludedValue := reflect.ValueOf(excluded)
	for i := 0; i < excludedValue.Len(); i++ {
		constraint := excludedValue.Index(i).Interface()
		match, err := match(parsedName, constraint)
		if err != nil {
			return ConstraintError{
				Type:   nameType,
				Name:   name,
				Detail: err.Error(),
			}
		}

		if match {
			return ConstraintError{
				Type:   nameType,
				Name:   name,
				Detail: fmt.Sprintf("%s %q is excluded by constraint %q", nameType, name, constraint),
			}
		}
	}

	var (
		err error
		ok  = true
	)

	permittedValue := reflect.ValueOf(permitted)
	for i := 0; i < permittedValue.Len(); i++ {
		constraint := permittedValue.Index(i).Interface()
		if ok, err = match(parsedName, constraint); err != nil {
			return ConstraintError{
				Type:   nameType,
				Name:   name,
				Detail: err.Error(),
			}
		}
		if ok {
			break
		}
	}
	if !ok {
		return ConstraintError{
			Type:   nameType,
			Name:   name,
			Detail: fmt.Sprintf("%s %q is not permitted by any constraint", nameType, name),
		}
	}

	return nil
}

func matchDomainConstraint(domain, constraint string) (bool, error) {
	// The meaning of zero length constraints is not specified, but this
	// code follows NSS and accepts them as matching everything.
	if constraint == "" {
		return true, nil
	}

	domainLabels, ok := domainToReverseLabels(domain)
	if !ok {
		return false, fmt.Errorf("internal error: cannot parse domain %q", domain)
	}

	// RFC 5280 says that a leading period in a domain name means that at least
	// one label must be prepended, but only for URI and email constraints, not
	// DNS constraints. The code also supports that behavior for DNS
	// constraints.

	mustHaveSubdomains := false
	if constraint[0] == '.' {
		mustHaveSubdomains = true
		constraint = constraint[1:]
	}

	constraintLabels, ok := domainToReverseLabels(constraint)
	if !ok {
		return false, fmt.Errorf("internal error: cannot parse domain %q", constraint)
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

func normalizeIP(ip net.IP) net.IP {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4
	}
	return ip
}

func matchIPConstraint(ip net.IP, constraint *net.IPNet) (bool, error) {
	ip = normalizeIP(ip)
	constraintIP := normalizeIP(constraint.IP)
	if len(ip) != len(constraintIP) {
		return false, nil
	}

	for i := range ip {
		if mask := constraint.Mask[i]; ip[i]&mask != constraintIP[i]&mask {
			return false, nil
		}
	}

	return true, nil
}

func matchEmailConstraint(mailbox rfc2821Mailbox, constraint string) (bool, error) {
	// If the constraint contains an @, then it specifies an exact mailbox
	// name.
	if strings.Contains(constraint, "@") {
		constraintMailbox, ok := parseRFC2821Mailbox(constraint)
		if !ok {
			return false, fmt.Errorf("internal error: cannot parse constraint %q", constraint)
		}
		return mailbox.local == constraintMailbox.local && strings.EqualFold(mailbox.domain, constraintMailbox.domain), nil
	}

	// Otherwise the constraint is like a DNS constraint of the domain part
	// of the mailbox.
	return matchDomainConstraint(mailbox.domain, constraint)
}

func matchURIConstraint(uri *url.URL, constraint string) (bool, error) {
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

	if strings.Contains(host, ":") && !strings.HasSuffix(host, "]") {
		var err error
		host, _, err = net.SplitHostPort(uri.Host)
		if err != nil {
			return false, err
		}
	}

	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") ||
		net.ParseIP(host) != nil {
		return false, fmt.Errorf("URI with IP (%q) cannot be matched against constraints", uri.String())
	}

	return matchDomainConstraint(host, constraint)
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
