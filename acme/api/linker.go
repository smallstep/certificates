package api

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/smallstep/certificates/acme"
)

// NewLinker returns a new Directory type.
func NewLinker(dns, prefix string) Linker {
	_, _, err := net.SplitHostPort(dns)
	if err != nil && strings.Contains(err.Error(), "too many colons in address") {
		// this is most probably an IPv6 without brackets, e.g. ::1, 2001:0db8:85a3:0000:0000:8a2e:0370:7334
		// in case a port was appended to this wrong format, we try to extract the port, then check if it's
		// still a valid IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334:8443 (8443 is the port). If none of
		// these cases, then the input dns is not changed.
		lastIndex := strings.LastIndex(dns, ":")
		hostPart, portPart := dns[:lastIndex], dns[lastIndex+1:]
		if ip := net.ParseIP(hostPart); ip != nil {
			dns = "[" + hostPart + "]:" + portPart
		} else if ip := net.ParseIP(dns); ip != nil {
			dns = "[" + dns + "]"
		}
	}
	return &linker{prefix: prefix, dns: dns}
}

// Linker interface for generating links for ACME resources.
type Linker interface {
	GetLink(ctx context.Context, typ LinkType, inputs ...string) string
	GetUnescapedPathSuffix(typ LinkType, provName string, inputs ...string) string

	LinkOrder(ctx context.Context, o *acme.Order)
	LinkAccount(ctx context.Context, o *acme.Account)
	LinkChallenge(ctx context.Context, o *acme.Challenge, azID string)
	LinkAuthorization(ctx context.Context, o *acme.Authorization)
	LinkOrdersByAccountID(ctx context.Context, orders []string)
}

// linker generates ACME links.
type linker struct {
	prefix string
	dns    string
}

func (l *linker) GetUnescapedPathSuffix(typ LinkType, provisionerName string, inputs ...string) string {
	switch typ {
	case NewNonceLinkType, NewAccountLinkType, NewOrderLinkType, NewAuthzLinkType, DirectoryLinkType, KeyChangeLinkType, RevokeCertLinkType:
		return fmt.Sprintf("/%s/%s", provisionerName, typ)
	case AccountLinkType, OrderLinkType, AuthzLinkType, CertificateLinkType:
		return fmt.Sprintf("/%s/%s/%s", provisionerName, typ, inputs[0])
	case ChallengeLinkType:
		return fmt.Sprintf("/%s/%s/%s/%s", provisionerName, typ, inputs[0], inputs[1])
	case OrdersByAccountLinkType:
		return fmt.Sprintf("/%s/%s/%s/orders", provisionerName, AccountLinkType, inputs[0])
	case FinalizeLinkType:
		return fmt.Sprintf("/%s/%s/%s/finalize", provisionerName, OrderLinkType, inputs[0])
	default:
		return ""
	}
}

// GetLink is a helper for GetLinkExplicit
func (l *linker) GetLink(ctx context.Context, typ LinkType, inputs ...string) string {
	var (
		provName string
		baseURL  = baseURLFromContext(ctx)
		u        = url.URL{}
	)
	if p, err := provisionerFromContext(ctx); err == nil && p != nil {
		provName = p.GetName()
	}
	// Copy the baseURL value from the pointer. https://github.com/golang/go/issues/38351
	if baseURL != nil {
		u = *baseURL
	}

	u.Path = l.GetUnescapedPathSuffix(typ, provName, inputs...)

	// If no Scheme is set, then default to https.
	if u.Scheme == "" {
		u.Scheme = "https"
	}

	// If no Host is set, then use the default (first DNS attr in the ca.json).
	if u.Host == "" {
		u.Host = l.dns
	}

	u.Path = l.prefix + u.Path
	return u.String()
}

// LinkType captures the link type.
type LinkType int

const (
	// NewNonceLinkType new-nonce
	NewNonceLinkType LinkType = iota
	// NewAccountLinkType new-account
	NewAccountLinkType
	// AccountLinkType account
	AccountLinkType
	// OrderLinkType order
	OrderLinkType
	// NewOrderLinkType new-order
	NewOrderLinkType
	// OrdersByAccountLinkType list of orders owned by account
	OrdersByAccountLinkType
	// FinalizeLinkType finalize order
	FinalizeLinkType
	// NewAuthzLinkType authz
	NewAuthzLinkType
	// AuthzLinkType new-authz
	AuthzLinkType
	// ChallengeLinkType challenge
	ChallengeLinkType
	// CertificateLinkType certificate
	CertificateLinkType
	// DirectoryLinkType directory
	DirectoryLinkType
	// RevokeCertLinkType revoke certificate
	RevokeCertLinkType
	// KeyChangeLinkType key rollover
	KeyChangeLinkType
)

func (l LinkType) String() string {
	switch l {
	case NewNonceLinkType:
		return "new-nonce"
	case NewAccountLinkType:
		return "new-account"
	case AccountLinkType:
		return "account"
	case NewOrderLinkType:
		return "new-order"
	case OrderLinkType:
		return "order"
	case NewAuthzLinkType:
		return "new-authz"
	case AuthzLinkType:
		return "authz"
	case ChallengeLinkType:
		return "challenge"
	case CertificateLinkType:
		return "certificate"
	case DirectoryLinkType:
		return "directory"
	case RevokeCertLinkType:
		return "revoke-cert"
	case KeyChangeLinkType:
		return "key-change"
	default:
		return fmt.Sprintf("unexpected LinkType '%d'", int(l))
	}
}

// LinkOrder sets the ACME links required by an ACME order.
func (l *linker) LinkOrder(ctx context.Context, o *acme.Order) {
	o.AuthorizationURLs = make([]string, len(o.AuthorizationIDs))
	for i, azID := range o.AuthorizationIDs {
		o.AuthorizationURLs[i] = l.GetLink(ctx, AuthzLinkType, azID)
	}
	o.FinalizeURL = l.GetLink(ctx, FinalizeLinkType, o.ID)
	if o.CertificateID != "" {
		o.CertificateURL = l.GetLink(ctx, CertificateLinkType, o.CertificateID)
	}
}

// LinkAccount sets the ACME links required by an ACME account.
func (l *linker) LinkAccount(ctx context.Context, acc *acme.Account) {
	acc.OrdersURL = l.GetLink(ctx, OrdersByAccountLinkType, acc.ID)
}

// LinkChallenge sets the ACME links required by an ACME challenge.
func (l *linker) LinkChallenge(ctx context.Context, ch *acme.Challenge, azID string) {
	ch.URL = l.GetLink(ctx, ChallengeLinkType, azID, ch.ID)
}

// LinkAuthorization sets the ACME links required by an ACME authorization.
func (l *linker) LinkAuthorization(ctx context.Context, az *acme.Authorization) {
	for _, ch := range az.Challenges {
		l.LinkChallenge(ctx, ch, az.ID)
	}
}

// LinkOrdersByAccountID converts each order ID to an ACME link.
func (l *linker) LinkOrdersByAccountID(ctx context.Context, orders []string) {
	for i, id := range orders {
		orders[i] = l.GetLink(ctx, OrderLinkType, id)
	}
}
