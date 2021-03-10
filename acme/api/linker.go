package api

import (
	"context"
	"fmt"
	"net/url"

	"github.com/smallstep/certificates/acme"
)

// NewLinker returns a new Directory type.
func NewLinker(dns, prefix string) Linker {
	return &linker{prefix: prefix, dns: dns}
}

// Linker interface for generating links for ACME resources.
type Linker interface {
	GetLink(ctx context.Context, typ LinkType, abs bool, inputs ...string) string
	GetLinkExplicit(typ LinkType, provName string, abs bool, baseURL *url.URL, inputs ...string) string

	LinkOrder(ctx context.Context, o *acme.Order)
	LinkAccount(ctx context.Context, o *acme.Account)
	LinkChallenge(ctx context.Context, o *acme.Challenge)
	LinkAuthorization(ctx context.Context, o *acme.Authorization)
	LinkOrdersByAccountID(ctx context.Context, orders []string)
}

// linker generates ACME links.
type linker struct {
	prefix string
	dns    string
}

// GetLink is a helper for GetLinkExplicit
func (l *linker) GetLink(ctx context.Context, typ LinkType, abs bool, inputs ...string) string {
	var provName string
	if p, err := provisionerFromContext(ctx); err == nil && p != nil {
		provName = p.GetName()
	}
	return l.GetLinkExplicit(typ, provName, abs, baseURLFromContext(ctx), inputs...)
}

// GetLinkExplicit returns an absolute or partial path to the given resource and a base
// URL dynamically obtained from the request for which the link is being
// calculated.
func (l *linker) GetLinkExplicit(typ LinkType, provisionerName string, abs bool, baseURL *url.URL, inputs ...string) string {
	var link string
	switch typ {
	case NewNonceLinkType, NewAccountLinkType, NewOrderLinkType, NewAuthzLinkType, DirectoryLinkType, KeyChangeLinkType, RevokeCertLinkType:
		link = fmt.Sprintf("/%s/%s", provisionerName, typ)
	case AccountLinkType, OrderLinkType, AuthzLinkType, CertificateLinkType:
		link = fmt.Sprintf("/%s/%s/%s", provisionerName, typ, inputs[0])
	case ChallengeLinkType:
		link = fmt.Sprintf("/%s/%s/%s/%s", provisionerName, typ, inputs[0], inputs[1])
	case OrdersByAccountLinkType:
		link = fmt.Sprintf("/%s/%s/%s/orders", provisionerName, AccountLinkType, inputs[0])
	case FinalizeLinkType:
		link = fmt.Sprintf("/%s/%s/%s/finalize", provisionerName, OrderLinkType, inputs[0])
	}

	if abs {
		// Copy the baseURL value from the pointer. https://github.com/golang/go/issues/38351
		u := url.URL{}
		if baseURL != nil {
			u = *baseURL
		}

		// If no Scheme is set, then default to https.
		if u.Scheme == "" {
			u.Scheme = "https"
		}

		// If no Host is set, then use the default (first DNS attr in the ca.json).
		if u.Host == "" {
			u.Host = l.dns
		}

		u.Path = l.prefix + link
		return u.String()
	}
	return link
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
		o.AuthorizationURLs[i] = l.GetLink(ctx, AuthzLinkType, true, azID)
	}
	o.FinalizeURL = l.GetLink(ctx, FinalizeLinkType, true, o.ID)
	if o.CertificateID != "" {
		o.CertificateURL = l.GetLink(ctx, CertificateLinkType, true, o.CertificateID)
	}
}

// LinkAccount sets the ACME links required by an ACME account.
func (l *linker) LinkAccount(ctx context.Context, acc *acme.Account) {
	acc.Orders = l.GetLink(ctx, OrdersByAccountLinkType, true, acc.ID)
}

// LinkChallenge sets the ACME links required by an ACME challenge.
func (l *linker) LinkChallenge(ctx context.Context, ch *acme.Challenge) {
	ch.URL = l.GetLink(ctx, ChallengeLinkType, true, ch.AuthzID, ch.ID)
}

// LinkAuthorization sets the ACME links required by an ACME authorization.
func (l *linker) LinkAuthorization(ctx context.Context, az *acme.Authorization) {
	for _, ch := range az.Challenges {
		l.LinkChallenge(ctx, ch)
	}
}

// LinkOrdersByAccountID converts each order ID to an ACME link.
func (l *linker) LinkOrdersByAccountID(ctx context.Context, orders []string) {
	for i, id := range orders {
		orders[i] = l.GetLink(ctx, OrderLinkType, true, id)
	}
}

// MockLinker implements the Linker interface. Only used for testing.
type MockLinker struct {
	MockGetLink         func(ctx context.Context, typ LinkType, abs bool, inputs ...string) string
	MockGetLinkExplicit func(typ LinkType, provName string, abs bool, baseURL *url.URL, inputs ...string) string

	MockLinkOrder             func(ctx context.Context, o *acme.Order)
	MockLinkAccount           func(ctx context.Context, o *acme.Account)
	MockLinkChallenge         func(ctx context.Context, o *acme.Challenge)
	MockLinkAuthorization     func(ctx context.Context, o *acme.Authorization)
	MockLinkOrdersByAccountID func(ctx context.Context, orders []string)

	MockError error
	MockRet1  interface{}
}

// GetLink mock.
func (m *MockLinker) GetLink(ctx context.Context, typ LinkType, abs bool, inputs ...string) string {
	if m.MockGetLink != nil {
		return m.MockGetLink(ctx, typ, abs, inputs...)
	}

	return m.MockRet1.(string)
}

// GetLinkExplicit mock.
func (m *MockLinker) GetLinkExplicit(typ LinkType, provName string, abs bool, baseURL *url.URL, inputs ...string) string {
	if m.MockGetLinkExplicit != nil {
		return m.MockGetLinkExplicit(typ, provName, abs, baseURL, inputs...)
	}

	return m.MockRet1.(string)
}

// LinkOrder mock.
func (m *MockLinker) LinkOrder(ctx context.Context, o *acme.Order) {
	if m.MockLinkOrder != nil {
		m.MockLinkOrder(ctx, o)
		return
	}
	return
}

// LinkAccount mock.
func (m *MockLinker) LinkAccount(ctx context.Context, o *acme.Account) {
	if m.MockLinkAccount != nil {
		m.MockLinkAccount(ctx, o)
		return
	}
	return
}

// LinkChallenge mock.
func (m *MockLinker) LinkChallenge(ctx context.Context, o *acme.Challenge) {
	if m.MockLinkChallenge != nil {
		m.MockLinkChallenge(ctx, o)
		return
	}
	return
}

// LinkAuthorization mock.
func (m *MockLinker) LinkAuthorization(ctx context.Context, o *acme.Authorization) {
	if m.MockLinkAuthorization != nil {
		m.MockLinkAuthorization(ctx, o)
		return
	}
	return
}

// LinkOrderAccountsByID mock.
func (m *MockLinker) LinkOrderAccountsByID(ctx context.Context, orders []string) {
	if m.MockLinkOrdersByAccountID != nil {
		m.MockLinkOrdersByAccountID(ctx, orders)
		return
	}
	return
}
