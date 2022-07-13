package acme

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi"
	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/provisioner"
)

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

func GetUnescapedPathSuffix(typ LinkType, provisionerName string, inputs ...string) string {
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
	Middleware(http.Handler) http.Handler
	LinkOrder(ctx context.Context, o *Order)
	LinkAccount(ctx context.Context, o *Account)
	LinkChallenge(ctx context.Context, o *Challenge, azID string)
	LinkAuthorization(ctx context.Context, o *Authorization)
	LinkOrdersByAccountID(ctx context.Context, orders []string)
}

type linkerKey struct{}

// NewLinkerContext adds the given linker to the context.
func NewLinkerContext(ctx context.Context, v Linker) context.Context {
	return context.WithValue(ctx, linkerKey{}, v)
}

// LinkerFromContext returns the current linker from the given context.
func LinkerFromContext(ctx context.Context) (v Linker, ok bool) {
	v, ok = ctx.Value(linkerKey{}).(Linker)
	return
}

// MustLinkerFromContext returns the current linker from the given context. It
// will panic if it's not in the context.
func MustLinkerFromContext(ctx context.Context) Linker {
	if v, ok := LinkerFromContext(ctx); !ok {
		panic("acme linker is not the context")
	} else {
		return v
	}
}

type baseURLKey struct{}

func newBaseURLContext(ctx context.Context, r *http.Request) context.Context {
	var u *url.URL
	if r.Host != "" {
		u = &url.URL{Scheme: "https", Host: r.Host}
	}
	return context.WithValue(ctx, baseURLKey{}, u)
}

func baseURLFromContext(ctx context.Context) *url.URL {
	if u, ok := ctx.Value(baseURLKey{}).(*url.URL); ok {
		return u
	}
	return nil
}

// linker generates ACME links.
type linker struct {
	prefix string
	dns    string
}

// Middleware gets the provisioner and current url from the request and sets
// them in the context so we can use the linker to create ACME links.
func (l *linker) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add base url to the context.
		ctx := newBaseURLContext(r.Context(), r)

		// Add provisioner to the context.
		nameEscaped := chi.URLParam(r, "provisionerID")
		name, err := url.PathUnescape(nameEscaped)
		if err != nil {
			render.Error(w, WrapErrorISE(err, "error url unescaping provisioner name '%s'", nameEscaped))
			return
		}

		p, err := authority.MustFromContext(ctx).LoadProvisionerByName(name)
		if err != nil {
			render.Error(w, err)
			return
		}

		acmeProv, ok := p.(*provisioner.ACME)
		if !ok {
			render.Error(w, NewError(ErrorAccountDoesNotExistType, "provisioner must be of type ACME"))
			return
		}

		ctx = NewProvisionerContext(ctx, Provisioner(acmeProv))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetLink is a helper for GetLinkExplicit.
func (l *linker) GetLink(ctx context.Context, typ LinkType, inputs ...string) string {
	var name string
	if p, ok := ProvisionerFromContext(ctx); ok {
		name = p.GetName()
	}

	var u url.URL
	if baseURL := baseURLFromContext(ctx); baseURL != nil {
		u = *baseURL
	}
	if u.Scheme == "" {
		u.Scheme = "https"
	}
	if u.Host == "" {
		u.Host = l.dns
	}

	u.Path = l.prefix + GetUnescapedPathSuffix(typ, name, inputs...)
	return u.String()
}

// LinkOrder sets the ACME links required by an ACME order.
func (l *linker) LinkOrder(ctx context.Context, o *Order) {
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
func (l *linker) LinkAccount(ctx context.Context, acc *Account) {
	acc.OrdersURL = l.GetLink(ctx, OrdersByAccountLinkType, acc.ID)
}

// LinkChallenge sets the ACME links required by an ACME challenge.
func (l *linker) LinkChallenge(ctx context.Context, ch *Challenge, azID string) {
	ch.URL = l.GetLink(ctx, ChallengeLinkType, azID, ch.ID)
}

// LinkAuthorization sets the ACME links required by an ACME authorization.
func (l *linker) LinkAuthorization(ctx context.Context, az *Authorization) {
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
