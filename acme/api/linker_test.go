package api

import (
	"context"
	"fmt"
	"net/url"
	"testing"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/acme"
)

func TestLinker_GetLink(t *testing.T) {
	dns := "ca.smallstep.com"
	prefix := "acme"
	linker := NewLinker(dns, prefix)
	id := "1234"

	prov := newProv()
	provName := url.PathEscape(prov.GetName())
	baseURL := &url.URL{Scheme: "https", Host: "test.ca.smallstep.com"}
	ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
	ctx = context.WithValue(ctx, baseURLContextKey, baseURL)

	assert.Equals(t, linker.GetLink(ctx, NewNonceLinkType, true),
		fmt.Sprintf("%s/acme/%s/new-nonce", baseURL.String(), provName))
	assert.Equals(t, linker.GetLink(ctx, NewNonceLinkType, false), fmt.Sprintf("/%s/new-nonce", provName))

	// No provisioner
	ctxNoProv := context.WithValue(context.Background(), baseURLContextKey, baseURL)
	assert.Equals(t, linker.GetLink(ctxNoProv, NewNonceLinkType, true),
		fmt.Sprintf("%s/acme//new-nonce", baseURL.String()))
	assert.Equals(t, linker.GetLink(ctxNoProv, NewNonceLinkType, false), "//new-nonce")

	// No baseURL
	ctxNoBaseURL := context.WithValue(context.Background(), provisionerContextKey, prov)
	assert.Equals(t, linker.GetLink(ctxNoBaseURL, NewNonceLinkType, true),
		fmt.Sprintf("%s/acme/%s/new-nonce", "https://ca.smallstep.com", provName))
	assert.Equals(t, linker.GetLink(ctxNoBaseURL, NewNonceLinkType, false), fmt.Sprintf("/%s/new-nonce", provName))

	assert.Equals(t, linker.GetLink(ctx, OrderLinkType, true, id),
		fmt.Sprintf("%s/acme/%s/order/1234", baseURL.String(), provName))
	assert.Equals(t, linker.GetLink(ctx, OrderLinkType, false, id), fmt.Sprintf("/%s/order/1234", provName))
}

func TestLinker_GetLinkExplicit(t *testing.T) {
	dns := "ca.smallstep.com"
	baseURL := &url.URL{Scheme: "https", Host: "test.ca.smallstep.com"}
	prefix := "acme"
	linker := NewLinker(dns, prefix)
	id := "1234"

	prov := newProv()
	provID := url.PathEscape(prov.GetName())

	assert.Equals(t, linker.GetLinkExplicit(NewNonceLinkType, provID, true, nil), fmt.Sprintf("%s/acme/%s/new-nonce", "https://ca.smallstep.com", provID))
	assert.Equals(t, linker.GetLinkExplicit(NewNonceLinkType, provID, true, &url.URL{}), fmt.Sprintf("%s/acme/%s/new-nonce", "https://ca.smallstep.com", provID))
	assert.Equals(t, linker.GetLinkExplicit(NewNonceLinkType, provID, true, &url.URL{Scheme: "http"}), fmt.Sprintf("%s/acme/%s/new-nonce", "http://ca.smallstep.com", provID))
	assert.Equals(t, linker.GetLinkExplicit(NewNonceLinkType, provID, true, baseURL), fmt.Sprintf("%s/acme/%s/new-nonce", baseURL, provID))
	assert.Equals(t, linker.GetLinkExplicit(NewNonceLinkType, provID, false, baseURL), fmt.Sprintf("/%s/new-nonce", provID))

	assert.Equals(t, linker.GetLinkExplicit(NewAccountLinkType, provID, true, baseURL), fmt.Sprintf("%s/acme/%s/new-account", baseURL, provID))
	assert.Equals(t, linker.GetLinkExplicit(NewAccountLinkType, provID, false, baseURL), fmt.Sprintf("/%s/new-account", provID))

	assert.Equals(t, linker.GetLinkExplicit(AccountLinkType, provID, true, baseURL, id), fmt.Sprintf("%s/acme/%s/account/1234", baseURL, provID))
	assert.Equals(t, linker.GetLinkExplicit(AccountLinkType, provID, false, baseURL, id), fmt.Sprintf("/%s/account/1234", provID))

	assert.Equals(t, linker.GetLinkExplicit(NewOrderLinkType, provID, true, baseURL), fmt.Sprintf("%s/acme/%s/new-order", baseURL, provID))
	assert.Equals(t, linker.GetLinkExplicit(NewOrderLinkType, provID, false, baseURL), fmt.Sprintf("/%s/new-order", provID))

	assert.Equals(t, linker.GetLinkExplicit(OrderLinkType, provID, true, baseURL, id), fmt.Sprintf("%s/acme/%s/order/1234", baseURL, provID))
	assert.Equals(t, linker.GetLinkExplicit(OrderLinkType, provID, false, baseURL, id), fmt.Sprintf("/%s/order/1234", provID))

	assert.Equals(t, linker.GetLinkExplicit(OrdersByAccountLinkType, provID, true, baseURL, id), fmt.Sprintf("%s/acme/%s/account/1234/orders", baseURL, provID))
	assert.Equals(t, linker.GetLinkExplicit(OrdersByAccountLinkType, provID, false, baseURL, id), fmt.Sprintf("/%s/account/1234/orders", provID))

	assert.Equals(t, linker.GetLinkExplicit(FinalizeLinkType, provID, true, baseURL, id), fmt.Sprintf("%s/acme/%s/order/1234/finalize", baseURL, provID))
	assert.Equals(t, linker.GetLinkExplicit(FinalizeLinkType, provID, false, baseURL, id), fmt.Sprintf("/%s/order/1234/finalize", provID))

	assert.Equals(t, linker.GetLinkExplicit(NewAuthzLinkType, provID, true, baseURL), fmt.Sprintf("%s/acme/%s/new-authz", baseURL, provID))
	assert.Equals(t, linker.GetLinkExplicit(NewAuthzLinkType, provID, false, baseURL), fmt.Sprintf("/%s/new-authz", provID))

	assert.Equals(t, linker.GetLinkExplicit(AuthzLinkType, provID, true, baseURL, id), fmt.Sprintf("%s/acme/%s/authz/1234", baseURL, provID))
	assert.Equals(t, linker.GetLinkExplicit(AuthzLinkType, provID, false, baseURL, id), fmt.Sprintf("/%s/authz/1234", provID))

	assert.Equals(t, linker.GetLinkExplicit(DirectoryLinkType, provID, true, baseURL), fmt.Sprintf("%s/acme/%s/directory", baseURL, provID))
	assert.Equals(t, linker.GetLinkExplicit(DirectoryLinkType, provID, false, baseURL), fmt.Sprintf("/%s/directory", provID))

	assert.Equals(t, linker.GetLinkExplicit(RevokeCertLinkType, provID, true, baseURL, id), fmt.Sprintf("%s/acme/%s/revoke-cert", baseURL, provID))
	assert.Equals(t, linker.GetLinkExplicit(RevokeCertLinkType, provID, false, baseURL), fmt.Sprintf("/%s/revoke-cert", provID))

	assert.Equals(t, linker.GetLinkExplicit(KeyChangeLinkType, provID, true, baseURL), fmt.Sprintf("%s/acme/%s/key-change", baseURL, provID))
	assert.Equals(t, linker.GetLinkExplicit(KeyChangeLinkType, provID, false, baseURL), fmt.Sprintf("/%s/key-change", provID))

	assert.Equals(t, linker.GetLinkExplicit(ChallengeLinkType, provID, true, baseURL, id, id), fmt.Sprintf("%s/acme/%s/challenge/%s/%s", baseURL, provID, id, id))
	assert.Equals(t, linker.GetLinkExplicit(ChallengeLinkType, provID, false, baseURL, id, id), fmt.Sprintf("/%s/challenge/%s/%s", provID, id, id))

	assert.Equals(t, linker.GetLinkExplicit(CertificateLinkType, provID, true, baseURL, id), fmt.Sprintf("%s/acme/%s/certificate/1234", baseURL, provID))
	assert.Equals(t, linker.GetLinkExplicit(CertificateLinkType, provID, false, baseURL, id), fmt.Sprintf("/%s/certificate/1234", provID))
}

func TestLinker_LinkOrder(t *testing.T) {
	baseURL := &url.URL{Scheme: "https", Host: "test.ca.smallstep.com"}
	prov := newProv()
	provName := url.PathEscape(prov.GetName())
	ctx := context.WithValue(context.Background(), baseURLContextKey, baseURL)
	ctx = context.WithValue(ctx, provisionerContextKey, prov)

	oid := "orderID"
	certID := "certID"
	linkerPrefix := "acme"
	l := NewLinker("dns", linkerPrefix)
	type test struct {
		o        *acme.Order
		validate func(o *acme.Order)
	}
	var tests = map[string]test{
		"no-authz-and-no-cert": {
			o: &acme.Order{
				ID: oid,
			},
			validate: func(o *acme.Order) {
				assert.Equals(t, o.FinalizeURL, fmt.Sprintf("%s/%s/%s/order/%s/finalize", baseURL, linkerPrefix, provName, oid))
				assert.Equals(t, o.AuthorizationURLs, []string{})
				assert.Equals(t, o.CertificateURL, "")
			},
		},
		"one-authz-and-cert": {
			o: &acme.Order{
				ID:               oid,
				CertificateID:    certID,
				AuthorizationIDs: []string{"foo"},
			},
			validate: func(o *acme.Order) {
				assert.Equals(t, o.FinalizeURL, fmt.Sprintf("%s/%s/%s/order/%s/finalize", baseURL, linkerPrefix, provName, oid))
				assert.Equals(t, o.AuthorizationURLs, []string{
					fmt.Sprintf("%s/%s/%s/authz/%s", baseURL, linkerPrefix, provName, "foo"),
				})
				assert.Equals(t, o.CertificateURL, fmt.Sprintf("%s/%s/%s/certificate/%s", baseURL, linkerPrefix, provName, certID))
			},
		},
		"many-authz": {
			o: &acme.Order{
				ID:               oid,
				CertificateID:    certID,
				AuthorizationIDs: []string{"foo", "bar", "zap"},
			},
			validate: func(o *acme.Order) {
				assert.Equals(t, o.FinalizeURL, fmt.Sprintf("%s/%s/%s/order/%s/finalize", baseURL, linkerPrefix, provName, oid))
				assert.Equals(t, o.AuthorizationURLs, []string{
					fmt.Sprintf("%s/%s/%s/authz/%s", baseURL, linkerPrefix, provName, "foo"),
					fmt.Sprintf("%s/%s/%s/authz/%s", baseURL, linkerPrefix, provName, "bar"),
					fmt.Sprintf("%s/%s/%s/authz/%s", baseURL, linkerPrefix, provName, "zap"),
				})
				assert.Equals(t, o.CertificateURL, fmt.Sprintf("%s/%s/%s/certificate/%s", baseURL, linkerPrefix, provName, certID))
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			l.LinkOrder(ctx, tc.o)
			tc.validate(tc.o)
		})
	}
}

func TestLinker_LinkAccount(t *testing.T) {
	baseURL := &url.URL{Scheme: "https", Host: "test.ca.smallstep.com"}
	prov := newProv()
	provName := url.PathEscape(prov.GetName())
	ctx := context.WithValue(context.Background(), baseURLContextKey, baseURL)
	ctx = context.WithValue(ctx, provisionerContextKey, prov)

	accID := "accountID"
	linkerPrefix := "acme"
	l := NewLinker("dns", linkerPrefix)
	type test struct {
		a        *acme.Account
		validate func(o *acme.Account)
	}
	var tests = map[string]test{
		"ok": {
			a: &acme.Account{
				ID: accID,
			},
			validate: func(a *acme.Account) {
				assert.Equals(t, a.OrdersURL, fmt.Sprintf("%s/%s/%s/account/%s/orders", baseURL, linkerPrefix, provName, accID))
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			l.LinkAccount(ctx, tc.a)
			tc.validate(tc.a)
		})
	}
}

func TestLinker_LinkChallenge(t *testing.T) {
	baseURL := &url.URL{Scheme: "https", Host: "test.ca.smallstep.com"}
	prov := newProv()
	provName := url.PathEscape(prov.GetName())
	ctx := context.WithValue(context.Background(), baseURLContextKey, baseURL)
	ctx = context.WithValue(ctx, provisionerContextKey, prov)

	chID := "chID"
	azID := "azID"
	linkerPrefix := "acme"
	l := NewLinker("dns", linkerPrefix)
	type test struct {
		ch       *acme.Challenge
		validate func(o *acme.Challenge)
	}
	var tests = map[string]test{
		"ok": {
			ch: &acme.Challenge{
				ID: chID,
			},
			validate: func(ch *acme.Challenge) {
				assert.Equals(t, ch.URL, fmt.Sprintf("%s/%s/%s/challenge/%s/%s", baseURL, linkerPrefix, provName, azID, ch.ID))
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			l.LinkChallenge(ctx, tc.ch, azID)
			tc.validate(tc.ch)
		})
	}
}

func TestLinker_LinkAuthorization(t *testing.T) {
	baseURL := &url.URL{Scheme: "https", Host: "test.ca.smallstep.com"}
	prov := newProv()
	provName := url.PathEscape(prov.GetName())
	ctx := context.WithValue(context.Background(), baseURLContextKey, baseURL)
	ctx = context.WithValue(ctx, provisionerContextKey, prov)

	chID0 := "chID-0"
	chID1 := "chID-1"
	chID2 := "chID-2"
	azID := "azID"
	linkerPrefix := "acme"
	l := NewLinker("dns", linkerPrefix)
	type test struct {
		az       *acme.Authorization
		validate func(o *acme.Authorization)
	}
	var tests = map[string]test{
		"ok": {
			az: &acme.Authorization{
				ID: azID,
				Challenges: []*acme.Challenge{
					{ID: chID0},
					{ID: chID1},
					{ID: chID2},
				},
			},
			validate: func(az *acme.Authorization) {
				assert.Equals(t, az.Challenges[0].URL, fmt.Sprintf("%s/%s/%s/challenge/%s/%s", baseURL, linkerPrefix, provName, az.ID, chID0))
				assert.Equals(t, az.Challenges[1].URL, fmt.Sprintf("%s/%s/%s/challenge/%s/%s", baseURL, linkerPrefix, provName, az.ID, chID1))
				assert.Equals(t, az.Challenges[2].URL, fmt.Sprintf("%s/%s/%s/challenge/%s/%s", baseURL, linkerPrefix, provName, az.ID, chID2))
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			l.LinkAuthorization(ctx, tc.az)
			tc.validate(tc.az)
		})
	}
}

func TestLinker_LinkOrdersByAccountID(t *testing.T) {
	baseURL := &url.URL{Scheme: "https", Host: "test.ca.smallstep.com"}
	prov := newProv()
	provName := url.PathEscape(prov.GetName())
	ctx := context.WithValue(context.Background(), baseURLContextKey, baseURL)
	ctx = context.WithValue(ctx, provisionerContextKey, prov)

	linkerPrefix := "acme"
	l := NewLinker("dns", linkerPrefix)
	type test struct {
		oids []string
	}
	var tests = map[string]test{
		"ok": {
			oids: []string{"foo", "bar", "baz"},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			l.LinkOrdersByAccountID(ctx, tc.oids)
			assert.Equals(t, tc.oids, []string{
				fmt.Sprintf("%s/%s/%s/order/%s", baseURL, linkerPrefix, provName, "foo"),
				fmt.Sprintf("%s/%s/%s/order/%s", baseURL, linkerPrefix, provName, "bar"),
				fmt.Sprintf("%s/%s/%s/order/%s", baseURL, linkerPrefix, provName, "baz"),
			})
		})
	}
}
