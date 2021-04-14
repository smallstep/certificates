package api

import (
	"context"
	"fmt"
	"net/url"
	"testing"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/acme"
)

func TestLinker_GetUnescapedPathSuffix(t *testing.T) {
	dns := "ca.smallstep.com"
	prefix := "acme"
	linker := NewLinker(dns, prefix)

	getPath := linker.GetUnescapedPathSuffix

	assert.Equals(t, getPath(NewNonceLinkType, "{provisionerID}"), "/{provisionerID}/new-nonce")
	assert.Equals(t, getPath(DirectoryLinkType, "{provisionerID}"), "/{provisionerID}/directory")
	assert.Equals(t, getPath(NewAccountLinkType, "{provisionerID}"), "/{provisionerID}/new-account")
	assert.Equals(t, getPath(AccountLinkType, "{provisionerID}", "{accID}"), "/{provisionerID}/account/{accID}")
	assert.Equals(t, getPath(KeyChangeLinkType, "{provisionerID}"), "/{provisionerID}/key-change")
	assert.Equals(t, getPath(NewOrderLinkType, "{provisionerID}"), "/{provisionerID}/new-order")
	assert.Equals(t, getPath(OrderLinkType, "{provisionerID}", "{ordID}"), "/{provisionerID}/order/{ordID}")
	assert.Equals(t, getPath(OrdersByAccountLinkType, "{provisionerID}", "{accID}"), "/{provisionerID}/account/{accID}/orders")
	assert.Equals(t, getPath(FinalizeLinkType, "{provisionerID}", "{ordID}"), "/{provisionerID}/order/{ordID}/finalize")
	assert.Equals(t, getPath(AuthzLinkType, "{provisionerID}", "{authzID}"), "/{provisionerID}/authz/{authzID}")
	assert.Equals(t, getPath(ChallengeLinkType, "{provisionerID}", "{authzID}", "{chID}"), "/{provisionerID}/challenge/{authzID}/{chID}")
	assert.Equals(t, getPath(CertificateLinkType, "{provisionerID}", "{certID}"), "/{provisionerID}/certificate/{certID}")
}

func TestLinker_GetLink(t *testing.T) {
	dns := "ca.smallstep.com"
	prefix := "acme"
	linker := NewLinker(dns, prefix)
	id := "1234"

	prov := newProv()
	escProvName := url.PathEscape(prov.GetName())
	baseURL := &url.URL{Scheme: "https", Host: "test.ca.smallstep.com"}
	ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
	ctx = context.WithValue(ctx, baseURLContextKey, baseURL)

	// No provisioner and no BaseURL from request
	assert.Equals(t, linker.GetLink(context.Background(), NewNonceLinkType), fmt.Sprintf("%s/acme/%s/new-nonce", "https://ca.smallstep.com", ""))
	// Provisioner: yes, BaseURL: no
	assert.Equals(t, linker.GetLink(context.WithValue(context.Background(), provisionerContextKey, prov), NewNonceLinkType), fmt.Sprintf("%s/acme/%s/new-nonce", "https://ca.smallstep.com", escProvName))

	// Provisioner: no, BaseURL: yes
	assert.Equals(t, linker.GetLink(context.WithValue(context.Background(), baseURLContextKey, baseURL), NewNonceLinkType), fmt.Sprintf("%s/acme/%s/new-nonce", "https://test.ca.smallstep.com", ""))

	assert.Equals(t, linker.GetLink(ctx, NewNonceLinkType), fmt.Sprintf("%s/acme/%s/new-nonce", baseURL, escProvName))
	assert.Equals(t, linker.GetLink(ctx, NewNonceLinkType), fmt.Sprintf("%s/acme/%s/new-nonce", baseURL, escProvName))

	assert.Equals(t, linker.GetLink(ctx, NewAccountLinkType), fmt.Sprintf("%s/acme/%s/new-account", baseURL, escProvName))

	assert.Equals(t, linker.GetLink(ctx, AccountLinkType, id), fmt.Sprintf("%s/acme/%s/account/1234", baseURL, escProvName))

	assert.Equals(t, linker.GetLink(ctx, NewOrderLinkType), fmt.Sprintf("%s/acme/%s/new-order", baseURL, escProvName))

	assert.Equals(t, linker.GetLink(ctx, OrderLinkType, id), fmt.Sprintf("%s/acme/%s/order/1234", baseURL, escProvName))

	assert.Equals(t, linker.GetLink(ctx, OrdersByAccountLinkType, id), fmt.Sprintf("%s/acme/%s/account/1234/orders", baseURL, escProvName))

	assert.Equals(t, linker.GetLink(ctx, FinalizeLinkType, id), fmt.Sprintf("%s/acme/%s/order/1234/finalize", baseURL, escProvName))

	assert.Equals(t, linker.GetLink(ctx, NewAuthzLinkType), fmt.Sprintf("%s/acme/%s/new-authz", baseURL, escProvName))

	assert.Equals(t, linker.GetLink(ctx, AuthzLinkType, id), fmt.Sprintf("%s/acme/%s/authz/1234", baseURL, escProvName))

	assert.Equals(t, linker.GetLink(ctx, DirectoryLinkType), fmt.Sprintf("%s/acme/%s/directory", baseURL, escProvName))

	assert.Equals(t, linker.GetLink(ctx, RevokeCertLinkType, id), fmt.Sprintf("%s/acme/%s/revoke-cert", baseURL, escProvName))

	assert.Equals(t, linker.GetLink(ctx, KeyChangeLinkType), fmt.Sprintf("%s/acme/%s/key-change", baseURL, escProvName))

	assert.Equals(t, linker.GetLink(ctx, ChallengeLinkType, id, id), fmt.Sprintf("%s/acme/%s/challenge/%s/%s", baseURL, escProvName, id, id))

	assert.Equals(t, linker.GetLink(ctx, CertificateLinkType, id), fmt.Sprintf("%s/acme/%s/certificate/1234", baseURL, escProvName))
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
