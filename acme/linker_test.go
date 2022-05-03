package acme

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/authority/provisioner"
)

func mockProvisioner(t *testing.T) Provisioner {
	t.Helper()
	var defaultDisableRenewal = false

	// Initialize provisioners
	p := &provisioner.ACME{
		Type: "ACME",
		Name: "test@acme-<test>provisioner.com",
	}
	if err := p.Init(provisioner.Config{Claims: provisioner.Claims{
		MinTLSDur:      &provisioner.Duration{Duration: 5 * time.Minute},
		MaxTLSDur:      &provisioner.Duration{Duration: 24 * time.Hour},
		DefaultTLSDur:  &provisioner.Duration{Duration: 24 * time.Hour},
		DisableRenewal: &defaultDisableRenewal,
	}}); err != nil {
		fmt.Printf("%v", err)
	}
	return p
}

func TestGetUnescapedPathSuffix(t *testing.T) {
	getPath := GetUnescapedPathSuffix

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

func TestLinker_DNS(t *testing.T) {
	prov := mockProvisioner(t)
	escProvName := url.PathEscape(prov.GetName())
	ctx := NewProvisionerContext(context.Background(), prov)
	type test struct {
		name                  string
		dns                   string
		prefix                string
		expectedDirectoryLink string
	}
	tests := []test{
		{
			name:                  "domain",
			dns:                   "ca.smallstep.com",
			prefix:                "acme",
			expectedDirectoryLink: fmt.Sprintf("https://ca.smallstep.com/acme/%s/directory", escProvName),
		},
		{
			name:                  "domain-port",
			dns:                   "ca.smallstep.com:8443",
			prefix:                "acme",
			expectedDirectoryLink: fmt.Sprintf("https://ca.smallstep.com:8443/acme/%s/directory", escProvName),
		},
		{
			name:                  "ipv4",
			dns:                   "127.0.0.1",
			prefix:                "acme",
			expectedDirectoryLink: fmt.Sprintf("https://127.0.0.1/acme/%s/directory", escProvName),
		},
		{
			name:                  "ipv4-port",
			dns:                   "127.0.0.1:8443",
			prefix:                "acme",
			expectedDirectoryLink: fmt.Sprintf("https://127.0.0.1:8443/acme/%s/directory", escProvName),
		},
		{
			name:                  "ipv6",
			dns:                   "[::1]",
			prefix:                "acme",
			expectedDirectoryLink: fmt.Sprintf("https://[::1]/acme/%s/directory", escProvName),
		},
		{
			name:                  "ipv6-port",
			dns:                   "[::1]:8443",
			prefix:                "acme",
			expectedDirectoryLink: fmt.Sprintf("https://[::1]:8443/acme/%s/directory", escProvName),
		},
		{
			name:                  "ipv6-no-brackets",
			dns:                   "::1",
			prefix:                "acme",
			expectedDirectoryLink: fmt.Sprintf("https://[::1]/acme/%s/directory", escProvName),
		},
		{
			name:                  "ipv6-port-no-brackets",
			dns:                   "::1:8443",
			prefix:                "acme",
			expectedDirectoryLink: fmt.Sprintf("https://[::1]:8443/acme/%s/directory", escProvName),
		},
		{
			name:                  "ipv6-long-no-brackets",
			dns:                   "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			prefix:                "acme",
			expectedDirectoryLink: fmt.Sprintf("https://[2001:0db8:85a3:0000:0000:8a2e:0370:7334]/acme/%s/directory", escProvName),
		},
		{
			name:                  "ipv6-long-port-no-brackets",
			dns:                   "2001:0db8:85a3:0000:0000:8a2e:0370:7334:8443",
			prefix:                "acme",
			expectedDirectoryLink: fmt.Sprintf("https://[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:8443/acme/%s/directory", escProvName),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			linker := NewLinker(tt.dns, tt.prefix)
			assert.Equals(t, tt.expectedDirectoryLink, linker.GetLink(ctx, DirectoryLinkType))
		})
	}
}

func TestLinker_GetLink(t *testing.T) {
	dns := "ca.smallstep.com"
	prefix := "acme"
	linker := NewLinker(dns, prefix)
	id := "1234"

	prov := mockProvisioner(t)
	escProvName := url.PathEscape(prov.GetName())
	baseURL := &url.URL{Scheme: "https", Host: "test.ca.smallstep.com"}
	ctx := NewProvisionerContext(context.Background(), prov)
	ctx = context.WithValue(ctx, baseURLKey{}, baseURL)

	// No provisioner and no BaseURL from request
	assert.Equals(t, linker.GetLink(context.Background(), NewNonceLinkType), fmt.Sprintf("%s/acme/%s/new-nonce", "https://ca.smallstep.com", ""))
	// Provisioner: yes, BaseURL: no
	assert.Equals(t, linker.GetLink(context.WithValue(context.Background(), provisionerKey{}, prov), NewNonceLinkType), fmt.Sprintf("%s/acme/%s/new-nonce", "https://ca.smallstep.com", escProvName))

	// Provisioner: no, BaseURL: yes
	assert.Equals(t, linker.GetLink(context.WithValue(context.Background(), baseURLKey{}, baseURL), NewNonceLinkType), fmt.Sprintf("%s/acme/%s/new-nonce", "https://test.ca.smallstep.com", ""))

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
	prov := mockProvisioner(t)
	provName := url.PathEscape(prov.GetName())
	ctx := NewProvisionerContext(context.Background(), prov)
	ctx = context.WithValue(ctx, baseURLKey{}, baseURL)

	oid := "orderID"
	certID := "certID"
	linkerPrefix := "acme"
	l := NewLinker("dns", linkerPrefix)
	type test struct {
		o        *Order
		validate func(o *Order)
	}
	var tests = map[string]test{
		"no-authz-and-no-cert": {
			o: &Order{
				ID: oid,
			},
			validate: func(o *Order) {
				assert.Equals(t, o.FinalizeURL, fmt.Sprintf("%s/%s/%s/order/%s/finalize", baseURL, linkerPrefix, provName, oid))
				assert.Equals(t, o.AuthorizationURLs, []string{})
				assert.Equals(t, o.CertificateURL, "")
			},
		},
		"one-authz-and-cert": {
			o: &Order{
				ID:               oid,
				CertificateID:    certID,
				AuthorizationIDs: []string{"foo"},
			},
			validate: func(o *Order) {
				assert.Equals(t, o.FinalizeURL, fmt.Sprintf("%s/%s/%s/order/%s/finalize", baseURL, linkerPrefix, provName, oid))
				assert.Equals(t, o.AuthorizationURLs, []string{
					fmt.Sprintf("%s/%s/%s/authz/%s", baseURL, linkerPrefix, provName, "foo"),
				})
				assert.Equals(t, o.CertificateURL, fmt.Sprintf("%s/%s/%s/certificate/%s", baseURL, linkerPrefix, provName, certID))
			},
		},
		"many-authz": {
			o: &Order{
				ID:               oid,
				CertificateID:    certID,
				AuthorizationIDs: []string{"foo", "bar", "zap"},
			},
			validate: func(o *Order) {
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
	prov := mockProvisioner(t)
	provName := url.PathEscape(prov.GetName())
	ctx := NewProvisionerContext(context.Background(), prov)
	ctx = context.WithValue(ctx, baseURLKey{}, baseURL)

	accID := "accountID"
	linkerPrefix := "acme"
	l := NewLinker("dns", linkerPrefix)
	type test struct {
		a        *Account
		validate func(o *Account)
	}
	var tests = map[string]test{
		"ok": {
			a: &Account{
				ID: accID,
			},
			validate: func(a *Account) {
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
	prov := mockProvisioner(t)
	provName := url.PathEscape(prov.GetName())
	ctx := NewProvisionerContext(context.Background(), prov)
	ctx = context.WithValue(ctx, baseURLKey{}, baseURL)

	chID := "chID"
	azID := "azID"
	linkerPrefix := "acme"
	l := NewLinker("dns", linkerPrefix)
	type test struct {
		ch       *Challenge
		validate func(o *Challenge)
	}
	var tests = map[string]test{
		"ok": {
			ch: &Challenge{
				ID: chID,
			},
			validate: func(ch *Challenge) {
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
	prov := mockProvisioner(t)
	provName := url.PathEscape(prov.GetName())
	ctx := NewProvisionerContext(context.Background(), prov)
	ctx = context.WithValue(ctx, baseURLKey{}, baseURL)

	chID0 := "chID-0"
	chID1 := "chID-1"
	chID2 := "chID-2"
	azID := "azID"
	linkerPrefix := "acme"
	l := NewLinker("dns", linkerPrefix)
	type test struct {
		az       *Authorization
		validate func(o *Authorization)
	}
	var tests = map[string]test{
		"ok": {
			az: &Authorization{
				ID: azID,
				Challenges: []*Challenge{
					{ID: chID0},
					{ID: chID1},
					{ID: chID2},
				},
			},
			validate: func(az *Authorization) {
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
	prov := mockProvisioner(t)
	provName := url.PathEscape(prov.GetName())
	ctx := NewProvisionerContext(context.Background(), prov)
	ctx = context.WithValue(ctx, baseURLKey{}, baseURL)

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
