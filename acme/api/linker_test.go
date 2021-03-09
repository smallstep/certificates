package api

import (
	"context"
	"fmt"
	"net/url"
	"testing"

	"github.com/smallstep/assert"
)

func TestLinkerGetLink(t *testing.T) {
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

func TestLinkerGetLinkExplicit(t *testing.T) {
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

	assert.Equals(t, linker.GetLinkExplicit(ChallengeLinkType, provID, true, baseURL, id), fmt.Sprintf("%s/acme/%s/challenge/%s/%s", baseURL, provID, id, id))
	assert.Equals(t, linker.GetLinkExplicit(ChallengeLinkType, provID, false, baseURL, id), fmt.Sprintf("/%s/challenge/%s/%s", provID, id, id))

	assert.Equals(t, linker.GetLinkExplicit(CertificateLinkType, provID, true, baseURL, id), fmt.Sprintf("%s/acme/%s/certificate/1234", baseURL, provID))
	assert.Equals(t, linker.GetLinkExplicit(CertificateLinkType, provID, false, baseURL, id), fmt.Sprintf("/%s/certificate/1234", provID))
}
