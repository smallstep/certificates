package acme

import (
	"context"
	"fmt"
	"net/url"
	"testing"

	"github.com/smallstep/assert"
)

func TestDirectoryGetLink(t *testing.T) {
	dns := "ca.smallstep.com"
	prefix := "acme"
	dir := newDirectory(dns, prefix)
	id := "1234"

	prov := newProv()
	provName := url.PathEscape(prov.GetName())
	baseURL := &url.URL{Scheme: "https", Host: "test.ca.smallstep.com"}
	ctx := context.WithValue(context.Background(), ProvisionerContextKey, prov)
	ctx = context.WithValue(ctx, BaseURLContextKey, baseURL)

	assert.Equals(t, dir.getLink(ctx, NewNonceLink, true),
		fmt.Sprintf("%s/acme/%s/new-nonce", baseURL.String(), provName))
	assert.Equals(t, dir.getLink(ctx, NewNonceLink, false), fmt.Sprintf("/%s/new-nonce", provName))

	// No provisioner
	ctxNoProv := context.WithValue(context.Background(), BaseURLContextKey, baseURL)
	assert.Equals(t, dir.getLink(ctxNoProv, NewNonceLink, true),
		fmt.Sprintf("%s/acme//new-nonce", baseURL.String()))
	assert.Equals(t, dir.getLink(ctxNoProv, NewNonceLink, false), "//new-nonce")

	// No baseURL
	ctxNoBaseURL := context.WithValue(context.Background(), ProvisionerContextKey, prov)
	assert.Equals(t, dir.getLink(ctxNoBaseURL, NewNonceLink, true),
		fmt.Sprintf("%s/acme/%s/new-nonce", "https://ca.smallstep.com", provName))
	assert.Equals(t, dir.getLink(ctxNoBaseURL, NewNonceLink, false), fmt.Sprintf("/%s/new-nonce", provName))

	assert.Equals(t, dir.getLink(ctx, OrderLink, true, id),
		fmt.Sprintf("%s/acme/%s/order/1234", baseURL.String(), provName))
	assert.Equals(t, dir.getLink(ctx, OrderLink, false, id), fmt.Sprintf("/%s/order/1234", provName))
}

func TestDirectoryGetLinkExplicit(t *testing.T) {
	dns := "ca.smallstep.com"
	baseURL := &url.URL{Scheme: "https", Host: "test.ca.smallstep.com"}
	prefix := "acme"
	dir := newDirectory(dns, prefix)
	id := "1234"

	prov := newProv()
	provID := url.PathEscape(prov.GetName())

	assert.Equals(t, dir.getLinkExplicit(NewNonceLink, provID, true, nil), fmt.Sprintf("%s/acme/%s/new-nonce", "https://ca.smallstep.com", provID))
	assert.Equals(t, dir.getLinkExplicit(NewNonceLink, provID, true, &url.URL{}), fmt.Sprintf("%s/acme/%s/new-nonce", "https://ca.smallstep.com", provID))
	assert.Equals(t, dir.getLinkExplicit(NewNonceLink, provID, true, &url.URL{Scheme: "http"}), fmt.Sprintf("%s/acme/%s/new-nonce", "http://ca.smallstep.com", provID))
	assert.Equals(t, dir.getLinkExplicit(NewNonceLink, provID, true, baseURL), fmt.Sprintf("%s/acme/%s/new-nonce", baseURL, provID))
	assert.Equals(t, dir.getLinkExplicit(NewNonceLink, provID, false, baseURL), fmt.Sprintf("/%s/new-nonce", provID))

	assert.Equals(t, dir.getLinkExplicit(NewAccountLink, provID, true, baseURL), fmt.Sprintf("%s/acme/%s/new-account", baseURL, provID))
	assert.Equals(t, dir.getLinkExplicit(NewAccountLink, provID, false, baseURL), fmt.Sprintf("/%s/new-account", provID))

	assert.Equals(t, dir.getLinkExplicit(AccountLink, provID, true, baseURL, id), fmt.Sprintf("%s/acme/%s/account/1234", baseURL, provID))
	assert.Equals(t, dir.getLinkExplicit(AccountLink, provID, false, baseURL, id), fmt.Sprintf("/%s/account/1234", provID))

	assert.Equals(t, dir.getLinkExplicit(NewOrderLink, provID, true, baseURL), fmt.Sprintf("%s/acme/%s/new-order", baseURL, provID))
	assert.Equals(t, dir.getLinkExplicit(NewOrderLink, provID, false, baseURL), fmt.Sprintf("/%s/new-order", provID))

	assert.Equals(t, dir.getLinkExplicit(OrderLink, provID, true, baseURL, id), fmt.Sprintf("%s/acme/%s/order/1234", baseURL, provID))
	assert.Equals(t, dir.getLinkExplicit(OrderLink, provID, false, baseURL, id), fmt.Sprintf("/%s/order/1234", provID))

	assert.Equals(t, dir.getLinkExplicit(OrdersByAccountLink, provID, true, baseURL, id), fmt.Sprintf("%s/acme/%s/account/1234/orders", baseURL, provID))
	assert.Equals(t, dir.getLinkExplicit(OrdersByAccountLink, provID, false, baseURL, id), fmt.Sprintf("/%s/account/1234/orders", provID))

	assert.Equals(t, dir.getLinkExplicit(FinalizeLink, provID, true, baseURL, id), fmt.Sprintf("%s/acme/%s/order/1234/finalize", baseURL, provID))
	assert.Equals(t, dir.getLinkExplicit(FinalizeLink, provID, false, baseURL, id), fmt.Sprintf("/%s/order/1234/finalize", provID))

	assert.Equals(t, dir.getLinkExplicit(NewAuthzLink, provID, true, baseURL), fmt.Sprintf("%s/acme/%s/new-authz", baseURL, provID))
	assert.Equals(t, dir.getLinkExplicit(NewAuthzLink, provID, false, baseURL), fmt.Sprintf("/%s/new-authz", provID))

	assert.Equals(t, dir.getLinkExplicit(AuthzLink, provID, true, baseURL, id), fmt.Sprintf("%s/acme/%s/authz/1234", baseURL, provID))
	assert.Equals(t, dir.getLinkExplicit(AuthzLink, provID, false, baseURL, id), fmt.Sprintf("/%s/authz/1234", provID))

	assert.Equals(t, dir.getLinkExplicit(DirectoryLink, provID, true, baseURL), fmt.Sprintf("%s/acme/%s/directory", baseURL, provID))
	assert.Equals(t, dir.getLinkExplicit(DirectoryLink, provID, false, baseURL), fmt.Sprintf("/%s/directory", provID))

	assert.Equals(t, dir.getLinkExplicit(RevokeCertLink, provID, true, baseURL, id), fmt.Sprintf("%s/acme/%s/revoke-cert", baseURL, provID))
	assert.Equals(t, dir.getLinkExplicit(RevokeCertLink, provID, false, baseURL), fmt.Sprintf("/%s/revoke-cert", provID))

	assert.Equals(t, dir.getLinkExplicit(KeyChangeLink, provID, true, baseURL), fmt.Sprintf("%s/acme/%s/key-change", baseURL, provID))
	assert.Equals(t, dir.getLinkExplicit(KeyChangeLink, provID, false, baseURL), fmt.Sprintf("/%s/key-change", provID))

	assert.Equals(t, dir.getLinkExplicit(ChallengeLink, provID, true, baseURL, id), fmt.Sprintf("%s/acme/%s/challenge/1234", baseURL, provID))
	assert.Equals(t, dir.getLinkExplicit(ChallengeLink, provID, false, baseURL, id), fmt.Sprintf("/%s/challenge/1234", provID))

	assert.Equals(t, dir.getLinkExplicit(CertificateLink, provID, true, baseURL, id), fmt.Sprintf("%s/acme/%s/certificate/1234", baseURL, provID))
	assert.Equals(t, dir.getLinkExplicit(CertificateLink, provID, false, baseURL, id), fmt.Sprintf("/%s/certificate/1234", provID))
}
