package acme

import (
	"fmt"
	"testing"

	"github.com/smallstep/assert"
)

func TestDirectoryGetLink(t *testing.T) {
	dns := "ca.smallstep.com"
	prefix := "acme"
	dir := newDirectory(dns, prefix)
	id := "1234"

	prov := newProv()
	provID := URLSafeProvisionerName(prov)

	assert.Equals(t, dir.getLink(NewNonceLink, provID, true), fmt.Sprintf("https://ca.smallstep.com/acme/%s/new-nonce", provID))
	assert.Equals(t, dir.getLink(NewNonceLink, provID, false), fmt.Sprintf("/%s/new-nonce", provID))

	assert.Equals(t, dir.getLink(NewAccountLink, provID, true), fmt.Sprintf("https://ca.smallstep.com/acme/%s/new-account", provID))
	assert.Equals(t, dir.getLink(NewAccountLink, provID, false), fmt.Sprintf("/%s/new-account", provID))

	assert.Equals(t, dir.getLink(AccountLink, provID, true, id), fmt.Sprintf("https://ca.smallstep.com/acme/%s/account/1234", provID))
	assert.Equals(t, dir.getLink(AccountLink, provID, false, id), fmt.Sprintf("/%s/account/1234", provID))

	assert.Equals(t, dir.getLink(NewOrderLink, provID, true), fmt.Sprintf("https://ca.smallstep.com/acme/%s/new-order", provID))
	assert.Equals(t, dir.getLink(NewOrderLink, provID, false), fmt.Sprintf("/%s/new-order", provID))

	assert.Equals(t, dir.getLink(OrderLink, provID, true, id), fmt.Sprintf("https://ca.smallstep.com/acme/%s/order/1234", provID))
	assert.Equals(t, dir.getLink(OrderLink, provID, false, id), fmt.Sprintf("/%s/order/1234", provID))

	assert.Equals(t, dir.getLink(OrdersByAccountLink, provID, true, id), fmt.Sprintf("https://ca.smallstep.com/acme/%s/account/1234/orders", provID))
	assert.Equals(t, dir.getLink(OrdersByAccountLink, provID, false, id), fmt.Sprintf("/%s/account/1234/orders", provID))

	assert.Equals(t, dir.getLink(FinalizeLink, provID, true, id), fmt.Sprintf("https://ca.smallstep.com/acme/%s/order/1234/finalize", provID))
	assert.Equals(t, dir.getLink(FinalizeLink, provID, false, id), fmt.Sprintf("/%s/order/1234/finalize", provID))

	assert.Equals(t, dir.getLink(NewAuthzLink, provID, true), fmt.Sprintf("https://ca.smallstep.com/acme/%s/new-authz", provID))
	assert.Equals(t, dir.getLink(NewAuthzLink, provID, false), fmt.Sprintf("/%s/new-authz", provID))

	assert.Equals(t, dir.getLink(AuthzLink, provID, true, id), fmt.Sprintf("https://ca.smallstep.com/acme/%s/authz/1234", provID))
	assert.Equals(t, dir.getLink(AuthzLink, provID, false, id), fmt.Sprintf("/%s/authz/1234", provID))

	assert.Equals(t, dir.getLink(DirectoryLink, provID, true), fmt.Sprintf("https://ca.smallstep.com/acme/%s/directory", provID))
	assert.Equals(t, dir.getLink(DirectoryLink, provID, false), fmt.Sprintf("/%s/directory", provID))

	assert.Equals(t, dir.getLink(RevokeCertLink, provID, true, id), fmt.Sprintf("https://ca.smallstep.com/acme/%s/revoke-cert", provID))
	assert.Equals(t, dir.getLink(RevokeCertLink, provID, false), fmt.Sprintf("/%s/revoke-cert", provID))

	assert.Equals(t, dir.getLink(KeyChangeLink, provID, true), fmt.Sprintf("https://ca.smallstep.com/acme/%s/key-change", provID))
	assert.Equals(t, dir.getLink(KeyChangeLink, provID, false), fmt.Sprintf("/%s/key-change", provID))

	assert.Equals(t, dir.getLink(ChallengeLink, provID, true, id), fmt.Sprintf("https://ca.smallstep.com/acme/%s/challenge/1234", provID))
	assert.Equals(t, dir.getLink(ChallengeLink, provID, false, id), fmt.Sprintf("/%s/challenge/1234", provID))

	assert.Equals(t, dir.getLink(CertificateLink, provID, true, id), fmt.Sprintf("https://ca.smallstep.com/acme/%s/certificate/1234", provID))
	assert.Equals(t, dir.getLink(CertificateLink, provID, false, id), fmt.Sprintf("/%s/certificate/1234", provID))
}
