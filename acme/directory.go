package acme

import (
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"
)

// Directory represents an ACME directory for configuring clients.
type Directory struct {
	NewNonce   string `json:"newNonce,omitempty"`
	NewAccount string `json:"newAccount,omitempty"`
	NewOrder   string `json:"newOrder,omitempty"`
	NewAuthz   string `json:"newAuthz,omitempty"`
	RevokeCert string `json:"revokeCert,omitempty"`
	KeyChange  string `json:"keyChange,omitempty"`
}

// ToLog enables response logging for the Directory type.
func (d *Directory) ToLog() (interface{}, error) {
	b, err := json.Marshal(d)
	if err != nil {
		return nil, ServerInternalErr(errors.Wrap(err, "error marshaling directory for logging"))
	}
	return string(b), nil
}

type directory struct {
	prefix, dns string
}

// newDirectory returns a new Directory type.
func newDirectory(dns, prefix string) *directory {
	return &directory{prefix: prefix, dns: dns}
}

// Link captures the link type.
type Link int

const (
	// NewNonceLink new-nonce
	NewNonceLink Link = iota
	// NewAccountLink new-account
	NewAccountLink
	// AccountLink account
	AccountLink
	// OrderLink order
	OrderLink
	// NewOrderLink new-order
	NewOrderLink
	// OrdersByAccountLink list of orders owned by account
	OrdersByAccountLink
	// FinalizeLink finalize order
	FinalizeLink
	// NewAuthzLink authz
	NewAuthzLink
	// AuthzLink new-authz
	AuthzLink
	// ChallengeLink challenge
	ChallengeLink
	// CertificateLink certificate
	CertificateLink
	// DirectoryLink directory
	DirectoryLink
	// RevokeCertLink revoke certificate
	RevokeCertLink
	// KeyChangeLink key rollover
	KeyChangeLink
)

func (l Link) String() string {
	switch l {
	case NewNonceLink:
		return "new-nonce"
	case NewAccountLink:
		return "new-account"
	case AccountLink:
		return "account"
	case NewOrderLink:
		return "new-order"
	case OrderLink:
		return "order"
	case NewAuthzLink:
		return "new-authz"
	case AuthzLink:
		return "authz"
	case ChallengeLink:
		return "challenge"
	case CertificateLink:
		return "certificate"
	case DirectoryLink:
		return "directory"
	case RevokeCertLink:
		return "revoke-cert"
	case KeyChangeLink:
		return "key-change"
	default:
		return "unexpected"
	}
}

// getLink returns an absolute or partial path to the given resource.
func (d *directory) getLink(typ Link, provisionerName string, abs bool, inputs ...string) string {
	var link string
	switch typ {
	case NewNonceLink, NewAccountLink, NewOrderLink, NewAuthzLink, DirectoryLink, KeyChangeLink, RevokeCertLink:
		link = fmt.Sprintf("/%s/%s", provisionerName, typ.String())
	case AccountLink, OrderLink, AuthzLink, ChallengeLink, CertificateLink:
		link = fmt.Sprintf("/%s/%s/%s", provisionerName, typ.String(), inputs[0])
	case OrdersByAccountLink:
		link = fmt.Sprintf("/%s/%s/%s/orders", provisionerName, AccountLink.String(), inputs[0])
	case FinalizeLink:
		link = fmt.Sprintf("/%s/%s/%s/finalize", provisionerName, OrderLink.String(), inputs[0])
	}
	if abs {
		return fmt.Sprintf("https://%s/%s%s", d.dns, d.prefix, link)
	}
	return link
}
