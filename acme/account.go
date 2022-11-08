package acme

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"time"

	"go.step.sm/crypto/jose"

	"github.com/smallstep/certificates/authority/policy"
)

// Account is a subset of the internal account type containing only those
// attributes required for responses in the ACME protocol.
type Account struct {
	ID                     string           `json:"-"`
	Key                    *jose.JSONWebKey `json:"-"`
	Contact                []string         `json:"contact,omitempty"`
	Status                 Status           `json:"status"`
	OrdersURL              string           `json:"orders"`
	ExternalAccountBinding interface{}      `json:"externalAccountBinding,omitempty"`
}

// ToLog enables response logging.
func (a *Account) ToLog() (interface{}, error) {
	b, err := json.Marshal(a)
	if err != nil {
		return nil, WrapErrorISE(err, "error marshaling account for logging")
	}
	return string(b), nil
}

// IsValid returns true if the Account is valid.
func (a *Account) IsValid() bool {
	return a.Status == StatusValid
}

// KeyToID converts a JWK to a thumbprint.
func KeyToID(jwk *jose.JSONWebKey) (string, error) {
	kid, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", WrapErrorISE(err, "error generating jwk thumbprint")
	}
	return base64.RawURLEncoding.EncodeToString(kid), nil
}

// PolicyNames contains ACME account level policy names
type PolicyNames struct {
	DNSNames []string `json:"dns"`
	IPRanges []string `json:"ips"`
}

// X509Policy contains ACME account level X.509 policy
type X509Policy struct {
	Allowed            PolicyNames `json:"allow"`
	Denied             PolicyNames `json:"deny"`
	AllowWildcardNames bool        `json:"allowWildcardNames"`
}

// Policy is an ACME Account level policy
type Policy struct {
	X509 X509Policy `json:"x509"`
}

func (p *Policy) GetAllowedNameOptions() *policy.X509NameOptions {
	if p == nil {
		return nil
	}
	return &policy.X509NameOptions{
		DNSDomains: p.X509.Allowed.DNSNames,
		IPRanges:   p.X509.Allowed.IPRanges,
	}
}
func (p *Policy) GetDeniedNameOptions() *policy.X509NameOptions {
	if p == nil {
		return nil
	}
	return &policy.X509NameOptions{
		DNSDomains: p.X509.Denied.DNSNames,
		IPRanges:   p.X509.Denied.IPRanges,
	}
}

// AreWildcardNamesAllowed returns if wildcard names
// like *.example.com are allowed to be signed.
// Defaults to false.
func (p *Policy) AreWildcardNamesAllowed() bool {
	if p == nil {
		return false
	}
	return p.X509.AllowWildcardNames
}

// ExternalAccountKey is an ACME External Account Binding key.
type ExternalAccountKey struct {
	ID            string    `json:"id"`
	ProvisionerID string    `json:"provisionerID"`
	Reference     string    `json:"reference"`
	AccountID     string    `json:"-"`
	HmacKey       []byte    `json:"-"`
	CreatedAt     time.Time `json:"createdAt"`
	BoundAt       time.Time `json:"boundAt,omitempty"`
	Policy        *Policy   `json:"policy,omitempty"`
}

// AlreadyBound returns whether this EAK is already bound to
// an ACME Account or not.
func (eak *ExternalAccountKey) AlreadyBound() bool {
	return !eak.BoundAt.IsZero()
}

// BindTo binds the EAK to an Account.
// It returns an error if it's already bound.
func (eak *ExternalAccountKey) BindTo(account *Account) error {
	if eak.AlreadyBound() {
		return NewError(ErrorUnauthorizedType, "external account binding key with id '%s' was already bound to account '%s' on %s", eak.ID, eak.AccountID, eak.BoundAt)
	}
	eak.AccountID = account.ID
	eak.BoundAt = time.Now()
	eak.HmacKey = []byte{} // clearing the key bytes; can only be used once
	return nil
}
