package acme

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/smallstep/certificates/authority/provisioner"
	"go.step.sm/crypto/jose"
)

// Interface is the acme authority interface.
type Interface interface {
	GetDirectory(ctx context.Context) (*Directory, error)
	NewNonce() (string, error)
	UseNonce(string) error

	DeactivateAccount(ctx context.Context, accID string) (*Account, error)
	GetAccount(ctx context.Context, accID string) (*Account, error)
	GetAccountByKey(ctx context.Context, key *jose.JSONWebKey) (*Account, error)
	NewAccount(ctx context.Context, acc *Account) (*Account, error)
	UpdateAccount(ctx context.Context, acc *Account) (*Account, error)

	GetAuthz(ctx context.Context, accID string, authzID string) (*Authorization, error)
	ValidateChallenge(ctx context.Context, accID string, chID string, key *jose.JSONWebKey) (*Challenge, error)

	FinalizeOrder(ctx context.Context, accID string, orderID string, csr *x509.CertificateRequest) (*Order, error)
	GetOrder(ctx context.Context, accID string, orderID string) (*Order, error)
	GetOrdersByAccount(ctx context.Context, accID string) ([]string, error)
	NewOrder(ctx context.Context, o *Order) (*Order, error)

	GetCertificate(string, string) ([]byte, error)

	LoadProvisionerByID(string) (provisioner.Interface, error)
	GetLink(ctx context.Context, linkType Link, absoluteLink bool, inputs ...string) string
	GetLinkExplicit(linkType Link, provName string, absoluteLink bool, baseURL *url.URL, inputs ...string) string
}

// Authority is the layer that handles all ACME interactions.
type Authority struct {
	backdate provisioner.Duration
	db       DB
	dir      *directory
	signAuth SignAuthority
}

// AuthorityOptions required to create a new ACME Authority.
type AuthorityOptions struct {
	Backdate provisioner.Duration
	// DB storage backend that impements the acme.DB interface.
	DB DB
	// DNS the host used to generate accurate ACME links. By default the authority
	// will use the Host from the request, so this value will only be used if
	// request.Host is empty.
	DNS string
	// Prefix is a URL path prefix under which the ACME api is served. This
	// prefix is required to generate accurate ACME links.
	// E.g. https://ca.smallstep.com/acme/my-acme-provisioner/new-account --
	// "acme" is the prefix from which the ACME api is accessed.
	Prefix string
}

// NewAuthority returns a new Authority that implements the ACME interface.
//
// Deprecated: NewAuthority exists for hitorical compatibility and should not
// be used. Use acme.New() instead.
func NewAuthority(db DB, dns, prefix string, signAuth SignAuthority) (*Authority, error) {
	return New(signAuth, AuthorityOptions{
		DB:     db,
		DNS:    dns,
		Prefix: prefix,
	})
}

// New returns a new Authority that implements the ACME interface.
func New(signAuth SignAuthority, ops AuthorityOptions) (*Authority, error) {
	return &Authority{
		backdate: ops.Backdate, db: ops.DB, dir: newDirectory(ops.DNS, ops.Prefix), signAuth: signAuth,
	}, nil
}

// GetLink returns the requested link from the directory.
func (a *Authority) GetLink(ctx context.Context, typ Link, abs bool, inputs ...string) string {
	return a.dir.getLink(ctx, typ, abs, inputs...)
}

// GetLinkExplicit returns the requested link from the directory.
func (a *Authority) GetLinkExplicit(typ Link, provName string, abs bool, baseURL *url.URL, inputs ...string) string {
	return a.dir.getLinkExplicit(typ, provName, abs, baseURL, inputs...)
}

// GetDirectory returns the ACME directory object.
func (a *Authority) GetDirectory(ctx context.Context) (*Directory, error) {
	return &Directory{
		NewNonce:   a.dir.getLink(ctx, NewNonceLink, true),
		NewAccount: a.dir.getLink(ctx, NewAccountLink, true),
		NewOrder:   a.dir.getLink(ctx, NewOrderLink, true),
		RevokeCert: a.dir.getLink(ctx, RevokeCertLink, true),
		KeyChange:  a.dir.getLink(ctx, KeyChangeLink, true),
	}, nil
}

// LoadProvisionerByID calls out to the SignAuthority interface to load a
// provisioner by ID.
func (a *Authority) LoadProvisionerByID(id string) (provisioner.Interface, error) {
	return a.signAuth.LoadProvisionerByID(id)
}

// NewNonce generates, stores, and returns a new ACME nonce.
func (a *Authority) NewNonce(ctx context.Context) (Nonce, error) {
	return a.db.CreateNonce(ctx)
}

// UseNonce consumes the given nonce if it is valid, returns error otherwise.
func (a *Authority) UseNonce(ctx context.Context, nonce string) error {
	return a.db.DeleteNonce(ctx, Nonce(nonce))
}

// NewAccount creates, stores, and returns a new ACME account.
func (a *Authority) NewAccount(ctx context.Context, acc *Account) error {
	if err := a.db.CreateAccount(ctx, acc); err != nil {
		return ErrorWrap(ErrorServerInternalType, err, "error creating account")
	}
	return nil
}

// UpdateAccount updates an ACME account.
func (a *Authority) UpdateAccount(ctx context.Context, acc *Account) (*Account, error) {
	/*
		acc.Contact = auo.Contact
		acc.Status = auo.Status
	*/
	if err := a.db.UpdateAccount(ctx, acc); err != nil {
		return nil, ErrorWrap(ErrorServerInternalType, err, "error updating account")
	}
	return acc, nil
}

// GetAccount returns an ACME account.
func (a *Authority) GetAccount(ctx context.Context, id string) (*Account, error) {
	acc, err := a.db.GetAccount(ctx, id)
	if err != nil {
		return nil, ErrorWrap(ErrorServerInternalType, err, "error retrieving account")
	}
	return acc, nil
}

// GetAccountByKey returns the ACME associated with the jwk id.
func (a *Authority) GetAccountByKey(ctx context.Context, jwk *jose.JSONWebKey) (*Account, error) {
	kid, err := KeyToID(jwk)
	if err != nil {
		return nil, err
	}
	acc, err := a.db.GetAccountByKeyID(ctx, kid)
	return acc, err
}

// GetOrder returns an ACME order.
func (a *Authority) GetOrder(ctx context.Context, accID, orderID string) (*Order, error) {
	prov, err := ProvisionerFromContext(ctx)
	if err != nil {
		return nil, err
	}
	o, err := a.db.GetOrder(ctx, orderID)
	if err != nil {
		return nil, ErrorWrap(ErrorServerInternalType, err, "error retrieving order")
	}
	if accID != o.AccountID {
		log.Printf("account-id from request ('%s') does not match order account-id ('%s')", accID, o.AccountID)
		return nil, NewError(ErrorUnauthorizedType, "account does not own order")
	}
	if prov.GetID() != o.ProvisionerID {
		log.Printf("provisioner-id from request ('%s') does not match order provisioner-id ('%s')", prov.GetID(), o.ProvisionerID)
		return nil, NewError(ErrorUnauthorizedType, "provisioner does not own order")
	}
	if err = o.UpdateStatus(ctx, a.db); err != nil {
		return nil, ErrorWrap(ErrorServerInternalType, err, "error updating order")
	}
	return o, nil
}

/*
// GetOrdersByAccount returns the list of order urls owned by the account.
func (a *Authority) GetOrdersByAccount(ctx context.Context, id string) ([]string, error) {
	ordersByAccountMux.Lock()
	defer ordersByAccountMux.Unlock()

	var oiba = orderIDsByAccount{}
	oids, err := oiba.unsafeGetOrderIDsByAccount(a.db, id)
	if err != nil {
		return nil, err
	}

	var ret = []string{}
	for _, oid := range oids {
		ret = append(ret, a.dir.getLink(ctx, OrderLink, true, oid))
	}
	return ret, nil
}
*/

// NewOrder generates, stores, and returns a new ACME order.
func (a *Authority) NewOrder(ctx context.Context, o *Order) (*Order, error) {
	prov, err := ProvisionerFromContext(ctx)
	if err != nil {
		return nil, err
	}
	o.DefaultDuration = prov.DefaultTLSCertDuration()
	o.Backdate = a.backdate.Duration
	o.ProvisionerID = prov.GetID()

	if err = a.db.CreateOrder(ctx, o); err != nil {
		return nil, ErrorWrap(ErrorServerInternalType, err, "error creating order")
	}
	return o, nil
}

// FinalizeOrder attempts to finalize an order and generate a new certificate.
func (a *Authority) FinalizeOrder(ctx context.Context, accID, orderID string, csr *x509.CertificateRequest) (*Order, error) {
	prov, err := ProvisionerFromContext(ctx)
	if err != nil {
		return nil, err
	}
	o, err := a.db.GetOrder(ctx, orderID)
	if err != nil {
		return nil, ErrorWrap(ErrorServerInternalType, err, "error retrieving order")
	}
	if accID != o.AccountID {
		log.Printf("account-id from request ('%s') does not match order account-id ('%s')", accID, o.AccountID)
		return nil, NewError(ErrorUnauthorizedType, "account does not own order")
	}
	if prov.GetID() != o.ProvisionerID {
		log.Printf("provisioner-id from request ('%s') does not match order provisioner-id ('%s')", prov.GetID(), o.ProvisionerID)
		return nil, NewError(ErrorUnauthorizedType, "provisioner does not own order")
	}
	if err = o.Finalize(ctx, a.db, csr, a.signAuth, prov); err != nil {
		return nil, ErrorWrap(ErrorServerInternalType, err, "error finalizing order")
	}
	return o, nil
}

// GetAuthz retrieves and attempts to update the status on an ACME authz
// before returning.
func (a *Authority) GetAuthz(ctx context.Context, accID, authzID string) (*Authorization, error) {
	az, err := a.db.GetAuthorization(ctx, authzID)
	if err != nil {
		return nil, ErrorWrap(ErrorServerInternalType, err, "error retrieving authorization")
	}
	if accID != az.AccountID {
		log.Printf("account-id from request ('%s') does not match authz account-id ('%s')", accID, az.AccountID)
		return nil, NewError(ErrorUnauthorizedType, "account does not own order")
	}
	if err = az.UpdateStatus(ctx, a.db); err != nil {
		return nil, ErrorWrap(ErrorServerInternalType, err, "error updating authorization status")
	}
	return az, nil
}

// ValidateChallenge attempts to validate the challenge.
func (a *Authority) ValidateChallenge(ctx context.Context, accID, chID string, jwk *jose.JSONWebKey) (*Challenge, error) {
	ch, err := a.db.GetChallenge(ctx, chID, "todo")
	if err != nil {
		return nil, ErrorWrap(ErrorServerInternalType, err, "error retrieving challenge")
	}
	if accID != ch.AccountID {
		log.Printf("account-id from request ('%s') does not match challenge account-id ('%s')", accID, ch.AccountID)
		return nil, NewError(ErrorUnauthorizedType, "account does not own order")
	}
	client := http.Client{
		Timeout: time.Duration(30 * time.Second),
	}
	dialer := &net.Dialer{
		Timeout: 30 * time.Second,
	}
	if err = ch.Validate(ctx, a.db, jwk, validateOptions{
		httpGet:   client.Get,
		lookupTxt: net.LookupTXT,
		tlsDial: func(network, addr string, config *tls.Config) (*tls.Conn, error) {
			return tls.DialWithDialer(dialer, network, addr, config)
		},
	}); err != nil {
		return nil, ErrorWrap(ErrorServerInternalType, err, "error validating challenge")
	}
	return ch, nil
}

// GetCertificate retrieves the Certificate by ID.
func (a *Authority) GetCertificate(ctx context.Context, accID, certID string) ([]byte, error) {
	cert, err := a.db.GetCertificate(ctx, certID)
	if err != nil {
		return nil, ErrorWrap(ErrorServerInternalType, err, "error retrieving certificate")
	}
	if cert.AccountID != accID {
		log.Printf("account-id from request ('%s') does not match challenge account-id ('%s')", accID, cert.AccountID)
		return nil, NewError(ErrorUnauthorizedType, "account does not own order")
	}
	return cert.ToACME(ctx)
}
