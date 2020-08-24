package acme

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/provisioner"
	database "github.com/smallstep/certificates/db"
	"github.com/smallstep/nosql"
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
	NewAccount(ctx context.Context, ao AccountOptions) (*Account, error)
	UpdateAccount(context.Context, string, []string) (*Account, error)

	GetAuthz(ctx context.Context, accID string, authzID string) (*Authz, error)
	ValidateChallenge(ctx context.Context, accID string, chID string, key *jose.JSONWebKey) (*Challenge, error)

	FinalizeOrder(ctx context.Context, accID string, orderID string, csr *x509.CertificateRequest) (*Order, error)
	GetOrder(ctx context.Context, accID string, orderID string) (*Order, error)
	GetOrdersByAccount(ctx context.Context, accID string) ([]string, error)
	NewOrder(ctx context.Context, oo OrderOptions) (*Order, error)

	GetCertificate(string, string) ([]byte, error)

	LoadProvisionerByID(string) (provisioner.Interface, error)
	GetLink(ctx context.Context, linkType Link, absoluteLink bool, inputs ...string) string
	GetLinkExplicit(linkType Link, provName string, absoluteLink bool, baseURL *url.URL, inputs ...string) string
}

// Authority is the layer that handles all ACME interactions.
type Authority struct {
	backdate provisioner.Duration
	db       nosql.DB
	dir      *directory
	signAuth SignAuthority
}

// AuthorityOptions required to create a new ACME Authority.
type AuthorityOptions struct {
	Backdate provisioner.Duration
	// DB is the database used by nosql.
	DB nosql.DB
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

var (
	accountTable           = []byte("acme_accounts")
	accountByKeyIDTable    = []byte("acme_keyID_accountID_index")
	authzTable             = []byte("acme_authzs")
	challengeTable         = []byte("acme_challenges")
	nonceTable             = []byte("nonces")
	orderTable             = []byte("acme_orders")
	ordersByAccountIDTable = []byte("acme_account_orders_index")
	certTable              = []byte("acme_certs")
)

// NewAuthority returns a new Authority that implements the ACME interface.
//
// Deprecated: NewAuthority exists for hitorical compatibility and should not
// be used. Use acme.New() instead.
func NewAuthority(db nosql.DB, dns, prefix string, signAuth SignAuthority) (*Authority, error) {
	return New(signAuth, AuthorityOptions{
		DB:     db,
		DNS:    dns,
		Prefix: prefix,
	})
}

// New returns a new Autohrity that implements the ACME interface.
func New(signAuth SignAuthority, ops AuthorityOptions) (*Authority, error) {
	if _, ok := ops.DB.(*database.SimpleDB); !ok {
		// If it's not a SimpleDB then go ahead and bootstrap the DB with the
		// necessary ACME tables. SimpleDB should ONLY be used for testing.
		tables := [][]byte{accountTable, accountByKeyIDTable, authzTable,
			challengeTable, nonceTable, orderTable, ordersByAccountIDTable,
			certTable}
		for _, b := range tables {
			if err := ops.DB.CreateTable(b); err != nil {
				return nil, errors.Wrapf(err, "error creating table %s",
					string(b))
			}
		}
	}
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
func (a *Authority) NewNonce() (string, error) {
	n, err := newNonce(a.db)
	if err != nil {
		return "", err
	}
	return n.ID, nil
}

// UseNonce consumes the given nonce if it is valid, returns error otherwise.
func (a *Authority) UseNonce(nonce string) error {
	return useNonce(a.db, nonce)
}

// NewAccount creates, stores, and returns a new ACME account.
func (a *Authority) NewAccount(ctx context.Context, ao AccountOptions) (*Account, error) {
	acc, err := newAccount(a.db, ao)
	if err != nil {
		return nil, err
	}
	return acc.toACME(ctx, a.db, a.dir)
}

// UpdateAccount updates an ACME account.
func (a *Authority) UpdateAccount(ctx context.Context, id string, contact []string) (*Account, error) {
	acc, err := getAccountByID(a.db, id)
	if err != nil {
		return nil, ServerInternalErr(err)
	}
	if acc, err = acc.update(a.db, contact); err != nil {
		return nil, err
	}
	return acc.toACME(ctx, a.db, a.dir)
}

// GetAccount returns an ACME account.
func (a *Authority) GetAccount(ctx context.Context, id string) (*Account, error) {
	acc, err := getAccountByID(a.db, id)
	if err != nil {
		return nil, err
	}
	return acc.toACME(ctx, a.db, a.dir)
}

// DeactivateAccount deactivates an ACME account.
func (a *Authority) DeactivateAccount(ctx context.Context, id string) (*Account, error) {
	acc, err := getAccountByID(a.db, id)
	if err != nil {
		return nil, err
	}
	if acc, err = acc.deactivate(a.db); err != nil {
		return nil, err
	}
	return acc.toACME(ctx, a.db, a.dir)
}

func keyToID(jwk *jose.JSONWebKey) (string, error) {
	kid, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", ServerInternalErr(errors.Wrap(err, "error generating jwk thumbprint"))
	}
	return base64.RawURLEncoding.EncodeToString(kid), nil
}

// GetAccountByKey returns the ACME associated with the jwk id.
func (a *Authority) GetAccountByKey(ctx context.Context, jwk *jose.JSONWebKey) (*Account, error) {
	kid, err := keyToID(jwk)
	if err != nil {
		return nil, err
	}
	acc, err := getAccountByKeyID(a.db, kid)
	if err != nil {
		return nil, err
	}
	return acc.toACME(ctx, a.db, a.dir)
}

// GetOrder returns an ACME order.
func (a *Authority) GetOrder(ctx context.Context, accID, orderID string) (*Order, error) {
	o, err := getOrder(a.db, orderID)
	if err != nil {
		return nil, err
	}
	if accID != o.AccountID {
		return nil, UnauthorizedErr(errors.New("account does not own order"))
	}
	if o, err = o.updateStatus(a.db); err != nil {
		return nil, err
	}
	return o.toACME(ctx, a.db, a.dir)
}

// GetOrdersByAccount returns the list of order urls owned by the account.
func (a *Authority) GetOrdersByAccount(ctx context.Context, id string) ([]string, error) {
	oids, err := getOrderIDsByAccount(a.db, id)
	if err != nil {
		return nil, err
	}

	var ret = []string{}
	for _, oid := range oids {
		ret = append(ret, a.dir.getLink(ctx, OrderLink, true, oid))
	}
	return ret, nil
}

// NewOrder generates, stores, and returns a new ACME order.
func (a *Authority) NewOrder(ctx context.Context, ops OrderOptions) (*Order, error) {
	prov, err := ProvisionerFromContext(ctx)
	if err != nil {
		return nil, err
	}
	ops.backdate = a.backdate.Duration
	ops.defaultDuration = prov.DefaultTLSCertDuration()
	order, err := newOrder(a.db, ops)
	if err != nil {
		return nil, Wrap(err, "error creating order")
	}
	return order.toACME(ctx, a.db, a.dir)
}

// FinalizeOrder attempts to finalize an order and generate a new certificate.
func (a *Authority) FinalizeOrder(ctx context.Context, accID, orderID string, csr *x509.CertificateRequest) (*Order, error) {
	prov, err := ProvisionerFromContext(ctx)
	if err != nil {
		return nil, err
	}
	o, err := getOrder(a.db, orderID)
	if err != nil {
		return nil, err
	}
	if accID != o.AccountID {
		return nil, UnauthorizedErr(errors.New("account does not own order"))
	}
	o, err = o.finalize(a.db, csr, a.signAuth, prov)
	if err != nil {
		return nil, Wrap(err, "error finalizing order")
	}
	return o.toACME(ctx, a.db, a.dir)
}

// GetAuthz retrieves and attempts to update the status on an ACME authz
// before returning.
func (a *Authority) GetAuthz(ctx context.Context, accID, authzID string) (*Authz, error) {
	az, err := getAuthz(a.db, authzID)
	if err != nil {
		return nil, err
	}
	if accID != az.getAccountID() {
		return nil, UnauthorizedErr(errors.New("account does not own authz"))
	}
	az, err = az.updateStatus(a.db)
	if err != nil {
		return nil, Wrap(err, "error updating authz status")
	}
	return az.toACME(ctx, a.db, a.dir)
}

// ValidateChallenge attempts to validate the challenge.
func (a *Authority) ValidateChallenge(ctx context.Context, accID, chID string, jwk *jose.JSONWebKey) (*Challenge, error) {
	ch, err := getChallenge(a.db, chID)
	if err != nil {
		return nil, err
	}
	if accID != ch.getAccountID() {
		return nil, UnauthorizedErr(errors.New("account does not own challenge"))
	}
	client := http.Client{
		Timeout: time.Duration(30 * time.Second),
	}
	dialer := &net.Dialer{
		Timeout: 30 * time.Second,
	}
	ch, err = ch.validate(a.db, jwk, validateOptions{
		httpGet:   client.Get,
		lookupTxt: net.LookupTXT,
		tlsDial: func(network, addr string, config *tls.Config) (*tls.Conn, error) {
			return tls.DialWithDialer(dialer, network, addr, config)
		},
	})
	if err != nil {
		return nil, Wrap(err, "error attempting challenge validation")
	}
	return ch.toACME(ctx, a.db, a.dir)
}

// GetCertificate retrieves the Certificate by ID.
func (a *Authority) GetCertificate(accID, certID string) ([]byte, error) {
	cert, err := getCert(a.db, certID)
	if err != nil {
		return nil, err
	}
	if accID != cert.AccountID {
		return nil, UnauthorizedErr(errors.New("account does not own certificate"))
	}
	return cert.toACME(a.db, a.dir)
}
