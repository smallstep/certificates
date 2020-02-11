package acme

import (
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
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/nosql"
)

// Interface is the acme authority interface.
type Interface interface {
	DeactivateAccount(provisioner.Interface, string) (*Account, error)
	FinalizeOrder(provisioner.Interface, string, string, *x509.CertificateRequest) (*Order, error)
	GetAccount(provisioner.Interface, string) (*Account, error)
	GetAccountByKey(provisioner.Interface, *jose.JSONWebKey) (*Account, error)
	GetAuthz(provisioner.Interface, string, string) (*Authz, error)
	GetCertificate(string, string) ([]byte, error)
	GetDirectory(provisioner.Interface) *Directory
	GetLink(Link, string, bool, ...string) string
	GetOrder(provisioner.Interface, string, string) (*Order, error)
	GetOrdersByAccount(provisioner.Interface, string) ([]string, error)
	LoadProvisionerByID(string) (provisioner.Interface, error)
	NewAccount(provisioner.Interface, AccountOptions) (*Account, error)
	NewNonce() (string, error)
	NewOrder(provisioner.Interface, OrderOptions) (*Order, error)
	UpdateAccount(provisioner.Interface, string, []string) (*Account, error)
	UseNonce(string) error
	ValidateChallenge(provisioner.Interface, string, string, *jose.JSONWebKey) (*Challenge, error)
}

// Authority is the layer that handles all ACME interactions.
type Authority struct {
	db       nosql.DB
	dir      *directory
	signAuth SignAuthority
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
func NewAuthority(db nosql.DB, dns, prefix string, signAuth SignAuthority) (*Authority, error) {
	if _, ok := db.(*database.SimpleDB); !ok {
		// If it's not a SimpleDB then go ahead and bootstrap the DB with the
		// necessary ACME tables. SimpleDB should ONLY be used for testing.
		tables := [][]byte{accountTable, accountByKeyIDTable, authzTable,
			challengeTable, nonceTable, orderTable, ordersByAccountIDTable,
			certTable}
		for _, b := range tables {
			if err := db.CreateTable(b); err != nil {
				return nil, errors.Wrapf(err, "error creating table %s",
					string(b))
			}
		}
	}
	return &Authority{
		db: db, dir: newDirectory(dns, prefix), signAuth: signAuth,
	}, nil
}

// GetLink returns the requested link from the directory.
func (a *Authority) GetLink(typ Link, provID string, abs bool, inputs ...string) string {
	return a.dir.getLink(typ, provID, abs, inputs...)
}

// GetDirectory returns the ACME directory object.
func (a *Authority) GetDirectory(p provisioner.Interface) *Directory {
	name := url.PathEscape(p.GetName())
	return &Directory{
		NewNonce:   a.dir.getLink(NewNonceLink, name, true),
		NewAccount: a.dir.getLink(NewAccountLink, name, true),
		NewOrder:   a.dir.getLink(NewOrderLink, name, true),
		RevokeCert: a.dir.getLink(RevokeCertLink, name, true),
		KeyChange:  a.dir.getLink(KeyChangeLink, name, true),
	}
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
func (a *Authority) NewAccount(p provisioner.Interface, ao AccountOptions) (*Account, error) {
	acc, err := newAccount(a.db, ao)
	if err != nil {
		return nil, err
	}
	return acc.toACME(a.db, a.dir, p)
}

// UpdateAccount updates an ACME account.
func (a *Authority) UpdateAccount(p provisioner.Interface, id string, contact []string) (*Account, error) {
	acc, err := getAccountByID(a.db, id)
	if err != nil {
		return nil, ServerInternalErr(err)
	}
	if acc, err = acc.update(a.db, contact); err != nil {
		return nil, err
	}
	return acc.toACME(a.db, a.dir, p)
}

// GetAccount returns an ACME account.
func (a *Authority) GetAccount(p provisioner.Interface, id string) (*Account, error) {
	acc, err := getAccountByID(a.db, id)
	if err != nil {
		return nil, err
	}
	return acc.toACME(a.db, a.dir, p)
}

// DeactivateAccount deactivates an ACME account.
func (a *Authority) DeactivateAccount(p provisioner.Interface, id string) (*Account, error) {
	acc, err := getAccountByID(a.db, id)
	if err != nil {
		return nil, err
	}
	if acc, err = acc.deactivate(a.db); err != nil {
		return nil, err
	}
	return acc.toACME(a.db, a.dir, p)
}

func keyToID(jwk *jose.JSONWebKey) (string, error) {
	kid, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", ServerInternalErr(errors.Wrap(err, "error generating jwk thumbprint"))
	}
	return base64.RawURLEncoding.EncodeToString(kid), nil
}

// GetAccountByKey returns the ACME associated with the jwk id.
func (a *Authority) GetAccountByKey(p provisioner.Interface, jwk *jose.JSONWebKey) (*Account, error) {
	kid, err := keyToID(jwk)
	if err != nil {
		return nil, err
	}
	acc, err := getAccountByKeyID(a.db, kid)
	if err != nil {
		return nil, err
	}
	return acc.toACME(a.db, a.dir, p)
}

// GetOrder returns an ACME order.
func (a *Authority) GetOrder(p provisioner.Interface, accID, orderID string) (*Order, error) {
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
	return o.toACME(a.db, a.dir, p)
}

// GetOrdersByAccount returns the list of order urls owned by the account.
func (a *Authority) GetOrdersByAccount(p provisioner.Interface, id string) ([]string, error) {
	oids, err := getOrderIDsByAccount(a.db, id)
	if err != nil {
		return nil, err
	}

	var ret = []string{}
	for _, oid := range oids {
		o, err := getOrder(a.db, oid)
		if err != nil {
			return nil, ServerInternalErr(err)
		}
		if o.Status == StatusInvalid {
			continue
		}
		ret = append(ret, a.dir.getLink(OrderLink, URLSafeProvisionerName(p), true, o.ID))
	}
	return ret, nil
}

// NewOrder generates, stores, and returns a new ACME order.
func (a *Authority) NewOrder(p provisioner.Interface, ops OrderOptions) (*Order, error) {
	order, err := newOrder(a.db, ops)
	if err != nil {
		return nil, Wrap(err, "error creating order")
	}
	return order.toACME(a.db, a.dir, p)
}

// FinalizeOrder attempts to finalize an order and generate a new certificate.
func (a *Authority) FinalizeOrder(p provisioner.Interface, accID, orderID string, csr *x509.CertificateRequest) (*Order, error) {
	o, err := getOrder(a.db, orderID)
	if err != nil {
		return nil, err
	}
	if accID != o.AccountID {
		return nil, UnauthorizedErr(errors.New("account does not own order"))
	}
	o, err = o.finalize(a.db, csr, a.signAuth, p)
	if err != nil {
		return nil, Wrap(err, "error finalizing order")
	}
	return o.toACME(a.db, a.dir, p)
}

// GetAuthz retrieves and attempts to update the status on an ACME authz
// before returning.
func (a *Authority) GetAuthz(p provisioner.Interface, accID, authzID string) (*Authz, error) {
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
	return az.toACME(a.db, a.dir, p)
}

// ValidateChallenge attempts to validate the challenge.
func (a *Authority) ValidateChallenge(p provisioner.Interface, accID, chID string, jwk *jose.JSONWebKey) (*Challenge, error) {
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
	return ch.toACME(a.db, a.dir, p)
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
