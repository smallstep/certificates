package acme

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
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
	ordinal int
)

// Ordinal is used during challenge retries to indicate ownership.
func init() {
	ordstr := os.Getenv("STEP_CA_ORDINAL");
	if ordstr == "" {
		ordinal = 0
	} else {
		ord, err := strconv.Atoi(ordstr)
		if err != nil {
			log.Fatal("Unrecognized ordinal ingeter value.")
			panic(nil)
		}
		ordinal = ord
	}
}

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

// The challenge validation state machine looks like:
//
// * https://tools.ietf.org/html/rfc8555#section-7.1.6
//
// While in the processing state, the server may retry as it sees fit. The challenge validation strategy
// needs to be rather specific in order for retries to work in a replicated, crash-proof deployment.
// In general, the goal is to allow requests to hit arbitrary instances of step-ca while managing retry
// responsibility such that multiple instances agree on an owner. Additionally, when a deployment of the
// CA is in progress, the ownership should be carried forward and new, updated (or in general, restarted),
// instances should pick back up where the crashed instance left off.
//
// The steps are:
//
// 1. Upon incoming request to the challenge endpoint, take ownership of the retry responsibility.
//  (a) Set Retry.Owner to this instance's ordinal (STEP_CA_ORDINAL).
//  (b) Set Retry.NumAttempts to 0 and Retry.MaxAttempts to the desired max.
//  (c) Set Challenge.Status to "processing"
//  (d) Set retry_after to a time (retryInterval) in the future.
// 2. Perform the validation attempt.
// 3. If the validation attempt results in a challenge that is still processing, schedule a retry.
//
// It's possible that another request to re-attempt the challenge comes in while a retry attempt is
// pending from a previous request. In general, these old attempts will see that Retry.NextAttempt
// is in the future and drop their task. But this also might have happened on another instance, etc.
//
// 4. When the retry timer fires, check to make sure the retry should still process.
//  (a) Refresh the challenge from the DB.
//  (a) Check that Retry.Owner is equal to this instance's ordinal.
//  (b) Check that Retry.NextAttempt is in the past.
// 5. If the retry will commence, immediately update Retry.NextAttempt and save the challenge.
//
// Finally, if this instance is terminated, retries need to be reschedule when the instance restarts. This
// is handled in the acme provisioner (authority/provisioner/acme.go) initialization.
//
// Note: the default ordinal does not need to be changed unless step-ca is running in a replicated scenario.
//
func (a *Authority) ValidateChallenge(p provisioner.Interface, accID, chID string, jwk *jose.JSONWebKey) (*Challenge, error) {
	ch, err := getChallenge(a.db, chID)

	// Validate the challenge belongs to the account owned by the requester.
	if err != nil {
		return nil, err
	}
	if accID != ch.getAccountID() {
		return nil, UnauthorizedErr(errors.New("account does not own challenge"))
	}

	// Take ownership of the challenge status and retry state. The values must be reset.
	up := ch.clone()
	up.Status = StatusProcessing
	up.Retry = &Retry {
		Owner: ordinal,
		ProvisionerID: p.GetID(),
		NumAttempts: 0,
		MaxAttempts: 10,
		NextAttempt: time.Now().Add(retryInterval).UTC().Format(time.RFC3339),

	}
	err = up.save(a.db, ch)
	if err != nil {
		return nil, Wrap(err, "error saving challenge")
	}
	ch = up

	v, err := a.validate(ch, jwk)
	// An error here is non-recoverable. Recoverable errors are set on the challenge object
	// and should not be returned directly.
	if err != nil {
		return nil, Wrap(err, "error attempting challenge validation")
	}
	err = v.save(a.db, ch)
	if err != nil {
		return nil, Wrap(err, "error saving challenge")
	}
	ch = v

	switch ch.getStatus() {
	case StatusValid, StatusInvalid:
		break
	case StatusProcessing:
		if ch.getRetry().Active() {
			time.AfterFunc(retryInterval, func() {
				a.RetryChallenge(ch.getID())
			})
		}
	default:
		panic("post-validation challenge in unexpected state" + ch.getStatus())
	}
	return ch.toACME(a.dir, p)
}

// The challenge validation process is specific to the type of challenge (dns-01, http-01, tls-alpn-01).
// But, we still pass generic "options" to the polymorphic validate call.
func (a *Authority) validate(ch challenge, jwk *jose.JSONWebKey) (challenge, error) {
	client := http.Client{
		Timeout: time.Duration(30 * time.Second),
	}
	dialer := &net.Dialer{
		Timeout: 30 * time.Second,
	}
	return ch.validate(jwk, validateOptions{
		httpGet:   client.Get,
		lookupTxt: net.LookupTXT,
		tlsDial: func(network, addr string, config *tls.Config) (*tls.Conn, error) {
			return tls.DialWithDialer(dialer, network, addr, config)
		},
	})
}


const retryInterval = 12 * time.Second

// see: ValidateChallenge
func (a *Authority) RetryChallenge(chID string) {
	ch, err := getChallenge(a.db, chID)
	if err != nil {
		return
	}
	switch ch.getStatus() {
	case StatusPending:
		panic("pending challenges must first be moved to the processing state")
	case StatusInvalid, StatusValid:
		return
	case StatusProcessing:
		break
	default:
		panic("unknown challenge state: " + ch.getStatus())
	}

	// When retrying, check to make sure the ordinal has not changed.
	// Make sure there are still retries left.
	// Then check to make sure Retry.NextAttempt is in the past.
	retry := ch.getRetry()
	switch {
	case retry.Owner != ordinal:
		return
	case !retry.Active():
		return
	}
	t, err := time.Parse(time.RFC3339, retry.NextAttempt)
	now := time.Now().UTC()
	switch {
	case err != nil:
		return
	case t.Before(now):
		return
	}

	// Update the db so that other retries simply drop when their timer fires.
	up := ch.clone()
	up.Retry.NextAttempt = now.Add(retryInterval).UTC().Format(time.RFC3339)
	up.Retry.NumAttempts += 1
	err = up.save(a.db, ch)
	if err != nil {
		return
	}
	ch = up

	p, err := a.LoadProvisionerByID(retry.ProvisionerID)
	acc, err := a.GetAccount(p, ch.getAccountID())

	v, err := a.validate(up, acc.Key)
	if err != nil {
		return
	}
	err = v.save(a.db, ch)
	if err != nil {
		return
	}
	ch = v

	switch ch.getStatus() {
	case StatusValid, StatusInvalid:
		break
	case StatusProcessing:
		if ch.getRetry().Active() {
			time.AfterFunc(retryInterval, func() {
				a.RetryChallenge(ch.getID())
			})
		}
	default:
		panic("post-validation challenge in unexpected state " + ch.getStatus())
	}
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

