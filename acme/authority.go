package acme

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"log"
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
	db       nosql.DB
	dir      *directory
	signAuth SignAuthority
	ordinal  int
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
func NewAuthority(db nosql.DB, dns, prefix string, signAuth SignAuthority, ordinal int) (*Authority, error) {
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
		db: db, dir: newDirectory(dns, prefix), signAuth: signAuth, ordinal: ordinal,
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
		o, err := getOrder(a.db, oid)
		if err != nil {
			return nil, ServerInternalErr(err)
		}
		if o.Status == StatusInvalid {
			continue
		}
		ret = append(ret, a.dir.getLink(ctx, OrderLink, true, o.ID))
	}
	return ret, nil
}

// NewOrder generates, stores, and returns a new ACME order.
func (a *Authority) NewOrder(ctx context.Context, ops OrderOptions) (*Order, error) {
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

// ValidateChallenge loads a challenge resource and then begins the validation process if the challenge
// is not in one of its terminal states {valid|invalid}.
//
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
// is in the future and drop their task. Because another instance may have taken ownership, old attempts
// would also see a different ordinal than their own.
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
func (a *Authority) ValidateChallenge(ctx context.Context, accID, chID string, jwk *jose.JSONWebKey) (*Challenge, error) {
	ch, err := getChallenge(a.db, chID)
	if err != nil {
		return nil, err
	}
	switch ch.getStatus() {
	case StatusPending, StatusProcessing:
		break
	case StatusInvalid, StatusValid:
		return ch.toACME(ctx, a.dir)
	default:
		e := errors.Errorf("unknown challenge state: %s", ch.getStatus())
		return nil, ServerInternalErr(e)
	}

	// Validate the challenge belongs to the account owned by the requester.
	if accID != ch.getAccountID() {
		return nil, UnauthorizedErr(errors.New("account does not own challenge"))
	}

	p, err := ProvisionerFromContext(ctx)
	if err != nil {
		return nil, err
	}

	// Take ownership of the challenge status and retry state. The values must be reset.
	up := ch.clone()
	up.Status = StatusProcessing
	up.Retry = &Retry{
		Owner:         a.ordinal,
		ProvisionerID: p.GetID(),
		NumAttempts:   0,
		MaxAttempts:   10,
		NextAttempt:   time.Now().Add(retryInterval).UTC().Format(time.RFC3339),
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
		e := errors.Errorf("post-validation challenge in unexpected state, %s", ch.getStatus())
		return nil, ServerInternalErr(e)
	}
	return ch.toACME(ctx, a.dir)
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
	return ch.clone().morph().validate(jwk, validateOptions{
		httpGet:   client.Get,
		lookupTxt: net.LookupTXT,
		tlsDial: func(network, addr string, config *tls.Config) (*tls.Conn, error) {
			return tls.DialWithDialer(dialer, network, addr, config)
		},
	})
}

const retryInterval = 12 * time.Second

// RetryChallenge behaves similar to ValidateChallenge, but simply attempts to perform a validation and
// write update the challenge record in the db if the challenge has remaining retry attempts.
//
// see: ValidateChallenge
func (a *Authority) RetryChallenge(chID string) {
	ch, err := getChallenge(a.db, chID)
	if err != nil {
		return
	}
	switch ch.getStatus() {
	case StatusPending:
		e := errors.New("pending challenges must first be moved to the processing state")
		log.Printf("%v", e)
		return
	case StatusInvalid, StatusValid:
		return
	case StatusProcessing:
		break
	default:
		e := errors.Errorf("unknown challenge state: %s", ch.getStatus())
		log.Printf("%v", e)
		return
	}

	// When retrying, check to make sure the ordinal has not changed.
	// Make sure there are still retries left.
	// Then check to make sure Retry.NextAttempt is in the past.
	retry := ch.getRetry()
	switch {
	case retry.Owner != a.ordinal:
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
	up.Retry.NumAttempts++
	err = up.save(a.db, ch)
	if err != nil {
		return
	}
	ch = up

	p, err := a.LoadProvisionerByID(retry.ProvisionerID)
	if err != nil {
		return
	}
	if p.GetType() != provisioner.TypeACME {
		log.Printf("%v", AccountDoesNotExistErr(errors.New("provisioner must be of type ACME")))
		return
	}
	ctx := context.WithValue(context.Background(), ProvisionerContextKey, p)
	acc, err := a.GetAccount(ctx, ch.getAccountID())
	if err != nil {
		return
	}

	v, err := a.validate(ch, acc.Key)
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
		e := errors.Errorf("post-validation challenge in unexpected state, %s", ch.getStatus())
		log.Printf("%v", e)
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
