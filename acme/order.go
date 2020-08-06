package acme

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/nosql"
	"go.step.sm/crypto/x509util"
)

var defaultOrderExpiry = time.Hour * 24

// Order contains order metadata for the ACME protocol order type.
type Order struct {
	Status         string       `json:"status"`
	Expires        string       `json:"expires,omitempty"`
	Identifiers    []Identifier `json:"identifiers"`
	NotBefore      string       `json:"notBefore,omitempty"`
	NotAfter       string       `json:"notAfter,omitempty"`
	Error          interface{}  `json:"error,omitempty"`
	Authorizations []string     `json:"authorizations"`
	Finalize       string       `json:"finalize"`
	Certificate    string       `json:"certificate,omitempty"`
	ID             string       `json:"-"`
}

// ToLog enables response logging.
func (o *Order) ToLog() (interface{}, error) {
	b, err := json.Marshal(o)
	if err != nil {
		return nil, ServerInternalErr(errors.Wrap(err, "error marshaling order for logging"))
	}
	return string(b), nil
}

// GetID returns the Order ID.
func (o *Order) GetID() string {
	return o.ID
}

// OrderOptions options with which to create a new Order.
type OrderOptions struct {
	AccountID       string       `json:"accID"`
	Identifiers     []Identifier `json:"identifiers"`
	NotBefore       time.Time    `json:"notBefore"`
	NotAfter        time.Time    `json:"notAfter"`
	backdate        time.Duration
	defaultDuration time.Duration
}

type order struct {
	ID             string       `json:"id"`
	AccountID      string       `json:"accountID"`
	Created        time.Time    `json:"created"`
	Expires        time.Time    `json:"expires,omitempty"`
	Status         string       `json:"status"`
	Identifiers    []Identifier `json:"identifiers"`
	NotBefore      time.Time    `json:"notBefore,omitempty"`
	NotAfter       time.Time    `json:"notAfter,omitempty"`
	Error          *Error       `json:"error,omitempty"`
	Authorizations []string     `json:"authorizations"`
	Certificate    string       `json:"certificate,omitempty"`
}

// newOrder returns a new Order type.
func newOrder(db nosql.DB, ops OrderOptions) (*order, error) {
	id, err := randID()
	if err != nil {
		return nil, err
	}

	authzs := make([]string, len(ops.Identifiers))
	for i, identifier := range ops.Identifiers {
		az, err := newAuthz(db, ops.AccountID, identifier)
		if err != nil {
			return nil, err
		}
		authzs[i] = az.getID()
	}

	now := clock.Now()
	var backdate time.Duration
	nbf := ops.NotBefore
	if nbf.IsZero() {
		nbf = now
		backdate = -1 * ops.backdate
	}
	naf := ops.NotAfter
	if naf.IsZero() {
		naf = nbf.Add(ops.defaultDuration)
	}

	o := &order{
		ID:             id,
		AccountID:      ops.AccountID,
		Created:        now,
		Status:         StatusPending,
		Expires:        now.Add(defaultOrderExpiry),
		Identifiers:    ops.Identifiers,
		NotBefore:      nbf.Add(backdate),
		NotAfter:       naf,
		Authorizations: authzs,
	}
	if err := o.save(db, nil); err != nil {
		return nil, err
	}

	// Update the "order IDs by account ID" index //
	oids, err := getOrderIDsByAccount(db, ops.AccountID)
	if err != nil {
		return nil, err
	}
	newOids := append(oids, o.ID)
	if err = orderIDs(newOids).save(db, oids, o.AccountID); err != nil {
		db.Del(orderTable, []byte(o.ID))
		return nil, err
	}
	return o, nil
}

type orderIDs []string

// save is used to update the list of orderIDs keyed by ACME account ID
// stored in the database.
//
// This method always converts empty lists to 'nil' when storing to the DB. We
// do this to avoid any confusion between an empty list and a nil value in the
// db.
func (oids orderIDs) save(db nosql.DB, old orderIDs, accID string) error {
	var (
		err  error
		oldb []byte
		newb []byte
	)
	if len(old) == 0 {
		oldb = nil
	} else {
		oldb, err = json.Marshal(old)
		if err != nil {
			return ServerInternalErr(errors.Wrap(err, "error marshaling old order IDs slice"))
		}
	}
	if len(oids) == 0 {
		newb = nil
	} else {
		newb, err = json.Marshal(oids)
		if err != nil {
			return ServerInternalErr(errors.Wrap(err, "error marshaling new order IDs slice"))
		}
	}
	_, swapped, err := db.CmpAndSwap(ordersByAccountIDTable, []byte(accID), oldb, newb)
	switch {
	case err != nil:
		return ServerInternalErr(errors.Wrapf(err, "error storing order IDs for account %s", accID))
	case !swapped:
		return ServerInternalErr(errors.Errorf("error storing order IDs "+
			"for account %s; order IDs changed since last read", accID))
	default:
		return nil
	}
}

func (o *order) save(db nosql.DB, old *order) error {
	var (
		err  error
		oldB []byte
	)
	if old == nil {
		oldB = nil
	} else {
		if oldB, err = json.Marshal(old); err != nil {
			return ServerInternalErr(errors.Wrap(err, "error marshaling old acme order"))
		}
	}

	newB, err := json.Marshal(o)
	if err != nil {
		return ServerInternalErr(errors.Wrap(err, "error marshaling new acme order"))
	}

	_, swapped, err := db.CmpAndSwap(orderTable, []byte(o.ID), oldB, newB)
	switch {
	case err != nil:
		return ServerInternalErr(errors.Wrap(err, "error storing order"))
	case !swapped:
		return ServerInternalErr(errors.New("error storing order; " +
			"value has changed since last read"))
	default:
		return nil
	}
}

// updateStatus updates order status if necessary.
func (o *order) updateStatus(db nosql.DB) (*order, error) {
	_newOrder := *o
	newOrder := &_newOrder

	now := time.Now().UTC()
	switch o.Status {
	case StatusInvalid:
		return o, nil
	case StatusValid:
		return o, nil
	case StatusReady:
		// check expiry
		if now.After(o.Expires) {
			newOrder.Status = StatusInvalid
			newOrder.Error = MalformedErr(errors.New("order has expired"))
			break
		}
		return o, nil
	case StatusPending:
		// check expiry
		if now.After(o.Expires) {
			newOrder.Status = StatusInvalid
			newOrder.Error = MalformedErr(errors.New("order has expired"))
			break
		}

		var count = map[string]int{
			StatusValid:   0,
			StatusInvalid: 0,
			StatusPending: 0,
		}
		for _, azID := range o.Authorizations {
			az, err := getAuthz(db, azID)
			if err != nil {
				return nil, err
			}
			if az, err = az.updateStatus(db); err != nil {
				return nil, err
			}
			st := az.getStatus()
			count[st]++
		}
		switch {
		case count[StatusInvalid] > 0:
			newOrder.Status = StatusInvalid

		// No change in the order status, so just return the order as is -
		// without writing any changes.
		case count[StatusPending] > 0:
			return newOrder, nil

		case count[StatusValid] == len(o.Authorizations):
			newOrder.Status = StatusReady

		default:
			return nil, ServerInternalErr(errors.New("unexpected authz status"))
		}
	default:
		return nil, ServerInternalErr(errors.Errorf("unrecognized order status: %s", o.Status))
	}

	if err := newOrder.save(db, o); err != nil {
		return nil, err
	}
	return newOrder, nil
}

// finalize signs a certificate if the necessary conditions for Order completion
// have been met.
func (o *order) finalize(db nosql.DB, csr *x509.CertificateRequest, auth SignAuthority, p Provisioner) (*order, error) {
	var err error
	if o, err = o.updateStatus(db); err != nil {
		return nil, err
	}
	switch o.Status {
	case StatusInvalid:
		return nil, OrderNotReadyErr(errors.Errorf("order %s has been abandoned", o.ID))
	case StatusValid:
		return o, nil
	case StatusPending:
		return nil, OrderNotReadyErr(errors.Errorf("order %s is not ready", o.ID))
	case StatusReady:
		break
	default:
		return nil, ServerInternalErr(errors.Errorf("unexpected status %s for order %s", o.Status, o.ID))
	}

	// RFC8555: The CSR MUST indicate the exact same set of requested
	// identifiers as the initial newOrder request. Identifiers of type "dns"
	// MUST appear either in the commonName portion of the requested subject
	// name or in an extensionRequest attribute [RFC2985] requesting a
	// subjectAltName extension, or both.
	if csr.Subject.CommonName != "" {
		csr.DNSNames = append(csr.DNSNames, csr.Subject.CommonName)
	}
	csr.DNSNames = uniqueLowerNames(csr.DNSNames)
	orderNames := make([]string, len(o.Identifiers))
	for i, n := range o.Identifiers {
		orderNames[i] = n.Value
	}
	orderNames = uniqueLowerNames(orderNames)

	// Validate identifier names against CSR alternative names.
	//
	// Note that with certificate templates we are not going to check for the
	// absence of other SANs as they will only be set if the templates allows
	// them.
	if len(csr.DNSNames) != len(orderNames) {
		return nil, BadCSRErr(errors.Errorf("CSR names do not match identifiers exactly: CSR names = %v, Order names = %v", csr.DNSNames, orderNames))
	}

	sans := make([]x509util.SubjectAlternativeName, len(csr.DNSNames))
	for i := range csr.DNSNames {
		if csr.DNSNames[i] != orderNames[i] {
			return nil, BadCSRErr(errors.Errorf("CSR names do not match identifiers exactly: CSR names = %v, Order names = %v", csr.DNSNames, orderNames))
		}
		sans[i] = x509util.SubjectAlternativeName{
			Type:  x509util.DNSType,
			Value: csr.DNSNames[i],
		}
	}

	// Get authorizations from the ACME provisioner.
	ctx := provisioner.NewContextWithMethod(context.Background(), provisioner.SignMethod)
	signOps, err := p.AuthorizeSign(ctx, "")
	if err != nil {
		return nil, ServerInternalErr(errors.Wrapf(err, "error retrieving authorization options from ACME provisioner"))
	}

	// Template data
	data := x509util.NewTemplateData()
	data.SetCommonName(csr.Subject.CommonName)
	data.Set(x509util.SANsKey, sans)

	templateOptions, err := provisioner.TemplateOptions(p.GetOptions(), data)
	if err != nil {
		return nil, ServerInternalErr(errors.Wrapf(err, "error creating template options from ACME provisioner"))
	}
	signOps = append(signOps, templateOptions)

	// Create and store a new certificate.
	certChain, err := auth.Sign(csr, provisioner.SignOptions{
		NotBefore: provisioner.NewTimeDuration(o.NotBefore),
		NotAfter:  provisioner.NewTimeDuration(o.NotAfter),
	}, signOps...)
	if err != nil {
		return nil, ServerInternalErr(errors.Wrapf(err, "error generating certificate for order %s", o.ID))
	}

	cert, err := newCert(db, CertOptions{
		AccountID:     o.AccountID,
		OrderID:       o.ID,
		Leaf:          certChain[0],
		Intermediates: certChain[1:],
	})
	if err != nil {
		return nil, err
	}

	_newOrder := *o
	newOrder := &_newOrder
	newOrder.Certificate = cert.ID
	newOrder.Status = StatusValid
	if err := newOrder.save(db, o); err != nil {
		return nil, err
	}
	return newOrder, nil
}

// getOrder retrieves and unmarshals an ACME Order type from the database.
func getOrder(db nosql.DB, id string) (*order, error) {
	b, err := db.Get(orderTable, []byte(id))
	if nosql.IsErrNotFound(err) {
		return nil, MalformedErr(errors.Wrapf(err, "order %s not found", id))
	} else if err != nil {
		return nil, ServerInternalErr(errors.Wrapf(err, "error loading order %s", id))
	}
	var o order
	if err := json.Unmarshal(b, &o); err != nil {
		return nil, ServerInternalErr(errors.Wrap(err, "error unmarshaling order"))
	}
	return &o, nil
}

// toACME converts the internal Order type into the public acmeOrder type for
// presentation in the ACME protocol.
func (o *order) toACME(ctx context.Context, db nosql.DB, dir *directory) (*Order, error) {
	azs := make([]string, len(o.Authorizations))
	for i, aid := range o.Authorizations {
		azs[i] = dir.getLink(ctx, AuthzLink, true, aid)
	}
	ao := &Order{
		Status:         o.Status,
		Expires:        o.Expires.Format(time.RFC3339),
		Identifiers:    o.Identifiers,
		NotBefore:      o.NotBefore.Format(time.RFC3339),
		NotAfter:       o.NotAfter.Format(time.RFC3339),
		Authorizations: azs,
		Finalize:       dir.getLink(ctx, FinalizeLink, true, o.ID),
		ID:             o.ID,
	}

	if o.Certificate != "" {
		ao.Certificate = dir.getLink(ctx, CertificateLink, true, o.Certificate)
	}
	return ao, nil
}

// uniqueLowerNames returns the set of all unique names in the input after all
// of them are lowercased. The returned names will be in their lowercased form
// and sorted alphabetically.
func uniqueLowerNames(names []string) (unique []string) {
	nameMap := make(map[string]int, len(names))
	for _, name := range names {
		nameMap[strings.ToLower(name)] = 1
	}
	unique = make([]string, 0, len(nameMap))
	for name := range nameMap {
		unique = append(unique, name)
	}
	sort.Strings(unique)
	return
}
