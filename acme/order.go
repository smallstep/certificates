
import (
	"context"
	"crypto/x509"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/provisioner"
	"go.step.sm/crypto/x509util"
)

// Order contains order metadata for the ACME protocol order type.
type Order struct {
	Status          string        `json:"status"`
	Expires         string        `json:"expires,omitempty"`
	Identifiers     []Identifier  `json:"identifiers"`
	NotBefore       string        `json:"notBefore,omitempty"`
	NotAfter        string        `json:"notAfter,omitempty"`
	Error           interface{}   `json:"error,omitempty"`
	Authorizations  []string      `json:"authorizations"`
	Finalize        string        `json:"finalize"`
	Certificate     string        `json:"certificate,omitempty"`
	ID              string        `json:"-"`
	ProvisionerID   string        `json:"-"`
	DefaultDuration time.Duration `json:"-"`
	Backdate        time.Duration `json:"-"`
}

// ToLog enables response logging.
func (o *Order) ToLog() (interface{}, error) {
	b, err := json.Marshal(o)
	if err != nil {
		return nil, ServerInternalErr(errors.Wrap(err, "error marshaling order for logging"))
	}
	return string(b), nil
}

// UpdateStatus updates the ACME Order Status if necessary.
// Changes to the order are saved using the database interface.
func (o *Order) UpdateStatus(ctx context.Context, db DB) error {
	now := time.Now().UTC()
	expiry, err := time.Parse(time.RFC3339, o.Expires)
	if err != nil {
		return ServerInternalErr(errors.Wrap("error converting expiry string to time"))
	}

	switch o.Status {
	case StatusInvalid:
		return nil
	case StatusValid:
		return nil
	case StatusReady:
		// Check expiry
		if now.After(expiry) {
			o.Status = StatusInvalid
			o.Error = MalformedErr(errors.New("order has expired"))
			break
		}
		return nil
	case StatusPending:
		// Check expiry
		if now.After(expiry) {
			o.Status = StatusInvalid
			o.Error = MalformedErr(errors.New("order has expired"))
			break
		}

		var count = map[string]int{
			StatusValid:   0,
			StatusInvalid: 0,
			StatusPending: 0,
		}
		for _, azID := range o.Authorizations {
			az, err := db.GetAuthorization(ctx, azID)
			if err != nil {
				return false, err
			}
			if az, err = az.UpdateStatus(db); err != nil {
				return false, err
			}
			st := az.Status
			count[st]++
		}
		switch {
		case count[StatusInvalid] > 0:
			o.Status = StatusInvalid

		// No change in the order status, so just return the order as is -
		// without writing any changes.
		case count[StatusPending] > 0:
			return nil

		case count[StatusValid] == len(o.Authorizations):
			o.Status = StatusReady

		default:
			return nil, ServerInternalErr(errors.New("unexpected authz status"))
		}
	default:
		return nil, ServerInternalErr(errors.Errorf("unrecognized order status: %s", o.Status))
	}
	return db.UpdateOrder(ctx, o)
}

// finalize signs a certificate if the necessary conditions for Order completion
// have been met.
func (o *order) Finalize(ctx, db DB, csr *x509.CertificateRequest, auth SignAuthority, p Provisioner) error {
	var err error
	if o, err = o.UpdateStatus(db); err != nil {
		return nil, err
	}

	switch o.Status {
	case StatusInvalid:
		return OrderNotReadyErr(errors.Errorf("order %s has been abandoned", o.ID))
	case StatusValid:
		return nil
	case StatusPending:
		return OrderNotReadyErr(errors.Errorf("order %s is not ready", o.ID))
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
	orderNames = uniqueSortedLowerNames(orderNames)

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

	o.Certificate = cert.ID
	o.Status = StatusValid
	return db.UpdateOrder(ctx, o)
}

// uniqueSortedLowerNames returns the set of all unique names in the input after all
// of them are lowercased. The returned names will be in their lowercased form
// and sorted alphabetically.
func uniqueSortedLowerNames(names []string) (unique []string) {
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
