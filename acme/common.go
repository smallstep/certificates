package acme

import (
	"crypto/x509"
	"net/url"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/cli/crypto/randutil"
)

// SignAuthority is the interface implemented by a CA authority.
type SignAuthority interface {
	Sign(cr *x509.CertificateRequest, opts provisioner.Options, signOpts ...provisioner.SignOption) ([]*x509.Certificate, error)
	LoadProvisionerByID(string) (provisioner.Interface, error)
}

// Identifier encodes the type that an order pertains to.
type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

var (
	// StatusValid -- valid
	StatusValid = "valid"
	// StatusInvalid -- invalid
	StatusInvalid = "invalid"
	// StatusPending -- pending; e.g. an Order that is not ready to be finalized.
	StatusPending = "pending"
	// StatusDeactivated -- deactivated; e.g. for an Account that is not longer valid.
	StatusDeactivated = "deactivated"
	// StatusReady -- ready; e.g. for an Order that is ready to be finalized.
	StatusReady = "ready"
	//statusExpired     = "expired"
	//statusActive      = "active"
	//statusProcessing  = "processing"
)

var idLen = 32

func randID() (val string, err error) {
	val, err = randutil.Alphanumeric(idLen)
	if err != nil {
		return "", ServerInternalErr(errors.Wrap(err, "error generating random alphanumeric ID"))
	}
	return val, nil
}

// Clock that returns time in UTC rounded to seconds.
type Clock int

// Now returns the UTC time rounded to seconds.
func (c *Clock) Now() time.Time {
	return time.Now().UTC().Round(time.Second)
}

var clock = new(Clock)

// URLSafeProvisionerName returns a path escaped version of the ACME provisioner
// ID that is safe to use in URL paths.
func URLSafeProvisionerName(p provisioner.Interface) string {
	return url.PathEscape(p.GetName())
}
