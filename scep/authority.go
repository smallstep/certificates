package scep

import (
	"crypto/x509"

	"github.com/smallstep/certificates/authority/provisioner"

	"github.com/smallstep/nosql"
)

// Interface is the SCEP authority interface.
type Interface interface {
	// GetDirectory(ctx context.Context) (*Directory, error)
	// NewNonce() (string, error)
	// UseNonce(string) error

	// DeactivateAccount(ctx context.Context, accID string) (*Account, error)
	// GetAccount(ctx context.Context, accID string) (*Account, error)
	// GetAccountByKey(ctx context.Context, key *jose.JSONWebKey) (*Account, error)
	// NewAccount(ctx context.Context, ao AccountOptions) (*Account, error)
	// UpdateAccount(context.Context, string, []string) (*Account, error)

	// GetAuthz(ctx context.Context, accID string, authzID string) (*Authz, error)
	// ValidateChallenge(ctx context.Context, accID string, chID string, key *jose.JSONWebKey) (*Challenge, error)

	// FinalizeOrder(ctx context.Context, accID string, orderID string, csr *x509.CertificateRequest) (*Order, error)
	// GetOrder(ctx context.Context, accID string, orderID string) (*Order, error)
	// GetOrdersByAccount(ctx context.Context, accID string) ([]string, error)
	// NewOrder(ctx context.Context, oo OrderOptions) (*Order, error)

	// GetCertificate(string, string) ([]byte, error)

	LoadProvisionerByID(string) (provisioner.Interface, error)
	// GetLink(ctx context.Context, linkType Link, absoluteLink bool, inputs ...string) string
	// GetLinkExplicit(linkType Link, provName string, absoluteLink bool, baseURL *url.URL, inputs ...string) string

	GetCACerts() ([]*x509.Certificate, error)
}

// Authority is the layer that handles all SCEP interactions.
type Authority struct {
	//certificates []*x509.Certificate
	//authConfig   authority.AuthConfig
	backdate provisioner.Duration
	db       nosql.DB
	// dir      *directory
	signAuth SignAuthority
}

// AuthorityOptions required to create a new SCEP Authority.
type AuthorityOptions struct {
	Certificates []*x509.Certificate
	//AuthConfig authority.AuthConfig
	Backdate provisioner.Duration
	// DB is the database used by nosql.
	DB nosql.DB
	// DNS the host used to generate accurate SCEP links. By default the authority
	// will use the Host from the request, so this value will only be used if
	// request.Host is empty.
	DNS string
	// Prefix is a URL path prefix under which the SCEP api is served. This
	// prefix is required to generate accurate SCEP links.
	Prefix string
}

// SignAuthority is the interface implemented by a CA authority.
type SignAuthority interface {
	Sign(cr *x509.CertificateRequest, opts provisioner.SignOptions, signOpts ...provisioner.SignOption) ([]*x509.Certificate, error)
	LoadProvisionerByID(string) (provisioner.Interface, error)
}

// LoadProvisionerByID calls out to the SignAuthority interface to load a
// provisioner by ID.
func (a *Authority) LoadProvisionerByID(id string) (provisioner.Interface, error) {
	return a.signAuth.LoadProvisionerByID(id)
}

func (a *Authority) GetCACerts() ([]*x509.Certificate, error) {

	// TODO: implement the SCEP authority

	return []*x509.Certificate{}, nil
}

// Interface guards
var (
	_ Interface = (*Authority)(nil)
)
