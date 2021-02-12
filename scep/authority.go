package scep

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"

	"github.com/smallstep/certificates/authority/provisioner"
	database "github.com/smallstep/certificates/db"
	"go.step.sm/crypto/pemutil"

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

	GetCACertificates() ([]*x509.Certificate, error)
	GetSigningKey() (*rsa.PrivateKey, error)
}

// Authority is the layer that handles all SCEP interactions.
type Authority struct {
	backdate provisioner.Duration
	db       nosql.DB
	prefix   string
	dns      string

	// dir      *directory

	intermediateCertificate *x509.Certificate
	intermediateKey         *rsa.PrivateKey

	//signer crypto.Signer

	signAuth SignAuthority
}

// AuthorityOptions required to create a new SCEP Authority.
type AuthorityOptions struct {
	IntermediateCertificatePath string
	IntermediateKeyPath         string

	// Backdate
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

// New returns a new Authority that implements the SCEP interface.
func New(signAuth SignAuthority, ops AuthorityOptions) (*Authority, error) {
	if _, ok := ops.DB.(*database.SimpleDB); !ok {
		// TODO: see ACME implementation
	}

	// TODO: the below is a bit similar as what happens in the core Authority class, which
	// creates the full x509 service. However, those aren't accessible directly, which is
	// why I reimplemented this (for now). There might be an alternative that I haven't
	// found yet.
	certificateChain, err := pemutil.ReadCertificateBundle(ops.IntermediateCertificatePath)
	if err != nil {
		return nil, err
	}

	intermediateKey, err := readPrivateKey(ops.IntermediateKeyPath)
	if err != nil {
		return nil, err
	}

	return &Authority{
		backdate:                ops.Backdate,
		db:                      ops.DB,
		prefix:                  ops.Prefix,
		dns:                     ops.DNS,
		intermediateCertificate: certificateChain[0],
		intermediateKey:         intermediateKey,
		signAuth:                signAuth,
	}, nil
}

func readPrivateKey(path string) (*rsa.PrivateKey, error) {

	keyBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode([]byte(keyBytes))
	if block == nil {
		return nil, nil
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// LoadProvisionerByID calls out to the SignAuthority interface to load a
// provisioner by ID.
func (a *Authority) LoadProvisionerByID(id string) (provisioner.Interface, error) {
	return a.signAuth.LoadProvisionerByID(id)
}

// GetCACertificates returns the certificate (chain) for the CA
func (a *Authority) GetCACertificates() ([]*x509.Certificate, error) {

	if a.intermediateCertificate == nil {
		return nil, errors.New("no intermediate certificate available in SCEP authority")
	}

	return []*x509.Certificate{a.intermediateCertificate}, nil
}

// GetSigningKey returns the RSA private key for the CA
// TODO: we likely should provide utility functions for decrypting and
// signing instead of providing the signing key directly
func (a *Authority) GetSigningKey() (*rsa.PrivateKey, error) {

	if a.intermediateKey == nil {
		return nil, errors.New("no intermediate key available in SCEP authority")
	}

	return a.intermediateKey, nil
}

// Interface guards
var (
	_ Interface = (*Authority)(nil)
)
