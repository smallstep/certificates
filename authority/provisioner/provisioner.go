package provisioner

import (
	"context"
	"crypto/x509"
	"encoding/json"
	stderrors "errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"
	kmsapi "go.step.sm/crypto/kms/apiv1"
	"golang.org/x/crypto/ssh"

	"github.com/smallstep/certificates/errs"
)

// Interface is the interface that all provisioner types must implement.
type Interface interface {
	GetID() string
	GetIDForToken() string
	GetTokenID(token string) (string, error)
	GetName() string
	GetType() Type
	GetEncryptedKey() (kid string, key string, ok bool)
	Init(config Config) error
	AuthorizeSign(ctx context.Context, token string) ([]SignOption, error)
	AuthorizeRevoke(ctx context.Context, token string) error
	AuthorizeRenew(ctx context.Context, cert *x509.Certificate) error
	AuthorizeSSHSign(ctx context.Context, token string) ([]SignOption, error)
	AuthorizeSSHRevoke(ctx context.Context, token string) error
	AuthorizeSSHRenew(ctx context.Context, token string) (*ssh.Certificate, error)
	AuthorizeSSHRekey(ctx context.Context, token string) (*ssh.Certificate, []SignOption, error)
}

// ErrAllowTokenReuse is an error that is returned by provisioners that allows
// the reuse of tokens.
//
// This is, for example, returned by the Azure provisioner when
// DisableTrustOnFirstUse is set to true. Azure caches tokens for up to 24hr and
// has no mechanism for getting a different token - this can be an issue when
// rebooting a VM. In contrast, AWS and GCP have facilities for requesting a new
// token. Therefore, for the Azure provisioner we are enabling token reuse, with
// the understanding that we are not following security best practices
var ErrAllowTokenReuse = stderrors.New("allow token reuse")

// Audiences stores all supported audiences by request type.
type Audiences struct {
	Sign      []string
	Renew     []string
	Revoke    []string
	SSHSign   []string
	SSHRevoke []string
	SSHRenew  []string
	SSHRekey  []string
}

// All returns all supported audiences across all request types in one list.
func (a Audiences) All() (auds []string) {
	auds = a.Sign
	auds = append(auds, a.Renew...)
	auds = append(auds, a.Revoke...)
	auds = append(auds, a.SSHSign...)
	auds = append(auds, a.SSHRevoke...)
	auds = append(auds, a.SSHRenew...)
	auds = append(auds, a.SSHRekey...)
	return
}

// WithFragment returns a copy of audiences where the url audiences contains the
// given fragment.
func (a Audiences) WithFragment(fragment string) Audiences {
	ret := Audiences{
		Sign:      make([]string, len(a.Sign)),
		Renew:     make([]string, len(a.Renew)),
		Revoke:    make([]string, len(a.Revoke)),
		SSHSign:   make([]string, len(a.SSHSign)),
		SSHRevoke: make([]string, len(a.SSHRevoke)),
		SSHRenew:  make([]string, len(a.SSHRenew)),
		SSHRekey:  make([]string, len(a.SSHRekey)),
	}
	for i, s := range a.Sign {
		if u, err := url.Parse(s); err == nil {
			ret.Sign[i] = u.ResolveReference(&url.URL{Fragment: fragment}).String()
		} else {
			ret.Sign[i] = s
		}
	}
	for i, s := range a.Renew {
		if u, err := url.Parse(s); err == nil {
			ret.Renew[i] = u.ResolveReference(&url.URL{Fragment: fragment}).String()
		} else {
			ret.Renew[i] = s
		}
	}
	for i, s := range a.Revoke {
		if u, err := url.Parse(s); err == nil {
			ret.Revoke[i] = u.ResolveReference(&url.URL{Fragment: fragment}).String()
		} else {
			ret.Revoke[i] = s
		}
	}
	for i, s := range a.SSHSign {
		if u, err := url.Parse(s); err == nil {
			ret.SSHSign[i] = u.ResolveReference(&url.URL{Fragment: fragment}).String()
		} else {
			ret.SSHSign[i] = s
		}
	}
	for i, s := range a.SSHRevoke {
		if u, err := url.Parse(s); err == nil {
			ret.SSHRevoke[i] = u.ResolveReference(&url.URL{Fragment: fragment}).String()
		} else {
			ret.SSHRevoke[i] = s
		}
	}
	for i, s := range a.SSHRenew {
		if u, err := url.Parse(s); err == nil {
			ret.SSHRenew[i] = u.ResolveReference(&url.URL{Fragment: fragment}).String()
		} else {
			ret.SSHRenew[i] = s
		}
	}
	for i, s := range a.SSHRekey {
		if u, err := url.Parse(s); err == nil {
			ret.SSHRekey[i] = u.ResolveReference(&url.URL{Fragment: fragment}).String()
		} else {
			ret.SSHRekey[i] = s
		}
	}
	return ret
}

// generateSignAudience generates a sign audience with the format
// https://<host>/1.0/sign#provisionerID
func generateSignAudience(caURL, provisionerID string) (string, error) {
	u, err := url.Parse(caURL)
	if err != nil {
		return "", errors.Wrapf(err, "error parsing %s", caURL)
	}
	return u.ResolveReference(&url.URL{Path: "/1.0/sign", Fragment: provisionerID}).String(), nil
}

// Type indicates the provisioner Type.
type Type int

const (
	noopType Type = 0
	// TypeJWK is used to indicate the JWK provisioners.
	TypeJWK Type = 1
	// TypeOIDC is used to indicate the OIDC provisioners.
	TypeOIDC Type = 2
	// TypeGCP is used to indicate the GCP provisioners.
	TypeGCP Type = 3
	// TypeAWS is used to indicate the AWS provisioners.
	TypeAWS Type = 4
	// TypeAzure is used to indicate the Azure provisioners.
	TypeAzure Type = 5
	// TypeACME is used to indicate the ACME provisioners.
	TypeACME Type = 6
	// TypeX5C is used to indicate the X5C provisioners.
	TypeX5C Type = 7
	// TypeK8sSA is used to indicate the X5C provisioners.
	TypeK8sSA Type = 8
	// TypeSSHPOP is used to indicate the SSHPOP provisioners.
	TypeSSHPOP Type = 9
	// TypeSCEP is used to indicate the SCEP provisioners
	TypeSCEP Type = 10
	// TypeNebula is used to indicate the Nebula provisioners
	TypeNebula Type = 11
)

// String returns the string representation of the type.
func (t Type) String() string {
	switch t {
	case TypeJWK:
		return "JWK"
	case TypeOIDC:
		return "OIDC"
	case TypeGCP:
		return "GCP"
	case TypeAWS:
		return "AWS"
	case TypeAzure:
		return "Azure"
	case TypeACME:
		return "ACME"
	case TypeX5C:
		return "X5C"
	case TypeK8sSA:
		return "K8sSA"
	case TypeSSHPOP:
		return "SSHPOP"
	case TypeSCEP:
		return "SCEP"
	case TypeNebula:
		return "Nebula"
	default:
		return ""
	}
}

// SSHKeys represents the SSH User and Host public keys.
type SSHKeys struct {
	UserKeys []ssh.PublicKey
	HostKeys []ssh.PublicKey
}

// SCEPKeyManager is a KMS interface that combines a KeyManager with a
// Decrypter.
type SCEPKeyManager interface {
	kmsapi.KeyManager
	kmsapi.Decrypter
}

// Config defines the default parameters used in the initialization of
// provisioners.
type Config struct {
	// Claims are the default claims.
	Claims Claims
	// Audiences are the audiences used in the default provisioner, (JWK).
	Audiences Audiences
	// SSHKeys are the root SSH public keys
	SSHKeys *SSHKeys
	// GetIdentityFunc is a function that returns an identity that will be
	// used by the provisioner to populate certificate attributes.
	GetIdentityFunc GetIdentityFunc
	// AuthorizeRenewFunc is a function that returns nil if a given X.509
	// certificate can be renewed.
	AuthorizeRenewFunc AuthorizeRenewFunc
	// AuthorizeSSHRenewFunc is a function that returns nil if a given SSH
	// certificate can be renewed.
	AuthorizeSSHRenewFunc AuthorizeSSHRenewFunc
	// WebhookClient is an http client to use in webhook request
	WebhookClient *http.Client
	// SCEPKeyManager, if defined, is the interface used by SCEP provisioners.
	SCEPKeyManager SCEPKeyManager
}

type provisioner struct {
	Type string `json:"type"`
}

// List represents a list of provisioners.
type List []Interface

// UnmarshalJSON implements json.Unmarshaler and allows to unmarshal a list of a
// interfaces into the right type.
func (l *List) UnmarshalJSON(data []byte) error {
	ps := []json.RawMessage{}
	if err := json.Unmarshal(data, &ps); err != nil {
		return errors.Wrap(err, "error unmarshaling provisioner list")
	}

	*l = List{}
	for _, data := range ps {
		var typ provisioner
		if err := json.Unmarshal(data, &typ); err != nil {
			return errors.Errorf("error unmarshaling provisioner")
		}
		var p Interface
		switch strings.ToLower(typ.Type) {
		case "jwk":
			p = &JWK{}
		case "oidc":
			p = &OIDC{}
		case "gcp":
			p = &GCP{}
		case "aws":
			p = &AWS{}
		case "azure":
			p = &Azure{}
		case "acme":
			p = &ACME{}
		case "x5c":
			p = &X5C{}
		case "k8ssa":
			p = &K8sSA{}
		case "sshpop":
			p = &SSHPOP{}
		case "scep":
			p = &SCEP{}
		case "nebula":
			p = &Nebula{}
		default:
			// Skip unsupported provisioners. A client using this method may be
			// compiled with a version of smallstep/certificates that does not
			// support a specific provisioner type. If we don't skip unknown
			// provisioners, a client encountering an unknown provisioner will
			// break. Rather than break the client, we skip the provisioner.
			// TODO: accept a pluggable logger (depending on client) that can
			// warn the user that an unknown provisioner was found and suggest
			// that the user update their client's dependency on
			// step/certificates and recompile.
			continue
		}
		if err := json.Unmarshal(data, p); err != nil {
			return errors.Wrap(err, "error unmarshaling provisioner")
		}
		*l = append(*l, p)
	}

	return nil
}

type base struct{}

// AuthorizeSign returns an unimplemented error. Provisioners should overwrite
// this method if they will support authorizing tokens for signing x509 Certificates.
func (b *base) AuthorizeSign(context.Context, string) ([]SignOption, error) {
	return nil, errs.Unauthorized("provisioner.AuthorizeSign not implemented")
}

// AuthorizeRevoke returns an unimplemented error. Provisioners should overwrite
// this method if they will support authorizing tokens for revoking x509 Certificates.
func (b *base) AuthorizeRevoke(context.Context, string) error {
	return errs.Unauthorized("provisioner.AuthorizeRevoke not implemented")
}

// AuthorizeRenew returns an unimplemented error. Provisioners should overwrite
// this method if they will support authorizing tokens for renewing x509 Certificates.
func (b *base) AuthorizeRenew(context.Context, *x509.Certificate) error {
	return errs.Unauthorized("provisioner.AuthorizeRenew not implemented")
}

// AuthorizeSSHSign returns an unimplemented error. Provisioners should overwrite
// this method if they will support authorizing tokens for signing SSH Certificates.
func (b *base) AuthorizeSSHSign(context.Context, string) ([]SignOption, error) {
	return nil, errs.Unauthorized("provisioner.AuthorizeSSHSign not implemented")
}

// AuthorizeSSHRevoke returns an unimplemented error. Provisioners should overwrite
// this method if they will support authorizing tokens for revoking SSH Certificates.
func (b *base) AuthorizeSSHRevoke(context.Context, string) error {
	return errs.Unauthorized("provisioner.AuthorizeSSHRevoke not implemented")
}

// AuthorizeSSHRenew returns an unimplemented error. Provisioners should overwrite
// this method if they will support authorizing tokens for renewing SSH Certificates.
func (b *base) AuthorizeSSHRenew(context.Context, string) (*ssh.Certificate, error) {
	return nil, errs.Unauthorized("provisioner.AuthorizeSSHRenew not implemented")
}

// AuthorizeSSHRekey returns an unimplemented error. Provisioners should overwrite
// this method if they will support authorizing tokens for rekeying SSH Certificates.
func (b *base) AuthorizeSSHRekey(context.Context, string) (*ssh.Certificate, []SignOption, error) {
	return nil, nil, errs.Unauthorized("provisioner.AuthorizeSSHRekey not implemented")
}

// Permissions defines extra extensions and critical options to grant to an SSH certificate.
type Permissions struct {
	Extensions      map[string]string `json:"extensions"`
	CriticalOptions map[string]string `json:"criticalOptions"`
}

// RAInfo is the information about a provisioner present in RA tokens generated
// by StepCAS.
type RAInfo struct {
	AuthorityID     string `json:"authorityId,omitempty"`
	EndpointID      string `json:"endpointId,omitempty"`
	ProvisionerID   string `json:"provisionerId,omitempty"`
	ProvisionerType string `json:"provisionerType,omitempty"`
	ProvisionerName string `json:"provisionerName,omitempty"`
}

// raProvisioner wraps a provisioner with RA data.
type raProvisioner struct {
	Interface
	raInfo *RAInfo
}

// RAInfo returns the RAInfo in the wrapped provisioner.
func (p *raProvisioner) RAInfo() *RAInfo {
	return p.raInfo
}

// MockProvisioner for testing
type MockProvisioner struct {
	Mret1, Mret2, Mret3 interface{}
	Merr                error
	MgetID              func() string
	MgetIDForToken      func() string
	MgetTokenID         func(string) (string, error)
	MgetName            func() string
	MgetType            func() Type
	MgetEncryptedKey    func() (string, string, bool)
	Minit               func(Config) error
	MauthorizeSign      func(ctx context.Context, ott string) ([]SignOption, error)
	MauthorizeRenew     func(ctx context.Context, cert *x509.Certificate) error
	MauthorizeRevoke    func(ctx context.Context, ott string) error
	MauthorizeSSHSign   func(ctx context.Context, ott string) ([]SignOption, error)
	MauthorizeSSHRenew  func(ctx context.Context, ott string) (*ssh.Certificate, error)
	MauthorizeSSHRekey  func(ctx context.Context, ott string) (*ssh.Certificate, []SignOption, error)
	MauthorizeSSHRevoke func(ctx context.Context, ott string) error
}

// GetID mock
func (m *MockProvisioner) GetID() string {
	if m.MgetID != nil {
		return m.MgetID()
	}
	return m.Mret1.(string)
}

// GetIDForToken mock
func (m *MockProvisioner) GetIDForToken() string {
	if m.MgetIDForToken != nil {
		return m.MgetIDForToken()
	}
	return m.Mret1.(string)
}

// GetTokenID mock
func (m *MockProvisioner) GetTokenID(token string) (string, error) {
	if m.MgetTokenID != nil {
		return m.MgetTokenID(token)
	}
	if m.Mret1 == nil {
		return "", m.Merr
	}
	return m.Mret1.(string), m.Merr
}

// GetName mock
func (m *MockProvisioner) GetName() string {
	if m.MgetName != nil {
		return m.MgetName()
	}
	return m.Mret1.(string)
}

// GetType mock
func (m *MockProvisioner) GetType() Type {
	if m.MgetType != nil {
		return m.MgetType()
	}
	return m.Mret1.(Type)
}

// GetEncryptedKey mock
func (m *MockProvisioner) GetEncryptedKey() (string, string, bool) {
	if m.MgetEncryptedKey != nil {
		return m.MgetEncryptedKey()
	}
	return m.Mret1.(string), m.Mret2.(string), m.Mret3.(bool)
}

// Init mock
func (m *MockProvisioner) Init(c Config) error {
	if m.Minit != nil {
		return m.Minit(c)
	}
	return m.Merr
}

// AuthorizeSign mock
func (m *MockProvisioner) AuthorizeSign(ctx context.Context, ott string) ([]SignOption, error) {
	if m.MauthorizeSign != nil {
		return m.MauthorizeSign(ctx, ott)
	}
	return m.Mret1.([]SignOption), m.Merr
}

// AuthorizeRevoke mock
func (m *MockProvisioner) AuthorizeRevoke(ctx context.Context, ott string) error {
	if m.MauthorizeRevoke != nil {
		return m.MauthorizeRevoke(ctx, ott)
	}
	return m.Merr
}

// AuthorizeRenew mock
func (m *MockProvisioner) AuthorizeRenew(ctx context.Context, c *x509.Certificate) error {
	if m.MauthorizeRenew != nil {
		return m.MauthorizeRenew(ctx, c)
	}
	return m.Merr
}

// AuthorizeSSHSign mock
func (m *MockProvisioner) AuthorizeSSHSign(ctx context.Context, ott string) ([]SignOption, error) {
	if m.MauthorizeSign != nil {
		return m.MauthorizeSign(ctx, ott)
	}
	return m.Mret1.([]SignOption), m.Merr
}

// AuthorizeSSHRenew mock
func (m *MockProvisioner) AuthorizeSSHRenew(ctx context.Context, ott string) (*ssh.Certificate, error) {
	if m.MauthorizeRenew != nil {
		return m.MauthorizeSSHRenew(ctx, ott)
	}
	return m.Mret1.(*ssh.Certificate), m.Merr
}

// AuthorizeSSHRekey mock
func (m *MockProvisioner) AuthorizeSSHRekey(ctx context.Context, ott string) (*ssh.Certificate, []SignOption, error) {
	if m.MauthorizeSSHRekey != nil {
		return m.MauthorizeSSHRekey(ctx, ott)
	}
	return m.Mret1.(*ssh.Certificate), m.Mret2.([]SignOption), m.Merr
}

// AuthorizeSSHRevoke mock
func (m *MockProvisioner) AuthorizeSSHRevoke(ctx context.Context, ott string) error {
	if m.MauthorizeSSHRevoke != nil {
		return m.MauthorizeSSHRevoke(ctx, ott)
	}
	return m.Merr
}
