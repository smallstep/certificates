package provisioner

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"

	"github.com/pkg/errors"
)

// Interface is the interface that all provisioner types must implement.
type Interface interface {
	GetID() string
	GetTokenID(token string) (string, error)
	GetName() string
	GetType() Type
	GetEncryptedKey() (kid string, key string, ok bool)
	Init(config Config) error
	AuthorizeSign(ctx context.Context, token string) ([]SignOption, error)
	AuthorizeRenewal(cert *x509.Certificate) error
	AuthorizeRevoke(token string) error
}

// Audiences stores all supported audiences by request type.
type Audiences struct {
	Sign   []string
	Revoke []string
}

// All returns all supported audiences across all request types in one list.
func (a Audiences) All() []string {
	return append(a.Sign, a.Revoke...)
}

// WithFragment returns a copy of audiences where the url audiences contains the
// given fragment.
func (a Audiences) WithFragment(fragment string) Audiences {
	ret := Audiences{
		Sign:   make([]string, len(a.Sign)),
		Revoke: make([]string, len(a.Revoke)),
	}
	for i, s := range a.Sign {
		if u, err := url.Parse(s); err == nil {
			ret.Sign[i] = u.ResolveReference(&url.URL{Fragment: fragment}).String()
		} else {
			ret.Sign[i] = s
		}
	}
	for i, s := range a.Revoke {
		if u, err := url.Parse(s); err == nil {
			ret.Revoke[i] = u.ResolveReference(&url.URL{Fragment: fragment}).String()
		} else {
			ret.Revoke[i] = s
		}
	}
	return ret
}

// generateSignAudience generates a sign audience with the format
// https://<host>/1.0/sign#provisionerID
func generateSignAudience(caURL string, provisionerID string) (string, error) {
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

	// RevokeAudienceKey is the key for the 'revoke' audiences in the audiences map.
	RevokeAudienceKey = "revoke"
	// SignAudienceKey is the key for the 'sign' audiences in the audiences map.
	SignAudienceKey = "sign"
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
	default:
		return ""
	}
}

// Config defines the default parameters used in the initialization of
// provisioners.
type Config struct {
	// Claims are the default claims.
	Claims Claims
	// Audiences are the audiences used in the default provisioner, (JWK).
	Audiences Audiences
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
			return errors.Errorf("error unmarshaling provisioner")
		}
		*l = append(*l, p)
	}

	return nil
}

var sshUserRegex = regexp.MustCompile("^[a-z][-a-z0-9_]*$")

// SanitizeSSHUserPrincipal grabs an email or a string with the format
// local@domain and returns a sanitized version of the local, valid to be used
// as a user name. If the email starts with a letter between a and z, the
// resulting string will match the regular expression `^[a-z][-a-z0-9_]*$`.
func SanitizeSSHUserPrincipal(email string) string {
	if i := strings.LastIndex(email, "@"); i >= 0 {
		email = email[:i]
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '-':
			return '-'
		case r == '.': // drop dots
			return -1
		default:
			return '_'
		}
	}, strings.ToLower(email))
}

// MockProvisioner for testing
type MockProvisioner struct {
	Mret1, Mret2, Mret3 interface{}
	Merr                error
	MgetID              func() string
	MgetTokenID         func(string) (string, error)
	MgetName            func() string
	MgetType            func() Type
	MgetEncryptedKey    func() (string, string, bool)
	Minit               func(Config) error
	MauthorizeRevoke    func(ott string) error
	MauthorizeSign      func(ctx context.Context, ott string) ([]SignOption, error)
	MauthorizeRenewal   func(*x509.Certificate) error
}

// GetID mock
func (m *MockProvisioner) GetID() string {
	if m.MgetID != nil {
		return m.MgetID()
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

// AuthorizeRevoke mock
func (m *MockProvisioner) AuthorizeRevoke(ott string) error {
	if m.MauthorizeRevoke != nil {
		return m.MauthorizeRevoke(ott)
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

// AuthorizeRenewal mock
func (m *MockProvisioner) AuthorizeRenewal(c *x509.Certificate) error {
	if m.MauthorizeRenewal != nil {
		return m.MauthorizeRenewal(c)
	}
	return m.Merr
}
