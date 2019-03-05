package provisioner

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/jose"
)

type openIDConfiguration struct {
	Issuer    string `json:"issuer"`
	JWKSetURI string `json:"jwks_uri"`
}

// openIDPayload represents the fields on the id_token JWT payload.
type openIDPayload struct {
	jose.Claims
	AtHash          string `json:"at_hash"`
	AuthorizedParty string `json:"azp"`
	Email           string `json:"email"`
	EmailVerified   string `json:"email_verified"`
	Hd              string `json:"hd"`
	Nonce           string `json:"nonce"`
}

// OIDC represents an OAuth 2.0 OpenID Connect provider.
type OIDC struct {
	Type                  string   `json:"type"`
	Name                  string   `json:"name"`
	ClientID              string   `json:"clientID"`
	ConfigurationEndpoint string   `json:"configurationEndpoint"`
	Claims                *Claims  `json:"claims,omitempty"`
	Admins                []string `json:"admins"`
	configuration         openIDConfiguration
	keyStore              *keyStore
}

// IsAdmin returns true if the given email is in the Admins whitelist, false
// otherwise.
func (o *OIDC) IsAdmin(email string) bool {
	for _, e := range o.Admins {
		if e == email {
			return true
		}
	}
	return false
}

// Validate validates and initializes the OIDC provider.
func (o *OIDC) Validate() error {
	switch {
	case o.Name == "":
		return errors.New("name cannot be empty")
	case o.ClientID == "":
		return errors.New("clientID cannot be empty")
	case o.ConfigurationEndpoint == "":
		return errors.New("configurationEndpoint cannot be empty")
	}

	// Decode openid-configuration endpoint
	var conf openIDConfiguration
	if err := getAndDecode(o.ConfigurationEndpoint, &conf); err != nil {
		return err
	}
	if conf.JWKSetURI == "" {
		return errors.Errorf("error parsing %s: jwks_uri cannot be empty", o.ConfigurationEndpoint)
	}
	// Get JWK key set
	keyStore, err := newKeyStore(conf.JWKSetURI)
	if err != nil {
		return err
	}
	o.configuration = conf
	o.keyStore = keyStore
	return nil
}

// ValidatePayload validates the given token payload.
//
// TODO(mariano): avoid reply attacks validating nonce.
func (o *OIDC) ValidatePayload(p openIDPayload) error {
	// According to "rfc7519 JSON Web Token" acceptable skew should be no more
	// than a few minutes.
	if err := p.ValidateWithLeeway(jose.Expected{
		Issuer:   o.configuration.Issuer,
		Audience: jose.Audience{o.ClientID},
	}, time.Minute); err != nil {
		return errors.Wrap(err, "failed to validate payload")
	}
	if p.AuthorizedParty != "" && p.AuthorizedParty != o.ClientID {
		return errors.New("failed to validate payload: invalid azp")
	}
	return nil
}

// Authorize validates the given token.
func (o *OIDC) Authorize(token string) ([]SignOption, error) {
	jwt, err := jose.ParseSigned(token)
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing token")
	}

	var claims openIDPayload
	// Parse claims to get the kid
	if err := jwt.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, errors.Wrap(err, "error parsing claims")
	}

	found := false
	kid := jwt.Headers[0].KeyID
	keys := o.keyStore.Get(kid)
	for _, key := range keys {
		if err := jwt.Claims(key, &claims); err == nil {
			found = true
			break
		}
	}
	if !found {
		return nil, errors.New("cannot validate token")
	}

	if err := o.ValidatePayload(claims); err != nil {
		return nil, err
	}

	if o.IsAdmin(claims.Email) {
		return []SignOption{}, nil
	}

	return []SignOption{
		emailOnlyIdentity(claims.Email),
	}, nil
}

func getAndDecode(uri string, v interface{}) error {
	resp, err := http.Get(uri)
	if err != nil {
		return errors.Wrapf(err, "failed to connect to %s", uri)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		return errors.Wrapf(err, "error reading %s", uri)
	}
	return nil
}
