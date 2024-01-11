package wire

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"text/template"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

type Provider struct {
	IssuerURL   string   `json:"issuer,omitempty"`
	AuthURL     string   `json:"authorization_endpoint,omitempty"`
	TokenURL    string   `json:"token_endpoint,omitempty"`
	JWKSURL     string   `json:"jwks_uri,omitempty"`
	UserInfoURL string   `json:"userinfo_endpoint,omitempty"`
	Algorithms  []string `json:"id_token_signing_alg_values_supported,omitempty"`
}

type Config struct {
	ClientID                   string           `json:"client_id,omitempty"`
	SupportedSigningAlgs       []string         `json:"supported_signing_algs,omitempty"`
	SkipClientIDCheck          bool             `json:"-"`
	SkipExpiryCheck            bool             `json:"-"`
	SkipIssuerCheck            bool             `json:"-"`
	Now                        func() time.Time `json:"-"`
	InsecureSkipSignatureCheck bool             `json:"-"`
}

type OIDCOptions struct {
	Provider *Provider `json:"provider,omitempty"`
	Config   *Config   `json:"config,omitempty"`
}

func (o *OIDCOptions) GetProvider(ctx context.Context) *oidc.Provider {
	if o == nil || o.Provider == nil {
		return nil
	}
	return toOIDCProviderConfig(o.Provider).NewProvider(ctx)
}

func (o *OIDCOptions) GetConfig() *oidc.Config {
	if o == nil || o.Config == nil {
		return &oidc.Config{}
	}

	return &oidc.Config{
		ClientID:                   o.Config.ClientID,
		SupportedSigningAlgs:       o.Config.SupportedSigningAlgs,
		SkipClientIDCheck:          o.Config.SkipClientIDCheck,
		SkipExpiryCheck:            o.Config.SkipExpiryCheck,
		SkipIssuerCheck:            o.Config.SkipIssuerCheck,
		Now:                        o.Config.Now,
		InsecureSkipSignatureCheck: o.Config.InsecureSkipSignatureCheck,
	}
}

func (o *OIDCOptions) validate() error {
	if o.Provider == nil {
		return errors.New("provider not set")
	}
	if o.Provider.IssuerURL == "" {
		return errors.New("issuer URL must not be empty")
	}
	if _, err := url.Parse(o.Provider.IssuerURL); err != nil {
		return fmt.Errorf("failed parsing issuer URL: %w", err)
	}
	if _, err := template.New("DeviceID").Parse(o.Provider.IssuerURL); err != nil {
		return fmt.Errorf("failed parsing template: %w", err)
	}

	return nil
}

func (o *OIDCOptions) EvaluateTarget(deviceID string) (string, error) {
	if o == nil {
		return "", errors.New("misconfigured target template configuration")
	}
	tmpl, err := template.New("DeviceID").Parse(o.Provider.IssuerURL)
	if err != nil {
		return "", fmt.Errorf("failed parsing OIDC template: %w", err)
	}
	buf := new(bytes.Buffer)
	if err = tmpl.Execute(buf, struct{ DeviceID string }{DeviceID: deviceID}); err != nil {
		return "", fmt.Errorf("failed executing OIDC template: %w", err)
	}
	return buf.String(), nil
}

func toOIDCProviderConfig(in *Provider) *oidc.ProviderConfig {
	issuerURL, _ := url.Parse(in.IssuerURL) // NOTE: validation is performed in validate()
	// Removes query params from the URL because we use it as a way to notify client about the actual OAuth ClientId
	// for this provisioner.
	// This URL is going to look like: "https://idp:5556/dex?clientid=foo"
	// If we don't trim the query params here i.e. 'clientid' then the idToken verification is going to fail because
	// the 'iss' claim of the idToken will be "https://idp:5556/dex"
	issuerURL.RawQuery = ""
	issuerURL.Fragment = ""
	return &oidc.ProviderConfig{
		IssuerURL:   issuerURL.String(),
		AuthURL:     in.AuthURL,
		TokenURL:    in.TokenURL,
		UserInfoURL: in.UserInfoURL,
		JWKSURL:     in.JWKSURL,
		Algorithms:  in.Algorithms,
	}
}
