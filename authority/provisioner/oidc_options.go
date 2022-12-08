package provisioner

import (
	"context"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

type ProviderJSON struct {
	IssuerURL   string   `json:"issuer,omitempty"`
	AuthURL     string   `json:"authorization_endpoint,omitempty"`
	TokenURL    string   `json:"token_endpoint,omitempty"`
	JWKSURL     string   `json:"jwks_uri,omitempty"`
	UserInfoURL string   `json:"userinfo_endpoint,omitempty"`
	Algorithms  []string `json:"id_token_signing_alg_values_supported,omitempty"`
}

type ConfigJSON struct {
	ClientID                   string           `json:"client-id,omitempty"`
	SupportedSigningAlgs       []string         `json:"support-signing-algs,omitempty"`
	SkipClientIDCheck          bool             `json:"-"`
	SkipExpiryCheck            bool             `json:"-"`
	SkipIssuerCheck            bool             `json:"-"`
	Now                        func() time.Time `json:"-"`
	InsecureSkipSignatureCheck bool             `json:"-"`
}

type OIDCOptions struct {
	Provider ProviderJSON `json:"provider,omitempty"`
	Config   ConfigJSON   `json:"config,omitempty"`
}

func (o *OIDCOptions) GetProvider(ctx context.Context) *oidc.Provider {
	if o == nil {
		return nil
	}
	return toProviderConfig(o.Provider).NewProvider(ctx)
}

func (o *OIDCOptions) GetConfig() *oidc.Config {
	if o == nil {
		return nil
	}
	config := oidc.Config(o.Config)
	return &config
}

func toProviderConfig(in ProviderJSON) *oidc.ProviderConfig {
	return &oidc.ProviderConfig{
		IssuerURL:   in.IssuerURL,
		AuthURL:     in.AuthURL,
		TokenURL:    in.TokenURL,
		UserInfoURL: in.UserInfoURL,
		JWKSURL:     in.JWKSURL,
		Algorithms:  in.Algorithms,
	}
}
