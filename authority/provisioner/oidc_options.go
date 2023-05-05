package provisioner

import (
	"bytes"
	"context"
	"fmt"
	"text/template"
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
		return &oidc.Config{}
	}
	config := oidc.Config(o.Config)
	return &config
}

func (o *OIDCOptions) GetTarget(deviceID string) (string, error) {
	if o == nil {
		return "", fmt.Errorf("Misconfigured target template configuration")
	}
	targetTemplate := o.Provider.IssuerURL
	tmpl, err := template.New("DeviceId").Parse(targetTemplate)
	buf := new(bytes.Buffer)
	err = tmpl.Execute(buf, struct{ DeviceId string }{deviceID})
	return buf.String(), err
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
