package wire

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"text/template"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"go.step.sm/crypto/x509util"
)

type Provider struct {
	DiscoveryBaseURL string   `json:"discoveryBaseUrl,omitempty"`
	IssuerURL        string   `json:"issuerUrl,omitempty"`
	AuthURL          string   `json:"authorizationUrl,omitempty"`
	TokenURL         string   `json:"tokenUrl,omitempty"`
	JWKSURL          string   `json:"jwksUrl,omitempty"`
	UserInfoURL      string   `json:"userInfoUrl,omitempty"`
	Algorithms       []string `json:"signatureAlgorithms,omitempty"`
}

type Config struct {
	ClientID            string   `json:"clientId,omitempty"`
	SignatureAlgorithms []string `json:"signatureAlgorithms,omitempty"`

	// the properties below are only used for testing
	SkipClientIDCheck          bool             `json:"-"`
	SkipExpiryCheck            bool             `json:"-"`
	SkipIssuerCheck            bool             `json:"-"`
	InsecureSkipSignatureCheck bool             `json:"-"`
	Now                        func() time.Time `json:"-"`
}

type OIDCOptions struct {
	Provider          *Provider `json:"provider,omitempty"`
	Config            *Config   `json:"config,omitempty"`
	TransformTemplate string    `json:"transform,omitempty"`

	target             *template.Template
	transform          *template.Template
	oidcProviderConfig *oidc.ProviderConfig
	provider           *oidc.Provider
	verifier           *oidc.IDTokenVerifier
}

func (o *OIDCOptions) GetVerifier(ctx context.Context) (*oidc.IDTokenVerifier, error) {
	if o.verifier == nil {
		switch {
		case o.Provider.DiscoveryBaseURL != "":
			// creates a new OIDC provider using automatic discovery and the default HTTP client
			provider, err := oidc.NewProvider(ctx, o.Provider.DiscoveryBaseURL)
			if err != nil {
				return nil, fmt.Errorf("failed creating new OIDC provider using discovery: %w", err)
			}
			o.provider = provider
		default:
			o.provider = o.oidcProviderConfig.NewProvider(ctx)
		}

		if o.provider == nil {
			return nil, errors.New("no OIDC provider available")
		}

		o.verifier = o.provider.Verifier(o.getConfig())
	}

	return o.verifier, nil
}

func (o *OIDCOptions) getConfig() *oidc.Config {
	if o == nil || o.Config == nil {
		return &oidc.Config{}
	}

	return &oidc.Config{
		ClientID:                   o.Config.ClientID,
		SupportedSigningAlgs:       o.Config.SignatureAlgorithms,
		SkipClientIDCheck:          o.Config.SkipClientIDCheck,
		SkipExpiryCheck:            o.Config.SkipExpiryCheck,
		SkipIssuerCheck:            o.Config.SkipIssuerCheck,
		Now:                        o.Config.Now,
		InsecureSkipSignatureCheck: o.Config.InsecureSkipSignatureCheck,
	}
}

const defaultTemplate = `{"name": "{{ .name }}", "preferred_username": "{{ .preferred_username }}"}`

func (o *OIDCOptions) validateAndInitialize() (err error) {
	if o.Provider == nil {
		return errors.New("provider not set")
	}
	if o.Provider.IssuerURL == "" && o.Provider.DiscoveryBaseURL == "" {
		return errors.New("either OIDC discovery or issuer URL must be set")
	}

	if o.Provider.DiscoveryBaseURL == "" {
		o.oidcProviderConfig, err = toOIDCProviderConfig(o.Provider)
		if err != nil {
			return fmt.Errorf("failed creationg OIDC provider config: %w", err)
		}
	}

	o.target, err = template.New("DeviceID").Parse(o.Provider.IssuerURL)
	if err != nil {
		return fmt.Errorf("failed parsing OIDC template: %w", err)
	}

	o.transform, err = parseTransform(o.TransformTemplate)
	if err != nil {
		return fmt.Errorf("failed parsing OIDC transformation template: %w", err)
	}

	return nil
}

func parseTransform(transformTemplate string) (*template.Template, error) {
	if transformTemplate == "" {
		transformTemplate = defaultTemplate
	}

	return template.New("transform").Funcs(x509util.GetFuncMap()).Parse(transformTemplate)
}

func (o *OIDCOptions) EvaluateTarget(deviceID string) (string, error) {
	buf := new(bytes.Buffer)
	if err := o.target.Execute(buf, struct{ DeviceID string }{DeviceID: deviceID}); err != nil {
		return "", fmt.Errorf("failed executing OIDC template: %w", err)
	}
	return buf.String(), nil
}

func (o *OIDCOptions) Transform(v map[string]any) (map[string]any, error) {
	if o.transform == nil || v == nil {
		return v, nil
	}
	// TODO(hs): add support for extracting error message from template "fail" function?
	buf := new(bytes.Buffer)
	if err := o.transform.Execute(buf, v); err != nil {
		return nil, fmt.Errorf("failed executing OIDC transformation: %w", err)
	}
	var r map[string]any
	if err := json.Unmarshal(buf.Bytes(), &r); err != nil {
		return nil, fmt.Errorf("failed unmarshaling transformed OIDC token: %w", err)
	}
	// add original claims if not yet in the transformed result
	for key, value := range v {
		if _, ok := r[key]; !ok {
			r[key] = value
		}
	}
	return r, nil
}

func toOIDCProviderConfig(in *Provider) (*oidc.ProviderConfig, error) {
	issuerURL, err := url.Parse(in.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed parsing issuer URL: %w", err)
	}
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
	}, nil
}
