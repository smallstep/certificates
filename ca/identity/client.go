package identity

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/pkg/errors"
)

// Client wraps http.Client with a transport using the step root and identity.
type Client struct {
	CaURL *url.URL
	*http.Client
}

// ResolveReference resolves the given reference from the CaURL.
func (c *Client) ResolveReference(ref *url.URL) *url.URL {
	return c.CaURL.ResolveReference(ref)
}

// LoadClient configures an http.Client with the root in
// $STEPPATH/config/defaults.json and the identity defined in
// $STEPPATH/config/identity.json
func LoadClient() (*Client, error) {
	b, err := ioutil.ReadFile(DefaultsFile)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading %s", DefaultsFile)
	}

	var defaults defaultsConfig
	if err := json.Unmarshal(b, &defaults); err != nil {
		return nil, errors.Wrapf(err, "error unmarshaling %s", DefaultsFile)
	}
	if err := defaults.Validate(); err != nil {
		return nil, errors.Wrapf(err, "error validating %s", DefaultsFile)
	}
	caURL, err := url.Parse(defaults.CaURL)
	if err != nil {
		return nil, errors.Wrapf(err, "error validating %s", DefaultsFile)
	}
	if caURL.Scheme == "" {
		caURL.Scheme = "https"
	}

	identity, err := LoadDefaultIdentity()
	if err != nil {
		return nil, err
	}
	if err := identity.Validate(); err != nil {
		return nil, errors.Wrapf(err, "error validating %s", IdentityFile)
	}
	if kind := identity.Kind(); kind != MutualTLS {
		return nil, errors.Errorf("unsupported identity %s: only mTLS is currently supported", kind)
	}

	// Prepare transport with information in defaults.json and identity.json
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{
		GetClientCertificate: identity.GetClientCertificateFunc(),
	}

	// RootCAs
	b, err = ioutil.ReadFile(defaults.Root)
	if err != nil {
		return nil, errors.Wrapf(err, "error loading %s", defaults.Root)
	}
	pool := x509.NewCertPool()
	if pool.AppendCertsFromPEM(b) {
		tr.TLSClientConfig.RootCAs = pool
	}

	return &Client{
		CaURL: caURL,
		Client: &http.Client{
			Transport: tr,
		},
	}, nil

}

type defaultsConfig struct {
	CaURL string `json:"ca-url"`
	Root  string `json:"root"`
}

func (c *defaultsConfig) Validate() error {
	switch {
	case c.CaURL == "":
		return fmt.Errorf("missing or invalid `ca-url` property")
	case c.Root == "":
		return fmt.Errorf("missing or invalid `root` property")
	default:
		return nil
	}
}
