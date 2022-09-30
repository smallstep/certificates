package ca

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/acme"
	acmeAPI "github.com/smallstep/certificates/acme/api"
	"go.step.sm/crypto/jose"
)

// ACMEClient implements an HTTP client to an ACME API.
type ACMEClient struct {
	client *http.Client
	dirLoc string
	dir    *acmeAPI.Directory
	acc    *acme.Account
	Key    *jose.JSONWebKey
	kid    string
}

// NewACMEClient initializes a new ACMEClient.
func NewACMEClient(endpoint string, contact []string, opts ...ClientOption) (*ACMEClient, error) {
	// Retrieve transport from options.
	o := new(clientOptions)
	if err := o.apply(opts); err != nil {
		return nil, err
	}
	tr, err := o.getTransport(endpoint)
	if err != nil {
		return nil, err
	}
	ac := &ACMEClient{
		client: &http.Client{
			Transport: tr,
		},
		dirLoc: endpoint,
	}
	req, err := http.NewRequest("GET", endpoint, http.NoBody)
	if err != nil {
		return nil, errors.Wrapf(err, "creating GET request %s failed", endpoint)
	}
	req.Header.Set("User-Agent", UserAgent)
	resp, err := ac.client.Do(req)
	if err != nil {
		return nil, errors.Wrapf(err, "client GET %s failed", endpoint)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, readACMEError(resp.Body)
	}
	var dir acmeAPI.Directory
	if err := readJSON(resp.Body, &dir); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", endpoint)
	}

	ac.dir = &dir

	ac.Key, err = jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
	if err != nil {
		return nil, err
	}

	nar := &acmeAPI.NewAccountRequest{
		Contact:              contact,
		TermsOfServiceAgreed: true,
	}
	payload, err := json.Marshal(nar)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling new account request")
	}

	resp, err = ac.post(payload, ac.dir.NewAccount, withJWK(ac))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, readACMEError(resp.Body)
	}
	var acc acme.Account
	if err := readJSON(resp.Body, &acc); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", dir.NewAccount)
	}
	ac.acc = &acc
	ac.kid = resp.Header.Get("Location")

	return ac, nil
}

// GetDirectory makes a directory request to the ACME api and returns an
// ACME directory object.
func (c *ACMEClient) GetDirectory() (*acmeAPI.Directory, error) {
	return c.dir, nil
}

// GetNonce makes a nonce request to the ACME api and returns an
// ACME directory object.
func (c *ACMEClient) GetNonce() (string, error) {
	req, err := http.NewRequest("GET", c.dir.NewNonce, http.NoBody)
	if err != nil {
		return "", errors.Wrapf(err, "creating GET request %s failed", c.dir.NewNonce)
	}
	req.Header.Set("User-Agent", UserAgent)
	resp, err := c.client.Do(req)
	if err != nil {
		return "", errors.Wrapf(err, "client GET %s failed", c.dir.NewNonce)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", readACMEError(resp.Body)
	}
	return resp.Header.Get("Replay-Nonce"), nil
}

type withHeaderOption func(so *jose.SignerOptions)

func withJWK(c *ACMEClient) withHeaderOption {
	return func(so *jose.SignerOptions) {
		so.WithHeader("jwk", c.Key.Public())
	}
}

func withKid(c *ACMEClient) withHeaderOption {
	return func(so *jose.SignerOptions) {
		so.WithHeader("kid", c.kid)
	}
}

// serialize serializes a json web signature and doesn't omit empty fields.
func serialize(obj *jose.JSONWebSignature) (string, error) {
	raw, err := obj.CompactSerialize()
	if err != nil {
		return "", errors.Wrap(err, "error serializing JWS")
	}
	parts := strings.Split(raw, ".")
	msg := struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}{Protected: parts[0], Payload: parts[1], Signature: parts[2]}
	b, err := json.Marshal(msg)
	if err != nil {
		return "", errors.Wrap(err, "error marshaling jws message")
	}
	return string(b), nil
}

func (c *ACMEClient) post(payload []byte, url string, headerOps ...withHeaderOption) (*http.Response, error) {
	if c.Key == nil {
		return nil, errors.New("acme client not configured with account")
	}
	nonce, err := c.GetNonce()
	if err != nil {
		return nil, err
	}
	so := new(jose.SignerOptions)
	so.WithHeader("nonce", nonce)
	so.WithHeader("url", url)
	for _, hop := range headerOps {
		hop(so)
	}
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(c.Key.Algorithm),
		Key:       c.Key.Key,
	}, so)
	if err != nil {
		return nil, errors.Wrap(err, "error creating JWS signer")
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		return nil, errors.Errorf("error signing payload: %s", strings.TrimPrefix(err.Error(), "square/go-jose: "))
	}
	raw, err := serialize(signed)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", url, strings.NewReader(raw))
	if err != nil {
		return nil, errors.Wrapf(err, "creating POST request %s failed", url)
	}
	req.Header.Set("Content-Type", "application/jose+json")
	req.Header.Set("User-Agent", UserAgent)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, errors.Wrapf(err, "client POST %s failed", c.dir.NewOrder)
	}
	return resp, nil
}

// NewOrder creates and returns the information for a new ACME order.
func (c *ACMEClient) NewOrder(payload []byte) (*acme.Order, error) {
	resp, err := c.post(payload, c.dir.NewOrder, withKid(c))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, readACMEError(resp.Body)
	}

	var o acme.Order
	if err := readJSON(resp.Body, &o); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", c.dir.NewOrder)
	}
	o.ID = resp.Header.Get("Location")
	return &o, nil
}

// GetChallenge returns the Challenge at the given path.
// With the validate parameter set to True this method will attempt to validate the
// challenge before returning it.
func (c *ACMEClient) GetChallenge(url string) (*acme.Challenge, error) {
	resp, err := c.post(nil, url, withKid(c))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, readACMEError(resp.Body)
	}

	var ch acme.Challenge
	if err := readJSON(resp.Body, &ch); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", url)
	}
	return &ch, nil
}

// ValidateChallenge returns the Challenge at the given path.
// With the validate parameter set to True this method will attempt to validate the
// challenge before returning it.
func (c *ACMEClient) ValidateChallenge(url string) error {
	resp, err := c.post([]byte("{}"), url, withKid(c))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return readACMEError(resp.Body)
	}
	return nil
}

// ValidateWithPayload will attempt to validate the challenge at the given url
// with the given attestation payload.
func (c *ACMEClient) ValidateWithPayload(url string, payload []byte) error {
	resp, err := c.post(payload, url, withKid(c))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return readACMEError(resp.Body)
	}
	return nil
}

// GetAuthz returns the Authz at the given path.
func (c *ACMEClient) GetAuthz(url string) (*acme.Authorization, error) {
	resp, err := c.post(nil, url, withKid(c))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, readACMEError(resp.Body)
	}

	var az acme.Authorization
	if err := readJSON(resp.Body, &az); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", url)
	}
	return &az, nil
}

// GetOrder returns the Order at the given path.
func (c *ACMEClient) GetOrder(url string) (*acme.Order, error) {
	resp, err := c.post(nil, url, withKid(c))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, readACMEError(resp.Body)
	}

	var o acme.Order
	if err := readJSON(resp.Body, &o); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", url)
	}
	return &o, nil
}

// FinalizeOrder makes a finalize request to the ACME api.
func (c *ACMEClient) FinalizeOrder(url string, csr *x509.CertificateRequest) error {
	payload, err := json.Marshal(acmeAPI.FinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(csr.Raw),
	})
	if err != nil {
		return errors.Wrap(err, "error marshaling finalize request")
	}
	resp, err := c.post(payload, url, withKid(c))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return readACMEError(resp.Body)
	}
	return nil
}

// GetCertificate retrieves the certificate along with all intermediates.
func (c *ACMEClient) GetCertificate(url string) (*x509.Certificate, []*x509.Certificate, error) {
	resp, err := c.post(nil, url, withKid(c))
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, nil, readACMEError(resp.Body)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, errors.Wrap(err, "error reading GET certificate response")
	}

	var certs []*x509.Certificate

	block, rest := pem.Decode(bodyBytes)
	if block == nil {
		return nil, nil, errors.New("failed to parse any certificates from response")
	}
	for block != nil {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, errors.Wrap(err, "error parsing certificate pem response")
		}
		certs = append(certs, cert)
		block, rest = pem.Decode(rest)
	}

	return certs[0], certs[1:], nil
}

// GetAccountOrders retrieves the orders belonging to the given account.
func (c *ACMEClient) GetAccountOrders() ([]string, error) {
	if c.acc == nil {
		return nil, errors.New("acme client not configured with account")
	}
	resp, err := c.post(nil, c.acc.OrdersURL, withKid(c))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, readACMEError(resp.Body)
	}

	var orders []string
	if err := readJSON(resp.Body, &orders); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", c.acc.OrdersURL)
	}

	return orders, nil
}

func readACMEError(r io.ReadCloser) error {
	defer r.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		return errors.Wrap(err, "error reading from body")
	}
	ae := new(acme.Error)
	err = json.Unmarshal(b, &ae)
	// If we successfully marshaled to an ACMEError then return the ACMEError.
	if err != nil || ae.Error() == "" {
		fmt.Printf("b = %s\n", b)
		// Throw up our hands.
		return errors.Errorf("%s", b)
	}
	return ae
}
