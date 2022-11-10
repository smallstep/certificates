package ca

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"time"

	"github.com/pkg/errors"
	"google.golang.org/protobuf/encoding/protojson"

	"go.step.sm/cli-utils/token"
	"go.step.sm/cli-utils/token/provision"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/randutil"
	"go.step.sm/linkedca"

	adminAPI "github.com/smallstep/certificates/authority/admin/api"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/errs"
)

const (
	adminURLPrefix = "admin"
	adminIssuer    = "step-admin-client/1.0"
)

// AdminClient implements an HTTP client for the CA server.
type AdminClient struct {
	client      *uaClient
	endpoint    *url.URL
	retryFunc   RetryFunc
	opts        []ClientOption
	x5cJWK      *jose.JSONWebKey
	x5cCertFile string
	x5cCertStrs []string
	x5cCert     *x509.Certificate
	x5cSubject  string
}

// AdminClientError is the client side representation of an
// AdminError returned by the CA.
type AdminClientError struct {
	Type    string `json:"type"`
	Detail  string `json:"detail"`
	Message string `json:"message"`
}

// Error returns the AdminClientError message as the error message
func (e *AdminClientError) Error() string {
	return e.Message
}

// NewAdminClient creates a new AdminClient with the given endpoint and options.
func NewAdminClient(endpoint string, opts ...ClientOption) (*AdminClient, error) {
	u, err := parseEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	// Retrieve transport from options.
	o := new(clientOptions)
	if err := o.apply(opts); err != nil {
		return nil, err
	}
	tr, err := o.getTransport(endpoint)
	if err != nil {
		return nil, err
	}

	return &AdminClient{
		client:      newClient(tr),
		endpoint:    u,
		retryFunc:   o.retryFunc,
		opts:        opts,
		x5cJWK:      o.x5cJWK,
		x5cCertFile: o.x5cCertFile,
		x5cCertStrs: o.x5cCertStrs,
		x5cCert:     o.x5cCert,
		x5cSubject:  o.x5cSubject,
	}, nil
}

func (c *AdminClient) generateAdminToken(aud *url.URL) (string, error) {
	// A random jwt id will be used to identify duplicated tokens
	jwtID, err := randutil.Hex(64) // 256 bits
	if err != nil {
		return "", err
	}

	// Drop any query string parameter from the token audience
	aud = &url.URL{
		Scheme: aud.Scheme,
		Host:   aud.Host,
		Path:   aud.Path,
	}

	now := time.Now()
	tokOptions := []token.Options{
		token.WithJWTID(jwtID),
		token.WithKid(c.x5cJWK.KeyID),
		token.WithIssuer(adminIssuer),
		token.WithAudience(aud.String()),
		token.WithValidity(now, now.Add(token.DefaultValidity)),
		token.WithX5CCerts(c.x5cCertStrs),
	}

	tok, err := provision.New(c.x5cSubject, tokOptions...)
	if err != nil {
		return "", err
	}

	return tok.SignedString(c.x5cJWK.Algorithm, c.x5cJWK.Key)
}

func (c *AdminClient) retryOnError(r *http.Response) bool {
	if c.retryFunc != nil {
		if c.retryFunc(r.StatusCode) {
			o := new(clientOptions)
			if err := o.apply(c.opts); err != nil {
				return false
			}
			tr, err := o.getTransport(c.endpoint.String())
			if err != nil {
				return false
			}
			r.Body.Close()
			c.client.SetTransport(tr)
			return true
		}
	}
	return false
}

// GetAdmin performs the GET /admin/admin/{id} request to the CA.
func (c *AdminClient) GetAdmin(id string) (*linkedca.Admin, error) {
	var retried bool
	u := c.endpoint.ResolveReference(&url.URL{Path: path.Join(adminURLPrefix, "admins", id)})
retry:
	resp, err := c.client.Get(u.String())
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) {
			retried = true
			goto retry
		}
		return nil, readAdminError(resp.Body)
	}
	var adm = new(linkedca.Admin)
	if err := readProtoJSON(resp.Body, adm); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	return adm, nil
}

// AdminOption is the type of options passed to the Admin method.
type AdminOption func(o *adminOptions) error

type adminOptions struct {
	cursor string
	limit  int
}

func (o *adminOptions) apply(opts []AdminOption) (err error) {
	for _, fn := range opts {
		if err = fn(o); err != nil {
			return
		}
	}
	return
}

func (o *adminOptions) rawQuery() string {
	v := url.Values{}
	if len(o.cursor) > 0 {
		v.Set("cursor", o.cursor)
	}
	if o.limit > 0 {
		v.Set("limit", strconv.Itoa(o.limit))
	}
	return v.Encode()
}

// WithAdminCursor will request the admins starting with the given cursor.
func WithAdminCursor(cursor string) AdminOption {
	return func(o *adminOptions) error {
		o.cursor = cursor
		return nil
	}
}

// WithAdminLimit will request the given number of admins.
func WithAdminLimit(limit int) AdminOption {
	return func(o *adminOptions) error {
		o.limit = limit
		return nil
	}
}

// GetAdminsPaginate returns a page from the the GET /admin/admins request to the CA.
func (c *AdminClient) GetAdminsPaginate(opts ...AdminOption) (*adminAPI.GetAdminsResponse, error) {
	var retried bool
	o := new(adminOptions)
	if err := o.apply(opts); err != nil {
		return nil, err
	}
	u := c.endpoint.ResolveReference(&url.URL{
		Path:     "/admin/admins",
		RawQuery: o.rawQuery(),
	})
	tok, err := c.generateAdminToken(u)
	if err != nil {
		return nil, errors.Wrapf(err, "error generating admin token")
	}
	req, err := http.NewRequest("GET", u.String(), http.NoBody)
	if err != nil {
		return nil, errors.Wrapf(err, "create GET %s request failed", u)
	}
	req.Header.Add("Authorization", tok)
retry:
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) {
			retried = true
			goto retry
		}
		return nil, readAdminError(resp.Body)
	}
	var body = new(adminAPI.GetAdminsResponse)
	if err := readJSON(resp.Body, body); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	return body, nil
}

// GetAdmins returns all admins from the GET /admin/admins request to the CA.
func (c *AdminClient) GetAdmins(opts ...AdminOption) ([]*linkedca.Admin, error) {
	var (
		cursor = ""
		admins = []*linkedca.Admin{}
	)
	for {
		resp, err := c.GetAdminsPaginate(WithAdminCursor(cursor), WithAdminLimit(100))
		if err != nil {
			return nil, err
		}
		admins = append(admins, resp.Admins...)
		if resp.NextCursor == "" {
			return admins, nil
		}
		cursor = resp.NextCursor
	}
}

// CreateAdmin performs the POST /admin/admins request to the CA.
func (c *AdminClient) CreateAdmin(createAdminRequest *adminAPI.CreateAdminRequest) (*linkedca.Admin, error) {
	var retried bool
	body, err := json.Marshal(createAdminRequest)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "error marshaling request")
	}
	u := c.endpoint.ResolveReference(&url.URL{Path: "/admin/admins"})
	tok, err := c.generateAdminToken(u)
	if err != nil {
		return nil, errors.Wrapf(err, "error generating admin token")
	}
	req, err := http.NewRequest("POST", u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, errors.Wrapf(err, "create GET %s request failed", u)
	}
	req.Header.Add("Authorization", tok)
retry:
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) {
			retried = true
			goto retry
		}
		return nil, readAdminError(resp.Body)
	}
	var adm = new(linkedca.Admin)
	if err := readProtoJSON(resp.Body, adm); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	return adm, nil
}

// RemoveAdmin performs the DELETE /admin/admins/{id} request to the CA.
func (c *AdminClient) RemoveAdmin(id string) error {
	var retried bool
	u := c.endpoint.ResolveReference(&url.URL{Path: path.Join(adminURLPrefix, "admins", id)})
	tok, err := c.generateAdminToken(u)
	if err != nil {
		return errors.Wrapf(err, "error generating admin token")
	}
	req, err := http.NewRequest("DELETE", u.String(), http.NoBody)
	if err != nil {
		return errors.Wrapf(err, "create DELETE %s request failed", u)
	}
	req.Header.Add("Authorization", tok)
retry:
	resp, err := c.client.Do(req)
	if err != nil {
		return clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) {
			retried = true
			goto retry
		}
		return readAdminError(resp.Body)
	}
	return nil
}

// UpdateAdmin performs the PUT /admin/admins/{id} request to the CA.
func (c *AdminClient) UpdateAdmin(id string, uar *adminAPI.UpdateAdminRequest) (*linkedca.Admin, error) {
	var retried bool
	body, err := json.Marshal(uar)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "error marshaling request")
	}
	u := c.endpoint.ResolveReference(&url.URL{Path: path.Join(adminURLPrefix, "admins", id)})
	tok, err := c.generateAdminToken(u)
	if err != nil {
		return nil, errors.Wrapf(err, "error generating admin token")
	}
	req, err := http.NewRequest("PATCH", u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, errors.Wrapf(err, "create PATCH %s request failed", u)
	}
	req.Header.Add("Authorization", tok)
retry:
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) {
			retried = true
			goto retry
		}
		return nil, readAdminError(resp.Body)
	}
	var adm = new(linkedca.Admin)
	if err := readProtoJSON(resp.Body, adm); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	return adm, nil
}

// GetProvisioner performs the GET /admin/provisioners/{name} request to the CA.
func (c *AdminClient) GetProvisioner(opts ...ProvisionerOption) (*linkedca.Provisioner, error) {
	var retried bool
	o := new(ProvisionerOptions)
	if err := o.Apply(opts); err != nil {
		return nil, err
	}
	var u *url.URL
	switch {
	case o.ID != "":
		u = c.endpoint.ResolveReference(&url.URL{
			Path:     "/admin/provisioners/id",
			RawQuery: o.rawQuery(),
		})
	case o.Name != "":
		u = c.endpoint.ResolveReference(&url.URL{Path: path.Join(adminURLPrefix, "provisioners", o.Name)})
	default:
		return nil, errors.New("must set either name or id in method options")
	}
	tok, err := c.generateAdminToken(u)
	if err != nil {
		return nil, errors.Wrapf(err, "error generating admin token")
	}
	req, err := http.NewRequest("GET", u.String(), http.NoBody)
	if err != nil {
		return nil, errors.Wrapf(err, "create GET %s request failed", u)
	}
	req.Header.Add("Authorization", tok)
retry:
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) {
			retried = true
			goto retry
		}
		return nil, readAdminError(resp.Body)
	}
	var prov = new(linkedca.Provisioner)
	if err := readProtoJSON(resp.Body, prov); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	return prov, nil
}

// GetProvisionersPaginate performs the GET /admin/provisioners request to the CA.
func (c *AdminClient) GetProvisionersPaginate(opts ...ProvisionerOption) (*adminAPI.GetProvisionersResponse, error) {
	var retried bool
	o := new(ProvisionerOptions)
	if err := o.Apply(opts); err != nil {
		return nil, err
	}
	u := c.endpoint.ResolveReference(&url.URL{
		Path:     "/admin/provisioners",
		RawQuery: o.rawQuery(),
	})
	tok, err := c.generateAdminToken(u)
	if err != nil {
		return nil, errors.Wrapf(err, "error generating admin token")
	}
	req, err := http.NewRequest("GET", u.String(), http.NoBody)
	if err != nil {
		return nil, errors.Wrapf(err, "create GET %s request failed", u)
	}
	req.Header.Add("Authorization", tok)
retry:
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) {
			retried = true
			goto retry
		}
		return nil, readAdminError(resp.Body)
	}
	var body = new(adminAPI.GetProvisionersResponse)
	if err := readJSON(resp.Body, body); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	return body, nil
}

// GetProvisioners returns all admins from the GET /admin/admins request to the CA.
func (c *AdminClient) GetProvisioners(opts ...AdminOption) (provisioner.List, error) {
	var (
		cursor = ""
		provs  = provisioner.List{}
	)
	for {
		resp, err := c.GetProvisionersPaginate(WithProvisionerCursor(cursor), WithProvisionerLimit(100))
		if err != nil {
			return nil, err
		}
		provs = append(provs, resp.Provisioners...)
		if resp.NextCursor == "" {
			return provs, nil
		}
		cursor = resp.NextCursor
	}
}

// RemoveProvisioner performs the DELETE /admin/provisioners/{name} request to the CA.
func (c *AdminClient) RemoveProvisioner(opts ...ProvisionerOption) error {
	var (
		u       *url.URL
		retried bool
	)

	o := new(ProvisionerOptions)
	if err := o.Apply(opts); err != nil {
		return err
	}

	switch {
	case o.ID != "":
		u = c.endpoint.ResolveReference(&url.URL{
			Path:     path.Join(adminURLPrefix, "provisioners/id"),
			RawQuery: o.rawQuery(),
		})
	case o.Name != "":
		u = c.endpoint.ResolveReference(&url.URL{Path: path.Join(adminURLPrefix, "provisioners", o.Name)})
	default:
		return errors.New("must set either name or id in method options")
	}
	tok, err := c.generateAdminToken(u)
	if err != nil {
		return errors.Wrapf(err, "error generating admin token")
	}
	req, err := http.NewRequest("DELETE", u.String(), http.NoBody)
	if err != nil {
		return errors.Wrapf(err, "create DELETE %s request failed", u)
	}
	req.Header.Add("Authorization", tok)
retry:
	resp, err := c.client.Do(req)
	if err != nil {
		return clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) {
			retried = true
			goto retry
		}
		return readAdminError(resp.Body)
	}
	return nil
}

// CreateProvisioner performs the POST /admin/provisioners request to the CA.
func (c *AdminClient) CreateProvisioner(prov *linkedca.Provisioner) (*linkedca.Provisioner, error) {
	var retried bool
	body, err := protojson.Marshal(prov)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "error marshaling request")
	}
	u := c.endpoint.ResolveReference(&url.URL{Path: path.Join(adminURLPrefix, "provisioners")})
	tok, err := c.generateAdminToken(u)
	if err != nil {
		return nil, errors.Wrapf(err, "error generating admin token")
	}
	req, err := http.NewRequest("POST", u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, errors.Wrapf(err, "create POST %s request failed", u)
	}
	req.Header.Add("Authorization", tok)
retry:
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) {
			retried = true
			goto retry
		}
		return nil, readAdminError(resp.Body)
	}
	var nuProv = new(linkedca.Provisioner)
	if err := readProtoJSON(resp.Body, nuProv); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	return nuProv, nil
}

// UpdateProvisioner performs the PUT /admin/provisioners/{name} request to the CA.
func (c *AdminClient) UpdateProvisioner(name string, prov *linkedca.Provisioner) error {
	var retried bool
	body, err := protojson.Marshal(prov)
	if err != nil {
		return errs.Wrap(http.StatusInternalServerError, err, "error marshaling request")
	}
	u := c.endpoint.ResolveReference(&url.URL{Path: path.Join(adminURLPrefix, "provisioners", name)})
	tok, err := c.generateAdminToken(u)
	if err != nil {
		return errors.Wrapf(err, "error generating admin token")
	}
	req, err := http.NewRequest("PUT", u.String(), bytes.NewReader(body))
	if err != nil {
		return errors.Wrapf(err, "create PUT %s request failed", u)
	}
	req.Header.Add("Authorization", tok)
retry:
	resp, err := c.client.Do(req)
	if err != nil {
		return clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) {
			retried = true
			goto retry
		}
		return readAdminError(resp.Body)
	}
	return nil
}

// GetExternalAccountKeysPaginate returns a page from the GET /admin/acme/eab request to the CA.
func (c *AdminClient) GetExternalAccountKeysPaginate(provisionerName, reference string, opts ...AdminOption) (*adminAPI.GetExternalAccountKeysResponse, error) {
	var retried bool
	o := new(adminOptions)
	if err := o.apply(opts); err != nil {
		return nil, err
	}
	p := path.Join(adminURLPrefix, "acme/eab", provisionerName)
	if reference != "" {
		p = path.Join(p, "/", reference)
	}
	u := c.endpoint.ResolveReference(&url.URL{
		Path:     p,
		RawQuery: o.rawQuery(),
	})
	tok, err := c.generateAdminToken(u)
	if err != nil {
		return nil, errors.Wrapf(err, "error generating admin token")
	}
	req, err := http.NewRequest("GET", u.String(), http.NoBody)
	if err != nil {
		return nil, errors.Wrapf(err, "create GET %s request failed", u)
	}
	req.Header.Add("Authorization", tok)
retry:
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) {
			retried = true
			goto retry
		}
		return nil, readAdminError(resp.Body)
	}
	var body = new(adminAPI.GetExternalAccountKeysResponse)
	if err := readJSON(resp.Body, body); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	return body, nil
}

// CreateExternalAccountKey performs the POST /admin/acme/eab request to the CA.
func (c *AdminClient) CreateExternalAccountKey(provisionerName string, eakRequest *adminAPI.CreateExternalAccountKeyRequest) (*linkedca.EABKey, error) {
	var retried bool
	body, err := json.Marshal(eakRequest)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "error marshaling request")
	}
	u := c.endpoint.ResolveReference(&url.URL{Path: path.Join(adminURLPrefix, "acme/eab/", provisionerName)})
	tok, err := c.generateAdminToken(u)
	if err != nil {
		return nil, errors.Wrapf(err, "error generating admin token")
	}
	req, err := http.NewRequest("POST", u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, errors.Wrapf(err, "create POST %s request failed", u)
	}
	req.Header.Add("Authorization", tok)
retry:
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) {
			retried = true
			goto retry
		}
		return nil, readAdminError(resp.Body)
	}
	var eabKey = new(linkedca.EABKey)
	if err := readProtoJSON(resp.Body, eabKey); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	return eabKey, nil
}

// RemoveExternalAccountKey performs the DELETE /admin/acme/eab/{prov}/{key_id} request to the CA.
func (c *AdminClient) RemoveExternalAccountKey(provisionerName, keyID string) error {
	var retried bool
	u := c.endpoint.ResolveReference(&url.URL{Path: path.Join(adminURLPrefix, "acme/eab", provisionerName, "/", keyID)})
	tok, err := c.generateAdminToken(u)
	if err != nil {
		return errors.Wrapf(err, "error generating admin token")
	}
	req, err := http.NewRequest("DELETE", u.String(), http.NoBody)
	if err != nil {
		return errors.Wrapf(err, "create DELETE %s request failed", u)
	}
	req.Header.Add("Authorization", tok)
retry:
	resp, err := c.client.Do(req)
	if err != nil {
		return clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) {
			retried = true
			goto retry
		}
		return readAdminError(resp.Body)
	}
	return nil
}

func (c *AdminClient) GetAuthorityPolicy() (*linkedca.Policy, error) {
	var retried bool
	u := c.endpoint.ResolveReference(&url.URL{Path: path.Join(adminURLPrefix, "policy")})
	tok, err := c.generateAdminToken(u)
	if err != nil {
		return nil, fmt.Errorf("error generating admin token: %w", err)
	}
	req, err := http.NewRequest(http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("creating GET %s request failed: %w", u, err)
	}
	req.Header.Add("Authorization", tok)
retry:
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) {
			retried = true
			goto retry
		}
		return nil, readAdminError(resp.Body)
	}
	var policy = new(linkedca.Policy)
	if err := readProtoJSON(resp.Body, policy); err != nil {
		return nil, fmt.Errorf("error reading %s: %w", u, err)
	}
	return policy, nil
}

func (c *AdminClient) CreateAuthorityPolicy(p *linkedca.Policy) (*linkedca.Policy, error) {
	var retried bool
	body, err := protojson.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("error marshaling request: %w", err)
	}
	u := c.endpoint.ResolveReference(&url.URL{Path: path.Join(adminURLPrefix, "policy")})
	tok, err := c.generateAdminToken(u)
	if err != nil {
		return nil, fmt.Errorf("error generating admin token: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating POST %s request failed: %w", u, err)
	}
	req.Header.Add("Authorization", tok)
retry:
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) {
			retried = true
			goto retry
		}
		return nil, readAdminError(resp.Body)
	}
	var policy = new(linkedca.Policy)
	if err := readProtoJSON(resp.Body, policy); err != nil {
		return nil, fmt.Errorf("error reading %s: %w", u, err)
	}
	return policy, nil
}

func (c *AdminClient) UpdateAuthorityPolicy(p *linkedca.Policy) (*linkedca.Policy, error) {
	var retried bool
	body, err := protojson.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("error marshaling request: %w", err)
	}
	u := c.endpoint.ResolveReference(&url.URL{Path: path.Join(adminURLPrefix, "policy")})
	tok, err := c.generateAdminToken(u)
	if err != nil {
		return nil, fmt.Errorf("error generating admin token: %w", err)
	}
	req, err := http.NewRequest(http.MethodPut, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating PUT %s request failed: %w", u, err)
	}
	req.Header.Add("Authorization", tok)
retry:
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) {
			retried = true
			goto retry
		}
		return nil, readAdminError(resp.Body)
	}
	var policy = new(linkedca.Policy)
	if err := readProtoJSON(resp.Body, policy); err != nil {
		return nil, fmt.Errorf("error reading %s: %w", u, err)
	}
	return policy, nil
}

func (c *AdminClient) RemoveAuthorityPolicy() error {
	var retried bool
	u := c.endpoint.ResolveReference(&url.URL{Path: path.Join(adminURLPrefix, "policy")})
	tok, err := c.generateAdminToken(u)
	if err != nil {
		return fmt.Errorf("error generating admin token: %w", err)
	}
	req, err := http.NewRequest(http.MethodDelete, u.String(), http.NoBody)
	if err != nil {
		return fmt.Errorf("creating DELETE %s request failed: %w", u, err)
	}
	req.Header.Add("Authorization", tok)
retry:
	resp, err := c.client.Do(req)
	if err != nil {
		return clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) {
			retried = true
			goto retry
		}
		return readAdminError(resp.Body)
	}
	return nil
}

func (c *AdminClient) GetProvisionerPolicy(provisionerName string) (*linkedca.Policy, error) {
	var retried bool
	u := c.endpoint.ResolveReference(&url.URL{Path: path.Join(adminURLPrefix, "provisioners", provisionerName, "policy")})
	tok, err := c.generateAdminToken(u)
	if err != nil {
		return nil, fmt.Errorf("error generating admin token: %w", err)
	}
	req, err := http.NewRequest(http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("creating GET %s request failed: %w", u, err)
	}
	req.Header.Add("Authorization", tok)
retry:
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) {
			retried = true
			goto retry
		}
		return nil, readAdminError(resp.Body)
	}
	var policy = new(linkedca.Policy)
	if err := readProtoJSON(resp.Body, policy); err != nil {
		return nil, fmt.Errorf("error reading %s: %w", u, err)
	}
	return policy, nil
}

func (c *AdminClient) CreateProvisionerPolicy(provisionerName string, p *linkedca.Policy) (*linkedca.Policy, error) {
	var retried bool
	body, err := protojson.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("error marshaling request: %w", err)
	}
	u := c.endpoint.ResolveReference(&url.URL{Path: path.Join(adminURLPrefix, "provisioners", provisionerName, "policy")})
	tok, err := c.generateAdminToken(u)
	if err != nil {
		return nil, fmt.Errorf("error generating admin token: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating POST %s request failed: %w", u, err)
	}
	req.Header.Add("Authorization", tok)
retry:
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) {
			retried = true
			goto retry
		}
		return nil, readAdminError(resp.Body)
	}
	var policy = new(linkedca.Policy)
	if err := readProtoJSON(resp.Body, policy); err != nil {
		return nil, fmt.Errorf("error reading %s: %w", u, err)
	}
	return policy, nil
}

func (c *AdminClient) UpdateProvisionerPolicy(provisionerName string, p *linkedca.Policy) (*linkedca.Policy, error) {
	var retried bool
	body, err := protojson.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("error marshaling request: %w", err)
	}
	u := c.endpoint.ResolveReference(&url.URL{Path: path.Join(adminURLPrefix, "provisioners", provisionerName, "policy")})
	tok, err := c.generateAdminToken(u)
	if err != nil {
		return nil, fmt.Errorf("error generating admin token: %w", err)
	}
	req, err := http.NewRequest(http.MethodPut, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating PUT %s request failed: %w", u, err)
	}
	req.Header.Add("Authorization", tok)
retry:
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) {
			retried = true
			goto retry
		}
		return nil, readAdminError(resp.Body)
	}
	var policy = new(linkedca.Policy)
	if err := readProtoJSON(resp.Body, policy); err != nil {
		return nil, fmt.Errorf("error reading %s: %w", u, err)
	}
	return policy, nil
}

func (c *AdminClient) RemoveProvisionerPolicy(provisionerName string) error {
	var retried bool
	u := c.endpoint.ResolveReference(&url.URL{Path: path.Join(adminURLPrefix, "provisioners", provisionerName, "policy")})
	tok, err := c.generateAdminToken(u)
	if err != nil {
		return fmt.Errorf("error generating admin token: %w", err)
	}
	req, err := http.NewRequest(http.MethodDelete, u.String(), http.NoBody)
	if err != nil {
		return fmt.Errorf("creating DELETE %s request failed: %w", u, err)
	}
	req.Header.Add("Authorization", tok)
retry:
	resp, err := c.client.Do(req)
	if err != nil {
		return clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) {
			retried = true
			goto retry
		}
		return readAdminError(resp.Body)
	}
	return nil
}

func (c *AdminClient) GetACMEPolicy(provisionerName, reference, keyID string) (*linkedca.Policy, error) {
	var retried bool
	var urlPath string
	switch {
	case keyID != "":
		urlPath = path.Join(adminURLPrefix, "acme", "policy", provisionerName, "key", keyID)
	default:
		urlPath = path.Join(adminURLPrefix, "acme", "policy", provisionerName, "reference", reference)
	}
	u := c.endpoint.ResolveReference(&url.URL{Path: urlPath})
	tok, err := c.generateAdminToken(u)
	if err != nil {
		return nil, fmt.Errorf("error generating admin token: %w", err)
	}
	req, err := http.NewRequest(http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("creating GET %s request failed: %w", u, err)
	}
	req.Header.Add("Authorization", tok)
retry:
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) {
			retried = true
			goto retry
		}
		return nil, readAdminError(resp.Body)
	}
	var policy = new(linkedca.Policy)
	if err := readProtoJSON(resp.Body, policy); err != nil {
		return nil, fmt.Errorf("error reading %s: %w", u, err)
	}
	return policy, nil
}

func (c *AdminClient) CreateACMEPolicy(provisionerName, reference, keyID string, p *linkedca.Policy) (*linkedca.Policy, error) {
	var retried bool
	body, err := protojson.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("error marshaling request: %w", err)
	}
	var urlPath string
	switch {
	case keyID != "":
		urlPath = path.Join(adminURLPrefix, "acme", "policy", provisionerName, "key", keyID)
	default:
		urlPath = path.Join(adminURLPrefix, "acme", "policy", provisionerName, "reference", reference)
	}
	u := c.endpoint.ResolveReference(&url.URL{Path: urlPath})
	tok, err := c.generateAdminToken(u)
	if err != nil {
		return nil, fmt.Errorf("error generating admin token: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating POST %s request failed: %w", u, err)
	}
	req.Header.Add("Authorization", tok)
retry:
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) {
			retried = true
			goto retry
		}
		return nil, readAdminError(resp.Body)
	}
	var policy = new(linkedca.Policy)
	if err := readProtoJSON(resp.Body, policy); err != nil {
		return nil, fmt.Errorf("error reading %s: %w", u, err)
	}
	return policy, nil
}

func (c *AdminClient) UpdateACMEPolicy(provisionerName, reference, keyID string, p *linkedca.Policy) (*linkedca.Policy, error) {
	var retried bool
	body, err := protojson.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("error marshaling request: %w", err)
	}
	var urlPath string
	switch {
	case keyID != "":
		urlPath = path.Join(adminURLPrefix, "acme", "policy", provisionerName, "key", keyID)
	default:
		urlPath = path.Join(adminURLPrefix, "acme", "policy", provisionerName, "reference", reference)
	}
	u := c.endpoint.ResolveReference(&url.URL{Path: urlPath})
	tok, err := c.generateAdminToken(u)
	if err != nil {
		return nil, fmt.Errorf("error generating admin token: %w", err)
	}
	req, err := http.NewRequest(http.MethodPut, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating PUT %s request failed: %w", u, err)
	}
	req.Header.Add("Authorization", tok)
retry:
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) {
			retried = true
			goto retry
		}
		return nil, readAdminError(resp.Body)
	}
	var policy = new(linkedca.Policy)
	if err := readProtoJSON(resp.Body, policy); err != nil {
		return nil, fmt.Errorf("error reading %s: %w", u, err)
	}
	return policy, nil
}

func (c *AdminClient) RemoveACMEPolicy(provisionerName, reference, keyID string) error {
	var retried bool
	var urlPath string
	switch {
	case keyID != "":
		urlPath = path.Join(adminURLPrefix, "acme", "policy", provisionerName, "key", keyID)
	default:
		urlPath = path.Join(adminURLPrefix, "acme", "policy", provisionerName, "reference", reference)
	}
	u := c.endpoint.ResolveReference(&url.URL{Path: urlPath})
	tok, err := c.generateAdminToken(u)
	if err != nil {
		return fmt.Errorf("error generating admin token: %w", err)
	}
	req, err := http.NewRequest(http.MethodDelete, u.String(), http.NoBody)
	if err != nil {
		return fmt.Errorf("creating DELETE %s request failed: %w", u, err)
	}
	req.Header.Add("Authorization", tok)
retry:
	resp, err := c.client.Do(req)
	if err != nil {
		return clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) {
			retried = true
			goto retry
		}
		return readAdminError(resp.Body)
	}
	return nil
}

func (c *AdminClient) CreateProvisionerWebhook(provisionerName string, wh *linkedca.Webhook) (*linkedca.Webhook, error) {
	var retried bool
	body, err := protojson.Marshal(wh)
	if err != nil {
		return nil, fmt.Errorf("error marshaling request: %w", err)
	}
	u := c.endpoint.ResolveReference(&url.URL{Path: path.Join(adminURLPrefix, "provisioners", provisionerName, "webhooks")})
	tok, err := c.generateAdminToken(u)
	if err != nil {
		return nil, fmt.Errorf("error generating admin token: %w", err)
	}
retry:
	req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating POST %s request failed: %w", u, err)
	}
	req.Header.Add("Authorization", tok)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) {
			retried = true
			goto retry
		}
		return nil, readAdminError(resp.Body)
	}
	var webhook = new(linkedca.Webhook)
	if err := readProtoJSON(resp.Body, webhook); err != nil {
		return nil, fmt.Errorf("error reading %s: %w", u, err)
	}
	return webhook, nil
}

func (c *AdminClient) UpdateProvisionerWebhook(provisionerName string, wh *linkedca.Webhook) (*linkedca.Webhook, error) {
	var retried bool
	body, err := protojson.Marshal(wh)
	if err != nil {
		return nil, fmt.Errorf("error marshaling request: %w", err)
	}
	u := c.endpoint.ResolveReference(&url.URL{Path: path.Join(adminURLPrefix, "provisioners", provisionerName, "webhooks", wh.Name)})
	tok, err := c.generateAdminToken(u)
	if err != nil {
		return nil, fmt.Errorf("error generating admin token: %w", err)
	}
retry:
	req, err := http.NewRequest(http.MethodPut, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating PUT %s request failed: %w", u, err)
	}
	req.Header.Add("Authorization", tok)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) {
			retried = true
			goto retry
		}
		return nil, readAdminError(resp.Body)
	}
	var webhook = new(linkedca.Webhook)
	if err := readProtoJSON(resp.Body, webhook); err != nil {
		return nil, fmt.Errorf("error reading %s: %w", u, err)
	}
	return webhook, nil
}

func (c *AdminClient) DeleteProvisionerWebhook(provisionerName, webhookName string) error {
	var retried bool
	u := c.endpoint.ResolveReference(&url.URL{Path: path.Join(adminURLPrefix, "provisioners", provisionerName, "webhooks", webhookName)})
	tok, err := c.generateAdminToken(u)
	if err != nil {
		return fmt.Errorf("error generating admin token: %w", err)
	}
retry:
	req, err := http.NewRequest(http.MethodDelete, u.String(), http.NoBody)
	if err != nil {
		return fmt.Errorf("creating DELETE %s request failed: %w", u, err)
	}
	req.Header.Add("Authorization", tok)
	resp, err := c.client.Do(req)
	if err != nil {
		return clientError(err)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) {
			retried = true
			goto retry
		}
		return readAdminError(resp.Body)
	}
	return nil
}

func readAdminError(r io.ReadCloser) error {
	// TODO: not all errors can be read (i.e. 404); seems to be a bigger issue
	defer r.Close()
	adminErr := new(AdminClientError)
	if err := json.NewDecoder(r).Decode(adminErr); err != nil {
		return err
	}
	return adminErr
}
