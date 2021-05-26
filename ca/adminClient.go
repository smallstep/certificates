package ca

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/mgmt"
	mgmtAPI "github.com/smallstep/certificates/authority/mgmt/api"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/errs"
	"github.com/smallstep/certificates/linkedca"
)

var adminURLPrefix = "admin"

// AdminClient implements an HTTP client for the CA server.
type AdminClient struct {
	client    *uaClient
	endpoint  *url.URL
	retryFunc RetryFunc
	opts      []ClientOption
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
		client:    newClient(tr),
		endpoint:  u,
		retryFunc: o.retryFunc,
		opts:      opts,
	}, nil
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
		return nil, errors.Wrapf(err, "client GET %s failed", u)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) {
			retried = true
			goto retry
		}
		return nil, readAdminError(resp.Body)
	}
	var adm = new(linkedca.Admin)
	if err := readJSON(resp.Body, adm); err != nil {
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
func (c *AdminClient) GetAdminsPaginate(opts ...AdminOption) (*mgmtAPI.GetAdminsResponse, error) {
	var retried bool
	o := new(adminOptions)
	if err := o.apply(opts); err != nil {
		return nil, err
	}
	u := c.endpoint.ResolveReference(&url.URL{
		Path:     "/admin/admins",
		RawQuery: o.rawQuery(),
	})
retry:
	resp, err := c.client.Get(u.String())
	if err != nil {
		return nil, errors.Wrapf(err, "client GET %s failed", u)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) {
			retried = true
			goto retry
		}
		return nil, readAdminError(resp.Body)
	}
	var body = new(mgmtAPI.GetAdminsResponse)
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
	return admins, nil
}

// CreateAdmin performs the POST /admin/admins request to the CA.
func (c *AdminClient) CreateAdmin(req *mgmtAPI.CreateAdminRequest) (*linkedca.Admin, error) {
	var retried bool
	body, err := json.Marshal(req)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "error marshaling request")
	}
	u := c.endpoint.ResolveReference(&url.URL{Path: "/admin/admins"})
retry:
	resp, err := c.client.Post(u.String(), "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, errors.Wrapf(err, "client POST %s failed", u)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) {
			retried = true
			goto retry
		}
		return nil, readAdminError(resp.Body)
	}
	var adm = new(linkedca.Admin)
	if err := readJSON(resp.Body, adm); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	return adm, nil
}

// RemoveAdmin performs the DELETE /admin/admins/{id} request to the CA.
func (c *AdminClient) RemoveAdmin(id string) error {
	var retried bool
	u := c.endpoint.ResolveReference(&url.URL{Path: path.Join(adminURLPrefix, "admins", id)})
	req, err := http.NewRequest("DELETE", u.String(), nil)
	if err != nil {
		return errors.Wrapf(err, "create DELETE %s request failed", u)
	}
retry:
	resp, err := c.client.Do(req)
	if err != nil {
		return errors.Wrapf(err, "client DELETE %s failed", u)
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
func (c *AdminClient) UpdateAdmin(id string, uar *mgmtAPI.UpdateAdminRequest) (*linkedca.Admin, error) {
	var retried bool
	body, err := json.Marshal(uar)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "error marshaling request")
	}
	u := c.endpoint.ResolveReference(&url.URL{Path: path.Join(adminURLPrefix, "admins", id)})
	req, err := http.NewRequest("PATCH", u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, errors.Wrapf(err, "create PUT %s request failed", u)
	}
retry:
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, errors.Wrapf(err, "client PUT %s failed", u)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) {
			retried = true
			goto retry
		}
		return nil, readAdminError(resp.Body)
	}
	var adm = new(linkedca.Admin)
	if err := readJSON(resp.Body, adm); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	return adm, nil
}

// GetProvisionerByName performs the GET /admin/provisioners/{name} request to the CA.
func (c *AdminClient) GetProvisionerByName(name string) (*linkedca.Provisioner, error) {
	var retried bool
	u := c.endpoint.ResolveReference(&url.URL{Path: path.Join(adminURLPrefix, "provisioners", name)})
retry:
	resp, err := c.client.Get(u.String())
	if err != nil {
		return nil, errors.Wrapf(err, "client GET %s failed", u)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) {
			retried = true
			goto retry
		}
		return nil, readAdminError(resp.Body)
	}
	var prov = new(linkedca.Provisioner)
	if err := readJSON(resp.Body, prov); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	return prov, nil
}

// GetProvisionersPaginate performs the GET /admin/provisioners request to the CA.
func (c *AdminClient) GetProvisionersPaginate(opts ...ProvisionerOption) (*mgmtAPI.GetProvisionersResponse, error) {
	var retried bool
	o := new(provisionerOptions)
	if err := o.apply(opts); err != nil {
		return nil, err
	}
	u := c.endpoint.ResolveReference(&url.URL{
		Path:     "/admin/provisioners",
		RawQuery: o.rawQuery(),
	})
retry:
	resp, err := c.client.Get(u.String())
	if err != nil {
		return nil, errors.Wrapf(err, "client GET %s failed", u)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) {
			retried = true
			goto retry
		}
		return nil, readAdminError(resp.Body)
	}
	var body = new(mgmtAPI.GetProvisionersResponse)
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
	return provs, nil
}

// RemoveProvisioner performs the DELETE /admin/provisioners/{name} request to the CA.
func (c *AdminClient) RemoveProvisioner(name string) error {
	var retried bool
	u := c.endpoint.ResolveReference(&url.URL{Path: path.Join(adminURLPrefix, "provisioners", name)})
	req, err := http.NewRequest("DELETE", u.String(), nil)
	if err != nil {
		return errors.Wrapf(err, "create DELETE %s request failed", u)
	}
retry:
	resp, err := c.client.Do(req)
	if err != nil {
		return errors.Wrapf(err, "client DELETE %s failed", u)
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
	body, err := json.Marshal(prov)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "error marshaling request")
	}
	u := c.endpoint.ResolveReference(&url.URL{Path: "/admin/provisioners"})
retry:
	resp, err := c.client.Post(u.String(), "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, errors.Wrapf(err, "client POST %s failed", u)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) {
			retried = true
			goto retry
		}
		return nil, readAdminError(resp.Body)
	}
	var nuProv = new(linkedca.Provisioner)
	if err := readJSON(resp.Body, nuProv); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	return nuProv, nil
}

// UpdateProvisioner performs the PUT /admin/provisioners/{id} request to the CA.
func (c *AdminClient) UpdateProvisioner(id string, upr *mgmtAPI.UpdateProvisionerRequest) (*linkedca.Provisioner, error) {
	var retried bool
	body, err := json.Marshal(upr)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "error marshaling request")
	}
	u := c.endpoint.ResolveReference(&url.URL{Path: path.Join(adminURLPrefix, "provisioners", id)})
	req, err := http.NewRequest("PUT", u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, errors.Wrapf(err, "create PUT %s request failed", u)
	}
retry:
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, errors.Wrapf(err, "client PUT %s failed", u)
	}
	if resp.StatusCode >= 400 {
		if !retried && c.retryOnError(resp) {
			retried = true
			goto retry
		}
		return nil, readAdminError(resp.Body)
	}
	var prov = new(linkedca.Provisioner)
	if err := readJSON(resp.Body, prov); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	return prov, nil
}

func readAdminError(r io.ReadCloser) error {
	defer r.Close()
	mgmtErr := new(mgmt.Error)
	if err := json.NewDecoder(r).Decode(mgmtErr); err != nil {
		return err
	}
	return errors.New(mgmtErr.Message)
}
