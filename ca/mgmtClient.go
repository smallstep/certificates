package ca

import (
	"net/http"
	"net/url"
	"path"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/mgmt"
)

// MgmtClient implements an HTTP client for the CA server.
type MgmtClient struct {
	client    *uaClient
	endpoint  *url.URL
	retryFunc RetryFunc
	opts      []ClientOption
}

// NewMgmtClient creates a new MgmtClient with the given endpoint and options.
func NewMgmtClient(endpoint string, opts ...ClientOption) (*MgmtClient, error) {
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

	return &MgmtClient{
		client:    newClient(tr),
		endpoint:  u,
		retryFunc: o.retryFunc,
		opts:      opts,
	}, nil
}

func (c *MgmtClient) retryOnError(r *http.Response) bool {
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

// GetAdmin performs the GET /config/admin/{id} request to the CA.
func (c *MgmtClient) GetAdmin(id string) (*mgmt.Admin, error) {
	var retried bool
	u := c.endpoint.ResolveReference(&url.URL{Path: path.Join("/config/admin", id)})
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
		return nil, readError(resp.Body)
	}
	var adm = new(mgmt.Admin)
	if err := readJSON(resp.Body, adm); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	return adm, nil
}

// GetAdmins performs the GET /config/admins request to the CA.
func (c *MgmtClient) GetAdmins() ([]*mgmt.Admin, error) {
	var retried bool
	u := c.endpoint.ResolveReference(&url.URL{Path: "/config/admins"})
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
		return nil, readError(resp.Body)
	}
	var admins = new([]*mgmt.Admin)
	if err := readJSON(resp.Body, admins); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	return *admins, nil
}
