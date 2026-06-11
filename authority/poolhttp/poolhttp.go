package poolhttp

import (
	"net/http"
	"sync"

	"github.com/smallstep/certificates/internal/httptransport"
)

// Transporter is implemented by custom HTTP clients with a method that
// returns an [*http.Transport].
type Transporter interface {
	Transport() *http.Transport
}

// Client is an HTTP client that uses a [sync.Pool] to create new and reuse HTTP
// clients. It implements the [provisioner.HTTPClient] and [Transporter]
// interfaces. This is the HTTP client used by the provisioners.
type Client struct {
	rw   sync.RWMutex
	pool sync.Pool
}

// New creates a new poolhttp [Client], the [sync.Pool] will initialize a new
// [*http.Client] with the given function.
func New(fn func() *http.Client) *Client {
	return &Client{
		pool: sync.Pool{
			New: func() any { return fn() },
		},
	}
}

// SetNew replaces the inner pool with a new [sync.Pool] with the given New
// function. This method can be use concurrently with other methods of this
// package.
func (c *Client) SetNew(fn func() *http.Client) {
	c.rw.Lock()
	c.pool = sync.Pool{
		New: func() any { return fn() },
	}
	c.rw.Unlock()
}

// getClient gets a client from the pool.
func (c *Client) getClient() *http.Client {
	c.rw.RLock()
	defer c.rw.RUnlock()
	if hc, ok := c.pool.Get().(*http.Client); ok && hc != nil {
		return hc
	}
	return nil
}

// Get issues a GET request to the specified URL. If the response is one of the
// following redirect codes, Get follows the redirect after calling the
// [Client.CheckRedirect] function:
func (c *Client) Get(u string) (resp *http.Response, err error) {
	if hc := c.getClient(); hc != nil {
		resp, err = hc.Get(u)
		c.pool.Put(hc)
	} else {
		resp, err = http.DefaultClient.Get(u)
	}

	return
}

// Do sends an HTTP request and returns an HTTP response, following policy (such
// as redirects, cookies, auth) as configured on the client.
func (c *Client) Do(req *http.Request) (resp *http.Response, err error) {
	if hc := c.getClient(); hc != nil {
		resp, err = hc.Do(req)
		c.pool.Put(hc)
	} else {
		resp, err = http.DefaultClient.Do(req)
	}

	return
}

// Transport() returns a clone of the http.Client Transport or returns the
// default transport.
func (c *Client) Transport() *http.Transport {
	if hc := c.getClient(); hc != nil {
		tr, ok := hc.Transport.(*http.Transport)
		c.pool.Put(hc)
		if ok {
			return tr.Clone()
		}
	}

	return httptransport.New()
}
