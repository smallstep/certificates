package acme

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// Client is the interface used to verify ACME challenges.
type Client interface {
	// Get issues an HTTP GET to the specified URL.
	Get(url string) (*http.Response, error)

	// LookupTXT returns the DNS TXT records for the given domain name.
	LookupTxt(name string) ([]string, error)

	// TLSDial connects to the given network address using net.Dialer and then
	// initiates a TLS handshake, returning the resulting TLS connection.
	TLSDial(network, addr string, config *tls.Config) (*tls.Conn, error)
}

type clientKey struct{}

// NewClientContext adds the given client to the context.
func NewClientContext(ctx context.Context, c Client) context.Context {
	return context.WithValue(ctx, clientKey{}, c)
}

// ClientFromContext returns the current client from the given context.
func ClientFromContext(ctx context.Context) (c Client, ok bool) {
	c, ok = ctx.Value(clientKey{}).(Client)
	return
}

// MustClientFromContext returns the current client from the given context. It will
// return a new instance of the client if it does not exist.
func MustClientFromContext(ctx context.Context) Client {
	c, ok := ClientFromContext(ctx)
	if !ok {
		return NewClient()
	}
	return c
}

type client struct {
	http   *http.Client
	dialer *net.Dialer
}

// NewClient returns an implementation of Client for verifying ACME challenges.
func NewClient() Client {
	return &client{
		http: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					//nolint:gosec // used on tls-alpn-01 challenge
					InsecureSkipVerify: true, // lgtm[go/disabled-certificate-check]
				},
			},
		},
		dialer: &net.Dialer{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *client) Get(url string) (*http.Response, error) {
	return c.http.Get(url)
}

func (c *client) LookupTxt(name string) ([]string, error) {
	return net.LookupTXT(name)
}

func (c *client) TLSDial(network, addr string, config *tls.Config) (*tls.Conn, error) {
	return tls.DialWithDialer(c.dialer, network, addr, config)
}
