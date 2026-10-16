package acme

import (
    "context"
    "crypto/tls"
    "net"
    "net/http"
    "net/url"
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
    // resolver is used for DNS lookups; defaults to net.DefaultResolver
    resolver *net.Resolver
}

// ClientOption configures the ACME client.
type ClientOption func(*client)

// WithProxyURL configures the HTTP(S) proxy to use for ACME HTTP requests.
// Example: WithProxyURL("http://proxy.local:3128") or WithProxyURL("socks5://...").
func WithProxyURL(proxyURL string) ClientOption {
    return func(c *client) {
        if tr, ok := c.http.Transport.(*http.Transport); ok {
            if u, err := url.Parse(proxyURL); err == nil {
                tr.Proxy = http.ProxyURL(u)
            }
        }
    }
}

// WithProxyFunc sets a custom proxy selection function, overriding environment variables.
func WithProxyFunc(fn func(*http.Request) (*url.URL, error)) ClientOption {
    return func(c *client) {
        if tr, ok := c.http.Transport.(*http.Transport); ok {
            tr.Proxy = fn
        }
    }
}

// WithResolver sets a custom DNS resolver to be used for both TXT lookups and dialing.
func WithResolver(r *net.Resolver) ClientOption {
    return func(c *client) {
        c.resolver = r
        c.dialer.Resolver = r
    }
}

// WithDNS configures the client to use a specific DNS server for all lookups and dialing.
// The address should be in host:port form, e.g. "8.8.8.8:53".
func WithDNS(addr string) ClientOption {
    return func(c *client) {
        r := &net.Resolver{
            PreferGo: true,
            Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
                d := &net.Dialer{Timeout: 5 * time.Second}
                return d.DialContext(ctx, network, addr)
            },
        }
        c.resolver = r
        c.dialer.Resolver = r
    }
}

// NewClientWithOptions returns an implementation of Client for verifying ACME challenges.
// It accepts optional ClientOptions to override proxy and DNS resolver behavior.
func NewClientWithOptions(opts ...ClientOption) Client {
    d := &net.Dialer{Timeout: 30 * time.Second}
    // Default transport uses environment proxy and our dialer so that custom resolver applies to HTTP too.
    tr := &http.Transport{
        Proxy: http.ProxyFromEnvironment,
        DialContext: d.DialContext,
        TLSClientConfig: &tls.Config{
            //nolint:gosec // used on tls-alpn-01 challenge
            InsecureSkipVerify: true, // lgtm[go/disabled-certificate-check]
        },
    }
    c := &client{
        http: &http.Client{
            Timeout:   30 * time.Second,
            Transport: tr,
        },
        dialer:   d,
        resolver: net.DefaultResolver,
    }

    // Apply options
    for _, opt := range opts {
        opt(c)
    }
    // Ensure transport dialer is bound (in case options replaced dialer.resolver)
    if tr2, ok := c.http.Transport.(*http.Transport); ok {
        tr2.DialContext = c.dialer.DialContext
    }
    return c
}

// NewClient returns an implementation of Client with default settings
// (proxy from environment and system DNS resolver). For custom configuration
// use NewClientWithOptions.
func NewClient(opts ...ClientOption) Client { // keep signature source-compatible for callers without options
    return NewClientWithOptions(opts...)
}

func (c *client) Get(url string) (*http.Response, error) {
	return c.http.Get(url)
}

func (c *client) LookupTxt(name string) ([]string, error) {
    // Prefer custom resolver with a bounded timeout
    if c.resolver != nil {
        ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
        defer cancel()
        return c.resolver.LookupTXT(ctx, name)
    }
    return net.LookupTXT(name)
}

func (c *client) TLSDial(network, addr string, config *tls.Config) (*tls.Conn, error) {
	return tls.DialWithDialer(c.dialer, network, addr, config)
}
