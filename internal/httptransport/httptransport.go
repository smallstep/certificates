// Package httptransport implements initialization of [http.Transport] instances and related
// functionality.
package httptransport

import (
	"net"
	"net/http"
	"time"
)

// Wrapper wraps the set of functions mapping [http.Transport] references to [http.RoundTripper].
type Wrapper func(*http.Transport) http.RoundTripper

// NoopWrapper returns a [Wrapper] that simply casts its provided [http.Transport] to an
// [http.RoundTripper].
func NoopWrapper() Wrapper {
	return func(t *http.Transport) http.RoundTripper {
		return t
	}
}

// New returns a reference to an [http.Transport] that's initialized just like the
// [http.DefaultTransport] is by the standard library.
func New() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}
