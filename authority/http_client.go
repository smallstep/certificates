package authority

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
)

// newHTTPClient will return an HTTP client that trusts the system cert pool and
// the given roots, but only if the http.DefaultTransport is an *http.Transport.
// If not, it will return the default HTTP client.
func newHTTPClient(roots ...*x509.Certificate) (*http.Client, error) {
	if tr, ok := http.DefaultTransport.(*http.Transport); ok {
		pool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("error initializing http client: %w", err)
		}
		for _, crt := range roots {
			pool.AddCert(crt)
		}

		tr = tr.Clone()
		tr.TLSClientConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    pool,
		}
		return &http.Client{
			Transport: tr,
		}, nil
	}

	return &http.Client{}, nil
}
