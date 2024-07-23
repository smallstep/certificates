package authority

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
)

// newHTTPClient returns an HTTP client that trusts the system cert pool and the
// given roots.
func newHTTPClient(roots ...*x509.Certificate) (*http.Client, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("error initializing http client: %w", err)
	}
	for _, crt := range roots {
		pool.AddCert(crt)
	}

	tr, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("error initializing http client: type is not *http.Transport")
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
