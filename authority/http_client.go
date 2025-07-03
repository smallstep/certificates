package authority

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"sync/atomic"

	"github.com/smallstep/certificates/authority/poolhttp"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/internal/httptransport"
)

// systemCertPool holds a copy of the system cert pool. This cert pool must be
// initialized when the authority is created and we should always get a clone of
// this pool.
var systemCertPool atomic.Pointer[x509.CertPool]

// initializeSystemCertPool initializes the system cert pool if necessary.
func initializeSystemCertPool() error {
	if systemCertPool.Load() == nil {
		pool, err := x509.SystemCertPool()
		if err != nil {
			return err
		}
		systemCertPool.Store(pool)
	}
	return nil
}

// newHTTPClient will return an HTTP client that trusts the system cert pool and
// the given roots.
func newHTTPClient(wt httptransport.Wrapper, roots ...*x509.Certificate) provisioner.HTTPClient {
	return poolhttp.New(func() *http.Client {
		pool := systemCertPool.Load().Clone()
		for _, crt := range roots {
			pool.AddCert(crt)
		}

		tr, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			tr = httptransport.New()
		} else {
			tr = tr.Clone()
		}

		tr.TLSClientConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    pool,
		}

		rr := wt(tr)

		return &http.Client{Transport: rr}
	})
}
