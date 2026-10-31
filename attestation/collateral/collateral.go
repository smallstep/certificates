// Package collateral fetches and caches the collateral that TEE evidence is
// verified with: TCB information, identities, certificates and revocation
// lists from Intel's provisioning certification service and AMD's key
// distribution service.
package collateral

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// TTL is how long a Getter keeps a response. The verifiers still check each
// item's own validity.
const TTL = time.Hour

// MaxSize limits the size of a response.
const MaxSize = 1 << 20

// HTTPClient is the interface of the client a Getter fetches with, which
// *http.Client implements.
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// Getter fetches collateral and caches successful responses for TTL, so that
// verifying evidence does not depend on, or overload, the vendors' services on
// every request.
type Getter struct {
	client  HTTPClient
	now     func() time.Time
	mu      sync.Mutex
	entries map[string]entry
}

type entry struct {
	header  http.Header
	body    []byte
	expires time.Time
}

// New returns a Getter that fetches with the given client.
func New(client HTTPClient) *Getter {
	return &Getter{
		client:  client,
		now:     time.Now,
		entries: make(map[string]entry),
	}
}

func (g *Getter) get(ctx context.Context, url string) (http.Header, []byte, error) {
	now := g.now()
	g.mu.Lock()
	e, ok := g.entries[url]
	g.mu.Unlock()
	if ok && now.Before(e.expires) {
		return e.header, e.body, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, nil, err
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error fetching %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("error fetching %s: status code %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxSize))
	if err != nil {
		return nil, nil, fmt.Errorf("error reading %s: %w", url, err)
	}

	g.mu.Lock()
	g.entries[url] = entry{
		header:  resp.Header,
		body:    body,
		expires: now.Add(TTL),
	}
	g.mu.Unlock()
	return resp.Header, body, nil
}

// TDX adapts a Getter to go-tdx-guest's trust.HTTPSGetter and
// trust.ContextHTTPSGetter, which return the response headers too.
type TDX struct {
	*Getter
}

// Get implements go-tdx-guest's trust.HTTPSGetter.
func (g TDX) Get(url string) (map[string][]string, []byte, error) {
	return g.GetContext(context.Background(), url)
}

// GetContext implements go-tdx-guest's trust.ContextHTTPSGetter.
func (g TDX) GetContext(ctx context.Context, url string) (map[string][]string, []byte, error) {
	return g.get(ctx, url)
}

// SEVSNP adapts a Getter to go-sev-guest's trust.HTTPSGetter and
// trust.ContextHTTPSGetter.
type SEVSNP struct {
	*Getter
}

// Get implements go-sev-guest's trust.HTTPSGetter.
func (g SEVSNP) Get(url string) ([]byte, error) {
	return g.GetContext(context.Background(), url)
}

// GetContext implements go-sev-guest's trust.ContextHTTPSGetter.
func (g SEVSNP) GetContext(ctx context.Context, url string) ([]byte, error) {
	_, body, err := g.get(ctx, url)
	return body, err
}
