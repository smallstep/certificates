package collateral

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetter(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/missing" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("TCB-Info-Issuer-Chain", "chain")
		_, _ = w.Write([]byte("collateral"))
	}))
	t.Cleanup(srv.Close)

	now := time.Now()
	g := New(srv.Client())
	g.now = func() time.Time { return now }
	tdx := TDX{g}
	sev := SEVSNP{g}

	header, body, err := tdx.Get(srv.URL + "/tcb")
	require.NoError(t, err)
	assert.Equal(t, []byte("collateral"), body)
	assert.Equal(t, []string{"chain"}, header["Tcb-Info-Issuer-Chain"])

	// A cached response is served without a request, to either library.
	body, err = sev.GetContext(context.Background(), srv.URL+"/tcb")
	require.NoError(t, err)
	assert.Equal(t, []byte("collateral"), body)
	assert.Equal(t, int32(1), hits.Load())

	// After the TTL it is fetched again.
	now = now.Add(TTL + time.Second)
	_, err = sev.Get(srv.URL + "/tcb")
	require.NoError(t, err)
	assert.Equal(t, int32(2), hits.Load())

	// Failures are not cached.
	for range 2 {
		_, _, err = tdx.GetContext(context.Background(), srv.URL+"/missing")
		assert.ErrorContains(t, err, "status code 404")
	}
	assert.Equal(t, int32(4), hits.Load())
}
