package poolhttp

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func requireBody(t *testing.T, want string, r io.ReadCloser) {
	t.Helper()
	t.Cleanup(func() {
		require.NoError(t, r.Close())
	})

	b, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, want, string(b))
}

func TestClient(t *testing.T) {
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello World")
	}))
	t.Cleanup(httpSrv.Close)
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello World")
	}))
	t.Cleanup(tlsSrv.Close)

	tests := []struct {
		name   string
		client *Client
		srv    *httptest.Server
	}{
		{"http", New(func() *http.Client { return httpSrv.Client() }), httpSrv},
		{"tls", New(func() *http.Client { return tlsSrv.Client() }), tlsSrv},
		{"nil", New(func() *http.Client { return nil }), httpSrv},
		{"empty", &Client{}, httpSrv},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := tc.client.Get(tc.srv.URL)
			require.NoError(t, err)
			requireBody(t, "Hello World\n", resp.Body)

			req, err := http.NewRequest("GET", tc.srv.URL, http.NoBody)
			require.NoError(t, err)

			resp, err = tc.client.Do(req)
			require.NoError(t, err)
			requireBody(t, "Hello World\n", resp.Body)

			client := &http.Client{
				Transport: tc.client.Transport(),
			}
			resp, err = client.Get(tc.srv.URL)
			require.NoError(t, err)
			requireBody(t, "Hello World\n", resp.Body)
		})
	}
}

func TestClient_SetNew(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello World")
	}))
	t.Cleanup(srv.Close)

	c := New(func() *http.Client {
		return srv.Client()
	})

	tests := []struct {
		name      string
		client    *http.Client
		assertion assert.ErrorAssertionFunc
	}{
		{"ok", srv.Client(), assert.NoError},
		{"fail", http.DefaultClient, assert.Error},
		{"ok again", srv.Client(), assert.NoError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c.SetNew(func() *http.Client {
				return tc.client
			})
			_, err := c.Get(srv.URL)
			tc.assertion(t, err)

		})
	}
}

func TestClient_parallel(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello World")
	}))
	t.Cleanup(srv.Close)

	c := New(func() *http.Client {
		return srv.Client()
	})
	req, err := http.NewRequest("GET", srv.URL, http.NoBody)
	require.NoError(t, err)

	for i := range 10 {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			t.Parallel()
			resp, err := c.Get(srv.URL)
			require.NoError(t, err)
			requireBody(t, "Hello World\n", resp.Body)

			resp, err = c.Do(req)
			require.NoError(t, err)
			requireBody(t, "Hello World\n", resp.Body)
		})
	}
}
