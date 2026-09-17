package provisioner

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/smallstep/assert"
	"go.step.sm/crypto/jose"
)

func Test_newKeyStore(t *testing.T) {
	srv := generateTLSJWKServer(2)
	srv.Close()

	srv = httptest.NewTLSServer(srv.Config.Handler)
	defer srv.Close()

	ks, err := newKeyStore(srv.Client(), srv.URL)
	assert.FatalError(t, err)

	type args struct {
		client *http.Client
		uri    string
	}
	tests := []struct {
		name    string
		args    args
		want    jose.JSONWebKeySet
		wantErr bool
	}{
		{"ok", args{srv.Client(), srv.URL}, ks.keySet, false},
		{"fail", args{srv.Client(), srv.URL + "/error"}, jose.JSONWebKeySet{}, true},
		{"fail json error body", args{srv.Client(), srv.URL + "/error-json"}, jose.JSONWebKeySet{}, true},
		{"fail client", args{http.DefaultClient, srv.URL}, jose.JSONWebKeySet{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newKeyStore(tt.args.client, tt.args.uri)
			if (err != nil) != tt.wantErr {
				t.Errorf("newKeyStore() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				if !reflect.DeepEqual(got.keySet, tt.want) {
					t.Errorf("newKeyStore() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func Test_keyStore(t *testing.T) {
	srv := generateJWKServer(2)
	defer srv.Close()

	ks, err := newKeyStore(srv.Client(), srv.URL+"/random")
	assert.FatalError(t, err)
	ks.RLock()
	keySet1 := ks.keySet
	ks.RUnlock()
	// Check contents
	assert.Len(t, 2, keySet1.Keys)
	assert.Len(t, 1, ks.Get(keySet1.Keys[0].KeyID))
	assert.Len(t, 1, ks.Get(keySet1.Keys[1].KeyID))
	assert.Len(t, 0, ks.Get("foobar"))

	// Wait for rotation
	time.Sleep(5 * time.Second)
	assert.Len(t, 0, ks.Get("foobar")) // force refresh

	ks.RLock()
	keySet2 := ks.keySet
	ks.RUnlock()
	if reflect.DeepEqual(keySet1, keySet2) {
		t.Error("keyStore did not rotated")
	}

	// Check contents
	assert.Len(t, 2, keySet2.Keys)
	assert.Len(t, 1, ks.Get(keySet2.Keys[0].KeyID))
	assert.Len(t, 1, ks.Get(keySet2.Keys[1].KeyID))
	assert.Len(t, 0, ks.Get("foobar"))

	// Check hits
	resp, err := srv.Client().Get(srv.URL + "/hits")
	assert.FatalError(t, err)
	hits := struct {
		Hits int `json:"hits"`
	}{}
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&hits)
	assert.FatalError(t, err)
	assert.True(t, hits.Hits > 1, fmt.Sprintf("invalid number of hits: %d is not greater than 1", hits.Hits))
}

func Test_keyStore_noCache(t *testing.T) {
	srv := generateJWKServer(2)
	defer srv.Close()

	ks, err := newKeyStore(srv.Client(), srv.URL+"/no-cache")
	assert.FatalError(t, err)
	ks.RLock()
	keySet1 := ks.keySet
	ks.RUnlock()
	// The keys will rotate on Get.
	// So we won't be able to find the cached ones
	assert.Len(t, 2, keySet1.Keys)
	assert.Len(t, 0, ks.Get(keySet1.Keys[0].KeyID))
	assert.Len(t, 0, ks.Get(keySet1.Keys[1].KeyID))
	assert.Len(t, 0, ks.Get("foobar"))

	// Check hits
	resp, err := srv.Client().Get(srv.URL + "/hits")
	assert.FatalError(t, err)
	hits := struct {
		Hits int `json:"hits"`
	}{}
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&hits)
	assert.FatalError(t, err)
	assert.True(t, hits.Hits > 1, fmt.Sprintf("invalid number of hits: %d is not greater than 1", hits.Hits))
}

func Test_keyStore_Get(t *testing.T) {
	srv := generateJWKServer(2)
	defer srv.Close()
	ks, err := newKeyStore(srv.Client(), srv.URL)
	assert.FatalError(t, err)

	type args struct {
		kid string
	}
	tests := []struct {
		name     string
		ks       *keyStore
		args     args
		wantKeys []jose.JSONWebKey
	}{
		{"ok1", ks, args{ks.keySet.Keys[0].KeyID}, []jose.JSONWebKey{ks.keySet.Keys[0]}},
		{"ok2", ks, args{ks.keySet.Keys[1].KeyID}, []jose.JSONWebKey{ks.keySet.Keys[1]}},
		{"fail", ks, args{"fail"}, []jose.JSONWebKey(nil)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotKeys := tt.ks.Get(tt.args.kid); !reflect.DeepEqual(gotKeys, tt.wantKeys) {
				t.Errorf("keyStore.Get() = %v, want %v", gotKeys, tt.wantKeys)
			}
		})
	}
}

func Test_keyStore_Get_unknownKeyID(t *testing.T) {
	srv := generateJWKServer(2)
	defer srv.Close()

	ks, err := newKeyStore(srv.Client(), srv.URL+"/rotate")
	assert.FatalError(t, err)
	ks.RLock()
	cached := ks.keySet
	ks.RUnlock()

	rotated := rotateJWKServer(t, srv)
	assert.Len(t, 1, ks.Get(cached.Keys[0].KeyID))

	assert.Len(t, 1, ks.Get(rotated.Keys[0].KeyID))
	assert.Len(t, 1, ks.Get(rotated.Keys[1].KeyID))
}

func Test_keyStore_Get_unknownKeyIDIsRateLimited(t *testing.T) {
	srv := generateJWKServer(2)
	defer srv.Close()

	client := &countingClient{HTTPClient: srv.Client()}
	ks, err := newKeyStore(client, srv.URL+"/rotate")
	assert.FatalError(t, err)

	rotated := rotateJWKServer(t, srv)
	assert.Len(t, 1, ks.Get(rotated.Keys[0].KeyID))
	assert.Equals(t, 2, client.gets) // one on init, one on the unknown key id

	for range 10 {
		assert.Len(t, 0, ks.Get("foobar"))
	}
	assert.Equals(t, 2, client.gets)
}

func Test_keyStore_Get_unknownKeyIDCoalescesReloads(t *testing.T) {
	srv := generateJWKServer(2)
	defer srv.Close()

	client := &countingClient{HTTPClient: srv.Client()}
	ks, err := newKeyStore(client, srv.URL+"/rotate")
	assert.FatalError(t, err)

	rotated := rotateJWKServer(t, srv)

	// nextReload only advances once a reload finishes, so a simultaneous burst
	// all passes the check in Get.
	found := make([]int, 50)
	var wg sync.WaitGroup
	for i := range found {
		wg.Add(1)
		go func() {
			defer wg.Done()
			found[i] = len(ks.Get(rotated.Keys[0].KeyID))
		}()
	}
	wg.Wait()

	for _, n := range found {
		assert.Equals(t, 1, n)
	}
	assert.Equals(t, 2, client.gets) // one on init, one shared by the burst
}

func Test_keyStore_Get_failedReloadKeepsCachedKeys(t *testing.T) {
	srv := generateJWKServer(2)
	defer srv.Close()

	ks, err := newKeyStore(srv.Client(), srv.URL+"/rotate")
	assert.FatalError(t, err)
	ks.RLock()
	cached := ks.keySet
	ks.RUnlock()

	// The endpoint starts answering with a JSON error body, which decodes into
	// an empty key set unless the status code is checked.
	failJWKServer(t, srv)

	// An unknown key id triggers a reload, and that reload fails.
	assert.Len(t, 0, ks.Get("foobar"))

	assert.Len(t, 1, ks.Get(cached.Keys[0].KeyID))
	assert.Len(t, 1, ks.Get(cached.Keys[1].KeyID))
}

// rotateJWKServer rotates the keys on srv and returns the new set.
func rotateJWKServer(t *testing.T, srv *httptest.Server) jose.JSONWebKeySet {
	t.Helper()
	var keySet jose.JSONWebKeySet
	resp, err := srv.Client().Get(srv.URL + "/rotate/next")
	assert.FatalError(t, err)
	defer resp.Body.Close()
	assert.FatalError(t, json.NewDecoder(resp.Body).Decode(&keySet))
	return keySet
}

// failJWKServer makes the /rotate endpoint of srv start returning an error.
func failJWKServer(t *testing.T, srv *httptest.Server) {
	t.Helper()
	resp, err := srv.Client().Get(srv.URL + "/rotate/fail")
	assert.FatalError(t, err)
	assert.FatalError(t, resp.Body.Close())
}

type countingClient struct {
	HTTPClient
	mu   sync.Mutex
	gets int
}

func (c *countingClient) Get(uri string) (*http.Response, error) {
	c.mu.Lock()
	c.gets++
	c.mu.Unlock()
	return c.HTTPClient.Get(uri)
}

func Test_abs(t *testing.T) {
	maxInt64 := time.Duration(1<<63 - 1)
	minInt64 := time.Duration(-1 << 63)
	type args struct {
		n time.Duration
	}
	tests := []struct {
		name string
		args args
		want time.Duration
	}{
		{"ok", args{0}, 0},
		{"ok", args{-time.Hour}, time.Hour},
		{"ok", args{time.Hour}, time.Hour},
		{"ok maxInt64", args{maxInt64}, maxInt64},
		{"ok minInt64 + 1", args{minInt64 + 1}, maxInt64},
		{"overflow on minInt64", args{minInt64}, minInt64},
		{"overflow on minInt64", args{minInt64}, -minInt64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := abs(tt.args.n); got != tt.want {
				t.Errorf("abs() = %v, want %v", got, tt.want)
			}
		})
	}
}
