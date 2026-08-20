package provisioner

import (
	"encoding/json"
	"io"
	"math/rand"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/pkg/errors"
	"go.step.sm/crypto/jose"
)

const (
	defaultCacheAge    = 12 * time.Hour
	defaultCacheJitter = 1 * time.Hour
	// minReloadInterval is the minimum time between cache refreshes on cache
	// misses.
	minReloadInterval = 1 * time.Minute
)

var maxAgeRegex = regexp.MustCompile(`max-age=(\d+)`)

type keyStore struct {
	sync.RWMutex
	client     HTTPClient
	uri        string
	keySet     jose.JSONWebKeySet
	expiry     time.Time
	jitter     time.Duration
	nextReload time.Time
}

func newKeyStore(client HTTPClient, uri string) (*keyStore, error) {
	keys, age, err := getKeysFromJWKsURI(client, uri)
	if err != nil {
		return nil, err
	}
	jitter := getCacheJitter(age)
	return &keyStore{
		client: client,
		uri:    uri,
		keySet: keys,
		expiry: getExpirationTime(age, jitter),
		jitter: jitter,
	}, nil
}

func (ks *keyStore) Get(kid string) (keys []jose.JSONWebKey) {
	ks.RLock()
	// Force reload if expiration has passed
	if time.Now().After(ks.expiry) {
		ks.RUnlock()
		ks.reload()
		ks.RLock()
	}
	keys = ks.keySet.Key(kid)
	// An identity provider can start signing with a new key before the cached
	// key set expires. Reload on an unknown key id so those tokens are not
	// rejected for the remainder of the cache lifetime, which is dictated by
	// the endpoint's cache-control header and can be arbitrarily long.
	if len(keys) == 0 && time.Now().After(ks.nextReload) {
		ks.RUnlock()
		ks.reload()
		ks.RLock()
		keys = ks.keySet.Key(kid)
	}
	ks.RUnlock()
	return
}

func (ks *keyStore) reload() {
	keys, age, err := getKeysFromJWKsURI(ks.client, ks.uri)

	ks.Lock()
	// Set on failure too, so that a key id no reload can resolve does not cause
	// a request per token.
	ks.nextReload = time.Now().Add(minReloadInterval)
	if err == nil {
		ks.keySet = keys
		ks.jitter = getCacheJitter(age)
		ks.expiry = getExpirationTime(age, ks.jitter)
	}
	ks.Unlock()
}

func getKeysFromJWKsURI(client HTTPClient, uri string) (jose.JSONWebKeySet, time.Duration, error) {
	var keys jose.JSONWebKeySet
	resp, err := client.Get(uri)
	if err != nil {
		return keys, 0, errors.Wrapf(err, "failed to connect to %s", uri)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return keys, 0, errors.Wrapf(err, "error reading response from %s", uri)
	}
	// An error response carrying a JSON body decodes into an empty key set
	// without error, which reload would then install in place of a usable one.
	if resp.StatusCode >= 400 {
		return keys, 0, errors.Errorf("error reading %s: status=%d, response=%s", uri, resp.StatusCode, b)
	}
	if err := json.Unmarshal(b, &keys); err != nil {
		return keys, 0, errors.Wrapf(err, "error reading %s", uri)
	}
	return keys, getCacheAge(resp.Header.Get("cache-control")), nil
}

func getCacheAge(cacheControl string) time.Duration {
	age := defaultCacheAge
	if cacheControl != "" {
		match := maxAgeRegex.FindAllStringSubmatch(cacheControl, -1)
		if len(match) > 0 {
			if len(match[0]) == 2 {
				maxAge := match[0][1]
				maxAgeInt, err := strconv.ParseInt(maxAge, 10, 64)
				if err != nil {
					return defaultCacheAge
				}
				age = time.Duration(maxAgeInt) * time.Second
			}
		}
	}
	return age
}

func getCacheJitter(age time.Duration) time.Duration {
	switch {
	case age > time.Hour:
		return defaultCacheJitter
	case age == 0:
		// Avoids a 0 jitter. The duration is not important as it will rotate
		// automatically on each Get request.
		return defaultCacheJitter
	default:
		return age / 3
	}
}

func getExpirationTime(age, jitter time.Duration) time.Time {
	if age > 0 {
		n := rand.Int63n(int64(jitter)) //nolint:gosec // not used for cryptographic security
		age -= time.Duration(n)
	}
	return time.Now().Truncate(time.Second).Add(abs(age))
}

// abs returns the absolute value of n.
func abs(n time.Duration) time.Duration {
	if n < 0 {
		return -n
	}
	return n
}
