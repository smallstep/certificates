package provisioner

import (
	"encoding/json"
	"math/rand"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/jose"
)

const (
	defaultCacheAge    = 12 * time.Hour
	defaultCacheJitter = 1 * time.Hour
)

var maxAgeRegex = regexp.MustCompile("max-age=([0-9]*)")

type keyStore struct {
	sync.RWMutex
	uri    string
	keys   jose.JSONWebKeySet
	timer  *time.Timer
	expiry time.Time
}

func newKeyStore(uri string) (*keyStore, error) {
	keys, age, err := getKeysFromJWKsURI(uri)
	if err != nil {
		return nil, err
	}
	ks := &keyStore{
		uri:    uri,
		keys:   keys,
		expiry: getExpirationTime(age),
	}
	ks.timer = time.AfterFunc(age, ks.reload)
	return ks, nil
}

func (ks *keyStore) Close() {
	ks.timer.Stop()
}

func (ks *keyStore) Get(kid string) (keys []jose.JSONWebKey) {
	ks.RLock()
	// Force reload if expiration has passed
	if time.Now().After(ks.expiry) {
		ks.RUnlock()
		ks.reload()
		ks.RLock()
	}
	keys = ks.keys.Key(kid)
	ks.RUnlock()
	return
}

func (ks *keyStore) reload() {
	var next time.Duration
	keys, age, err := getKeysFromJWKsURI(ks.uri)
	if err != nil {
		next = ks.nextReloadDuration(defaultCacheJitter / 2)
	} else {
		ks.Lock()
		ks.keys = keys
		ks.expiry = time.Now().Round(time.Second).Add(age - 1*time.Minute).UTC()
		ks.Unlock()
		next = ks.nextReloadDuration(age)
	}

	ks.Lock()
	ks.timer.Reset(next)
	ks.Unlock()
}

func (ks *keyStore) nextReloadDuration(age time.Duration) time.Duration {
	n := rand.Int63n(int64(defaultCacheJitter))
	age -= time.Duration(n)
	if age < 0 {
		age = 0
	}
	return age
}

func getKeysFromJWKsURI(uri string) (jose.JSONWebKeySet, time.Duration, error) {
	var keys jose.JSONWebKeySet
	resp, err := http.Get(uri)
	if err != nil {
		return keys, 0, errors.Wrapf(err, "failed to connect to %s", uri)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return keys, 0, errors.Wrapf(err, "error reading %s", uri)
	}
	return keys, getCacheAge(resp.Header.Get("cache-control")), nil
}

func getCacheAge(cacheControl string) time.Duration {
	age := defaultCacheAge
	if len(cacheControl) > 0 {
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

func getExpirationTime(age time.Duration) time.Time {
	return time.Now().Round(time.Second).Add(age - 1*time.Minute).UTC()
}
