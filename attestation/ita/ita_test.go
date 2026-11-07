package ita

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/jose"

	"github.com/smallstep/certificates/attestation"
	cstest "github.com/smallstep/certificates/attestation/confidentialspace/confidentialspacetest"
)

const testKID = "test-signing-key.PS384"

// testNow is now: the test PKI is valid from when it is created.
var testNow = time.Now().Truncate(time.Second)

// server publishes keys the way Intel Trust Authority does, counting fetches.
type server struct {
	*httptest.Server
	fetches atomic.Int32
	keys    jose.JSONWebKeySet
}

func newServer(t *testing.T, keys ...jose.JSONWebKey) *server {
	t.Helper()
	s := &server{keys: jose.JSONWebKeySet{Keys: keys}}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s.fetches.Add(1)
		_ = json.NewEncoder(w).Encode(s.keys)
	}))
	t.Cleanup(s.Close)
	return s
}

func publishedKey(pki *cstest.PKI, kid string) jose.JSONWebKey {
	return jose.JSONWebKey{Key: pki.Leaf.PublicKey, KeyID: kid, Algorithm: jose.PS384, Use: "sig", Certificates: pki.Chain()}
}

func userData() []byte {
	b := make([]byte, UserDataSize)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

// tdxClaims returns the tdx claims of a token for userData, with a verifier
// nonce if nonce is set.
func tdxClaims(ud []byte, nonce bool) map[string]any {
	h := sha512.New()
	claims := map[string]any{
		"tdx_is_debuggable":   false,
		"attester_tcb_status": "UpToDate",
		"attester_user_data":  base64.StdEncoding.EncodeToString(ud),
		"tdx_mrtd":            "efef2faf",
	}
	if nonce {
		val, iat := []byte("bm9uY2U="), []byte("2026-11-07 12:00:00 +0000 UTC")
		h.Write(val)
		h.Write(iat)
		claims["verifier_nonce"] = map[string]any{
			"val": base64.StdEncoding.EncodeToString(val),
			"iat": base64.StdEncoding.EncodeToString(iat),
		}
	}
	h.Write(ud)
	claims["attester_runtime_data"] = map[string]any{"user-data": hex.EncodeToString(h.Sum(nil))}
	return claims
}

func tokenClaims(tdx map[string]any) map[string]any {
	return map[string]any{
		"iss": Issuer,
		"iat": testNow.Unix(),
		"nbf": testNow.Unix(),
		"exp": testNow.Add(5 * time.Minute).Unix(),
		"jti": "28aa9e11-19fc-46ee-bf65-ab99373b3dfb",
		"tdx": tdx,
		"tpm": map[string]any{"pcrs": []map[string]any{{"index": 7, "alg": "SHA-256", "digest": "f014e5cb"}}},
	}
}

func mint(t *testing.T, key crypto.Signer, alg jose.SignatureAlgorithm, kid, jku string, claims map[string]any) string {
	t.Helper()
	so := new(jose.SignerOptions).WithType("JWT").WithHeader("kid", kid)
	if jku != "" {
		so = so.WithHeader("jku", jku)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, so)
	require.NoError(t, err)
	token, err := jose.Signed(signer).Claims(claims).CompactSerialize()
	require.NoError(t, err)
	return token
}

func TestVerify(t *testing.T) {
	pki := cstest.New(t)
	srv := newServer(t, publishedKey(pki, testKID))
	opts := func() Options {
		return Options{Keys: NewKeySet(srv.URL, srv.Client()), Roots: pki.Roots(), Now: testNow}
	}

	for _, nonce := range []bool{false, true} {
		token := mint(t, pki.LeafKey, jose.PS384, testKID, srv.URL, tokenClaims(tdxClaims(userData(), nonce)))
		tok, err := Verify(context.Background(), token, opts())
		require.NoError(t, err, "nonce %v", nonce)
		assert.Equal(t, userData(), tok.UserData)
		assert.Equal(t, "UpToDate", tok.Claims.TDX.TCBStatus)
		res := tok.Result()
		assert.Equal(t, pki.Leaf.SerialNumber.String(), res.SignerSerialNumber)
		assert.Contains(t, res.Claims, "tpm")
	}

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	wrongKey := publishedKey(pki, "wrong-key")
	wrongKey.Key = otherKey.Public()
	wrongKeySrv := newServer(t, wrongKey)
	otherPKI := cstest.New(t)

	change := func(f func(tdx map[string]any)) map[string]any {
		tdx := tdxClaims(userData(), false)
		f(tdx)
		return tokenClaims(tdx)
	}
	claims := func(f func(c map[string]any)) map[string]any {
		c := tokenClaims(tdxClaims(userData(), false))
		f(c)
		return c
	}
	tests := []struct {
		name    string
		token   string
		opts    func() Options
		wantErr string
	}{
		{"fail algorithm", mint(t, pki.LeafKey, jose.RS512, testKID, "", tokenClaims(tdxClaims(userData(), false))), opts,
			`unsupported intel trust authority token algorithm "RS512"`},
		{"fail jku", mint(t, pki.LeafKey, jose.PS384, testKID, "https://evil.example/certs", tokenClaims(tdxClaims(userData(), false))), opts,
			"is not " + srv.URL},
		{"fail unknown kid", mint(t, pki.LeafKey, jose.PS384, "unknown", "", tokenClaims(tdxClaims(userData(), false))), opts,
			`no token signing key "unknown"`},
		{"fail untrusted chain", mint(t, pki.LeafKey, jose.PS384, testKID, "", tokenClaims(tdxClaims(userData(), false))),
			func() Options { o := opts(); o.Roots = otherPKI.Roots(); return o }, "chain is not valid"},
		{"fail signature", mint(t, otherKey, jose.PS384, testKID, "", tokenClaims(tdxClaims(userData(), false))), opts,
			"error verifying intel trust authority token"},
		{"fail issuer", mint(t, pki.LeafKey, jose.PS384, testKID, "", claims(func(c map[string]any) { c["iss"] = "https://other.example" })), opts,
			"token is not valid"},
		{"fail expired", mint(t, pki.LeafKey, jose.PS384, testKID, "", claims(func(c map[string]any) { c["exp"] = testNow.Add(-2 * time.Minute).Unix() })), opts,
			"token is not valid"},
		{"fail too old", mint(t, pki.LeafKey, jose.PS384, testKID, "", claims(func(c map[string]any) {
			c["iat"] = testNow.Add(-10 * time.Minute).Unix()
			c["nbf"] = c["iat"]
		})), opts, "too old"},
		{"fail no tdx", mint(t, pki.LeafKey, jose.PS384, testKID, "", claims(func(c map[string]any) { delete(c, "tdx") })), opts,
			"has no tdx claims"},
		{"fail debuggable", mint(t, pki.LeafKey, jose.PS384, testKID, "", change(func(tdx map[string]any) { tdx["tdx_is_debuggable"] = true })), opts,
			"debuggable"},
		{"fail debuggable missing", mint(t, pki.LeafKey, jose.PS384, testKID, "", change(func(tdx map[string]any) { delete(tdx, "tdx_is_debuggable") })), opts,
			"debuggable"},
		{"fail user data size", mint(t, pki.LeafKey, jose.PS384, testKID, "", tokenClaims(tdxClaims(userData()[:32], false))), opts,
			"not the base64 encoding of 64 bytes"},
		{"fail runtime data", mint(t, pki.LeafKey, jose.PS384, testKID, "", change(func(tdx map[string]any) {
			tdx["attester_runtime_data"] = map[string]any{"user-data": hex.EncodeToString(make([]byte, 64))}
		})), opts, "runtime data does not commit to its user data"},
		{"fail nonce not base64", mint(t, pki.LeafKey, jose.PS384, testKID, "", change(func(tdx map[string]any) {
			tdx["verifier_nonce"] = map[string]any{"val": "***", "iat": "***"}
		})), opts, "verifier_nonce is not base64"},
		{"fail not a token", "not a token", opts, "error parsing intel trust authority token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Verify(context.Background(), tt.token, tt.opts())
			assert.ErrorContains(t, err, tt.wantErr)
			assert.True(t, errors.Is(err, attestation.ErrInvalidEvidence))
		})
	}

	t.Run("fail key is not the certificate's", func(t *testing.T) {
		// go-jose refuses a published key whose x5c leaf holds another key,
		// so the key set cannot be used at all.
		token := mint(t, otherKey, jose.PS384, "wrong-key", "", tokenClaims(tdxClaims(userData(), false)))
		o := opts()
		o.Keys = NewKeySet(wrongKeySrv.URL, wrongKeySrv.Client())
		_, err := Verify(context.Background(), token, o)
		assert.ErrorContains(t, err, "public keys in key and x5c fields do not match")
	})

	t.Run("fail no keys", func(t *testing.T) {
		_, err := Verify(context.Background(), "x", Options{})
		assert.EqualError(t, err, "no keys to verify the intel trust authority token with")
	})
}

func TestKeySet(t *testing.T) {
	pki := cstest.New(t)
	srv := newServer(t, publishedKey(pki, testKID))
	now := testNow
	s := NewKeySet(srv.URL, srv.Client())
	s.now = func() time.Time { return now }

	_, err := s.Key(context.Background(), testKID)
	require.NoError(t, err)
	_, err = s.Key(context.Background(), testKID)
	require.NoError(t, err)
	assert.Equal(t, int32(1), srv.fetches.Load(), "a known key is served from the cache")

	// An unknown key fetches again only after keySetRetry.
	_, err = s.Key(context.Background(), "rotated")
	assert.ErrorContains(t, err, `no token signing key "rotated"`)
	assert.Equal(t, int32(1), srv.fetches.Load())
	srv.keys.Keys = append(srv.keys.Keys, publishedKey(pki, "rotated"))
	now = now.Add(keySetRetry + time.Second)
	_, err = s.Key(context.Background(), "rotated")
	require.NoError(t, err)
	assert.Equal(t, int32(2), srv.fetches.Load())

	// Keys are fetched again after keySetTTL.
	now = now.Add(keySetTTL + time.Second)
	_, err = s.Key(context.Background(), testKID)
	require.NoError(t, err)
	assert.Equal(t, int32(3), srv.fetches.Load())

	assert.Equal(t, DefaultJWKSURL, NewKeySet("", nil).URL())
}

func TestKeySetFetchErrors(t *testing.T) {
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer failing.Close()
	garbage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer garbage.Close()

	for name, url := range map[string]string{"status": failing.URL, "json": garbage.URL} {
		t.Run(name, func(t *testing.T) {
			_, err := NewKeySet(url, http.DefaultClient).Key(context.Background(), testKID)
			require.Error(t, err)
			// The CA could not fetch keys: that is not the evidence's fault.
			assert.False(t, errors.Is(err, attestation.ErrInvalidEvidence))
		})
	}
}

func TestIsToken(t *testing.T) {
	pki := cstest.New(t)
	assert.True(t, IsToken(mint(t, pki.LeafKey, jose.PS384, testKID, "", tokenClaims(nil))))
	assert.False(t, IsToken(mint(t, pki.LeafKey, jose.RS256, testKID, "", map[string]any{"iss": "https://confidentialcomputing.googleapis.com"})))
	assert.False(t, IsToken("not a token"))
}

func TestRoots(t *testing.T) {
	subjects := Roots().Subjects() //nolint:staticcheck // the pool is built from PEM, not the system
	require.Len(t, subjects, 1)
	c, err := parseFirst(rootPEM)
	require.NoError(t, err)
	assert.Equal(t, "Intel Trust Authority Root CA", c.Subject.CommonName)
}

func parseFirst(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no pem block")
	}
	return x509.ParseCertificate(block.Bytes)
}
