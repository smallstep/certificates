// Package ita verifies the attestation tokens Intel Trust Authority issues for
// Intel TDX trust domains, including Azure confidential VMs whose paravisor
// reports for the guest.
package ita

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sync"
	"time"

	"go.step.sm/crypto/jose"

	"github.com/smallstep/certificates/attestation"
)

const (
	// Issuer is the issuer of Intel Trust Authority's tokens.
	Issuer = "https://portal.trustauthority.intel.com"
	// DefaultJWKSURL is where Intel Trust Authority publishes the keys that
	// sign its tokens, each with its certificate chain.
	DefaultJWKSURL = "https://portal.trustauthority.intel.com/certs"
	// DefaultMaxTokenAge is the default maximum age of a token.
	DefaultMaxTokenAge = 5 * time.Minute
	// Leeway is the clock skew allowed when checking exp, nbf and iat.
	Leeway = time.Minute
	// UserDataSize is the size of the user data a token must carry: what
	// the caller binds.
	UserDataSize = 64

	// keySetTTL is how long fetched keys are used before they are fetched
	// again; keySetRetry is how soon an unknown key ID may cause a fetch.
	keySetTTL   = 15 * time.Minute
	keySetRetry = time.Minute
	maxKeySet   = 1 << 20
)

// rootPEM is "Intel Trust Authority Root CA", valid from 2024-11-27 to
// 2049-12-30, the root of the certificate chains Intel Trust Authority
// publishes with its token signing keys at DefaultJWKSURL. Its SHA-256
// fingerprint is
// 70:91:E8:9E:9A:17:B9:39:ED:C0:1F:0A:87:B0:C3:86:3F:22:42:29:9B:F3:C0:FF:D5:EE:4A:21:7F:F7:4F:5F.
//
//go:embed intel_trust_authority_root.crt
var rootPEM []byte

var roots = sync.OnceValue(func() *x509.CertPool {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(rootPEM) {
		panic("ita: the embedded root is not valid PEM")
	}
	return pool
})

// Roots returns a pool with Intel Trust Authority's root, the default for
// verifying the chains of its token signing keys.
func Roots() *x509.CertPool {
	return roots()
}

// HTTPClient sends HTTP requests.
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// KeySet fetches and caches the token signing keys published at a URL that is
// configured, never taken from a token.
type KeySet struct {
	url    string
	client HTTPClient
	now    func() time.Time

	mu        sync.Mutex
	keys      jose.JSONWebKeySet
	fetchedAt time.Time
}

// NewKeySet returns a KeySet for the keys at url, DefaultJWKSURL if empty.
func NewKeySet(url string, client HTTPClient) *KeySet {
	if url == "" {
		url = DefaultJWKSURL
	}
	return &KeySet{url: url, client: client, now: time.Now}
}

// URL returns the URL the keys are fetched from.
func (s *KeySet) URL() string {
	return s.url
}

// Key returns the key with the given ID. It fetches the keys when they are
// older than keySetTTL, or when the ID is unknown and the last fetch is older
// than keySetRetry, so that a rotated key is found. A failure to fetch does not
// match attestation.ErrInvalidEvidence.
func (s *KeySet) Key(ctx context.Context, kid string) (*jose.JSONWebKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	age := s.now().Sub(s.fetchedAt)
	keys := s.keys.Key(kid)
	if s.fetchedAt.IsZero() || age > keySetTTL || (len(keys) == 0 && age > keySetRetry) {
		if err := s.fetch(ctx); err != nil {
			return nil, err
		}
		keys = s.keys.Key(kid)
	}
	if len(keys) == 0 {
		return nil, attestation.Invalidf("intel trust authority has no token signing key %q", kid)
	}
	return &keys[0], nil
}

func (s *KeySet) fetch(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, http.NoBody)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("error fetching intel trust authority keys: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("error fetching intel trust authority keys: %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxKeySet+1))
	if err != nil {
		return fmt.Errorf("error fetching intel trust authority keys: %w", err)
	}
	if len(b) > maxKeySet {
		return errors.New("intel trust authority keys exceed 1 MiB")
	}
	var keys jose.JSONWebKeySet
	if err := json.Unmarshal(b, &keys); err != nil {
		return fmt.Errorf("error parsing intel trust authority keys: %w", err)
	}
	s.keys = keys
	s.fetchedAt = s.now()
	return nil
}

// Claims are the claims of a token that Verify checks.
type Claims struct {
	jose.Claims
	TDX *TDXClaims `json:"tdx"`
}

// TDXClaims are the claims of a token's tdx object that Verify checks.
type TDXClaims struct {
	IsDebuggable  *bool          `json:"tdx_is_debuggable"`
	UserData      string         `json:"attester_user_data"`
	RuntimeData   map[string]any `json:"attester_runtime_data"`
	VerifierNonce *struct {
		Val string `json:"val"`
		Iat string `json:"iat"`
	} `json:"verifier_nonce"`
	TCBStatus string `json:"attester_tcb_status"`
}

// Token is a verified token.
type Token struct {
	// Leaf is the certificate of the key that signed the token.
	Leaf *x509.Certificate
	// Claims are the claims Verify checked.
	Claims Claims
	// RawClaims are all the claims of the token.
	RawClaims map[string]any
	// UserData is the user data the token carries, which the attested
	// trust domain committed to.
	UserData []byte
}

// Result returns the token as an attestation result.
func (t *Token) Result() *attestation.ITA {
	return &attestation.ITA{
		Claims:             t.RawClaims,
		SignerSerialNumber: t.Leaf.SerialNumber.String(),
	}
}

// Options are the options Verify verifies a token with.
type Options struct {
	// Keys resolves the token's key ID. It is required.
	Keys *KeySet
	// Roots are the roots of the signing keys' chains. They default to
	// Roots().
	Roots *x509.CertPool
	// MaxTokenAge is the maximum age of the token. It defaults to
	// DefaultMaxTokenAge.
	MaxTokenAge time.Duration
	// Now is the time the token is verified at. It defaults to the current
	// time.
	Now time.Time
}

// allowedAlgorithms are the signature algorithms Intel Trust Authority signs
// tokens with.
var allowedAlgorithms = []string{jose.PS384, jose.RS256}

// Verify verifies an Intel Trust Authority token for an Intel TDX trust
// domain:
//   - the token's PS384 or RS256 signature, with the published key its kid
//     names, whose x5c chain must verify to the roots and whose leaf must be
//     that key;
//   - the issuer, the exp, nbf and iat claims, and the age of the token;
//   - that the trust domain is not debuggable;
//   - that the user data is 64 bytes, and that the runtime data's user-data,
//     which the TD quote committed to, is SHA-512 of the verifier nonce's val
//     and iat, if any, followed by the user data.
//
// Errors of the token match attestation.ErrInvalidEvidence.
func Verify(ctx context.Context, token string, opts Options) (*Token, error) {
	if opts.Keys == nil {
		return nil, errors.New("no keys to verify the intel trust authority token with")
	}
	if opts.Roots == nil {
		opts.Roots = Roots()
	}
	if opts.MaxTokenAge <= 0 {
		opts.MaxTokenAge = DefaultMaxTokenAge
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}

	jwt, err := jose.ParseSigned(token)
	if err != nil {
		return nil, attestation.Invalidf("error parsing intel trust authority token: %w", err)
	}
	if len(jwt.Headers) != 1 {
		return nil, attestation.Invalidf("intel trust authority token must have exactly one signature")
	}
	header := jwt.Headers[0]
	if !slices.Contains(allowedAlgorithms, header.Algorithm) {
		return nil, attestation.Invalidf("unsupported intel trust authority token algorithm %q", header.Algorithm)
	}
	if jku, ok := header.ExtraHeaders["jku"]; ok && jku != opts.Keys.URL() {
		return nil, attestation.Invalidf("intel trust authority token jku %v is not %s", jku, opts.Keys.URL())
	}
	if header.KeyID == "" {
		return nil, attestation.Invalidf("intel trust authority token has no kid")
	}
	key, err := opts.Keys.Key(ctx, header.KeyID)
	if err != nil {
		return nil, err
	}
	leaf, err := verifyChain(key, opts.Roots, opts.Now)
	if err != nil {
		return nil, err
	}

	var (
		claims    Claims
		rawClaims map[string]any
	)
	if err := jwt.Claims(leaf.PublicKey, &claims, &rawClaims); err != nil {
		return nil, attestation.Invalidf("error verifying intel trust authority token: %w", err)
	}
	if err := claims.ValidateWithLeeway(jose.Expected{Issuer: Issuer, Time: opts.Now}, Leeway); err != nil {
		return nil, attestation.Invalidf("intel trust authority token is not valid: %w", err)
	}
	if claims.Expiry == nil || claims.IssuedAt == nil {
		return nil, attestation.Invalidf("intel trust authority token must have exp and iat claims")
	}
	if age := opts.Now.Sub(claims.IssuedAt.Time()); age > opts.MaxTokenAge {
		return nil, attestation.Invalidf("intel trust authority token is too old: issued %s ago, the maximum is %s", age, opts.MaxTokenAge)
	}

	tdx := claims.TDX
	if tdx == nil {
		return nil, attestation.Invalidf("intel trust authority token has no tdx claims")
	}
	if tdx.IsDebuggable == nil || *tdx.IsDebuggable {
		return nil, attestation.Invalidf("intel trust authority token is for a debuggable trust domain")
	}
	userData, err := base64.StdEncoding.DecodeString(tdx.UserData)
	if err != nil || len(userData) != UserDataSize {
		return nil, attestation.Invalidf("intel trust authority token attester_user_data is not the base64 encoding of %d bytes", UserDataSize)
	}
	if err := checkRuntimeData(tdx, userData); err != nil {
		return nil, err
	}

	return &Token{Leaf: leaf, Claims: claims, RawClaims: rawClaims, UserData: userData}, nil
}

// verifyChain verifies the x5c chain of a published key and returns its leaf,
// which must hold the key.
func verifyChain(key *jose.JSONWebKey, roots *x509.CertPool, now time.Time) (*x509.Certificate, error) {
	if len(key.Certificates) == 0 {
		return nil, attestation.Invalidf("intel trust authority key %q has no certificate chain", key.KeyID)
	}
	leaf := key.Certificates[0]
	intermediates := x509.NewCertPool()
	for _, c := range key.Certificates[1:] {
		intermediates.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, attestation.Invalidf("intel trust authority key %q chain is not valid: %w", key.KeyID, err)
	}
	pub, ok := leaf.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, attestation.Invalidf("intel trust authority key %q has an unsupported type %T", key.KeyID, leaf.PublicKey)
	}
	if k, ok := key.Key.(crypto.PublicKey); !ok || !pub.Equal(k) {
		return nil, attestation.Invalidf("intel trust authority key %q is not the key of its certificate", key.KeyID)
	}
	return leaf, nil
}

// checkRuntimeData checks that the runtime data's user-data is SHA-512 of the
// verifier nonce, if any, and the user data. The nonce's val and iat claims are
// the base64 encodings of the bytes that were hashed.
func checkRuntimeData(tdx *TDXClaims, userData []byte) error {
	h := sha512.New()
	if n := tdx.VerifierNonce; n != nil {
		val, err1 := base64.StdEncoding.DecodeString(n.Val)
		iat, err2 := base64.StdEncoding.DecodeString(n.Iat)
		if err1 != nil || err2 != nil {
			return attestation.Invalidf("intel trust authority token verifier_nonce is not base64")
		}
		h.Write(val)
		h.Write(iat)
	}
	h.Write(userData)
	got, _ := tdx.RuntimeData["user-data"].(string)
	want := h.Sum(nil)
	if b, err := hex.DecodeString(got); err != nil || !bytes.Equal(b, want) {
		return attestation.Invalidf("intel trust authority token runtime data does not commit to its user data")
	}
	return nil
}

// IsToken reports, without verifying it, whether token claims Intel Trust
// Authority as its issuer, to tell it from other attestation tokens.
func IsToken(token string) bool {
	jwt, err := jose.ParseSigned(token)
	if err != nil {
		return false
	}
	var claims jose.Claims
	if err := jwt.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return false
	}
	return claims.Issuer == Issuer
}
