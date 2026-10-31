package confidentialspace

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/minica"

	"github.com/smallstep/certificates/attestation"
	cstest "github.com/smallstep/certificates/attestation/confidentialspace/confidentialspacetest"
)

const testAudience = "https://ca.example.com/acme/acme/directory"

func TestNonces_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		want    Nonces
		wantErr bool
	}{
		{"ok string", `"nonce-0123"`, Nonces{"nonce-0123"}, false},
		{"ok array", `["nonce-0123","nonce-4567"]`, Nonces{"nonce-0123", "nonce-4567"}, false},
		{"ok null", `null`, nil, false},
		{"fail number", `123`, nil, true},
		{"fail object", `{"a":"b"}`, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Nonces
			err := json.Unmarshal([]byte(tt.data), &got)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestVerify(t *testing.T) {
	pki := cstest.New(t)
	otherPKI := cstest.New(t)
	now := time.Now().Truncate(time.Second)
	nonces := []string{"nonce-for-key-authorization", "nonce-for-key-digest"}

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca, err := minica.New(minica.WithName("Test EC Attestation"))
	require.NoError(t, err)
	ecLeaf, err := ca.Sign(&x509.Certificate{Subject: pkix.Name{CommonName: "EC Signer"}, PublicKey: ecKey.Public()})
	require.NoError(t, err)
	ecRoots := x509.NewCertPool()
	ecRoots.AddCert(ca.Root)
	otherRSAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	claims := func() map[string]any { return cstest.Claims(now, testAudience, nonces...) }
	claimsWith := func(fn func(c map[string]any)) map[string]any {
		c := claims()
		fn(c)
		return c
	}
	defaultOpts := Options{
		Roots:     pki.Roots(),
		Audience:  testAudience,
		MinNonces: 2,
		Now:       now,
	}

	tests := []struct {
		name    string
		token   string
		opts    func(o *Options)
		wantErr string
	}{
		{"ok", pki.Mint(t, claims()), nil, ""},
		{"ok audience array", pki.Mint(t, claimsWith(func(c map[string]any) {
			c["aud"] = []string{"other", testAudience}
		})), nil, ""},
		{"ok six nonces", pki.Mint(t, claimsWith(func(c map[string]any) {
			c["eat_nonce"] = append(nonces, "nonce-2-pass", "nonce-3-pass", "nonce-4-pass", "nonce-5-pass")
		})), nil, ""},
		{"ok expired within leeway", pki.Mint(t, claimsWith(func(c map[string]any) {
			c["iat"] = now.Add(-2 * time.Minute).Unix()
			c["exp"] = now.Add(-30 * time.Second).Unix()
		})), nil, ""},
		{"ok default min nonces", pki.Mint(t, claimsWith(func(c map[string]any) {
			c["eat_nonce"] = "single-nonce"
		})), func(o *Options) { o.MinNonces = 0 }, ""},
		{"fail nil roots", pki.Mint(t, claims()), func(o *Options) { o.Roots = nil }, "no roots"},
		{"fail parse", "not-a-token", nil, "error parsing attestation token"},
		{"fail algorithm", cstest.Mint(t, ecKey, jose.ES256, []*x509.Certificate{ecLeaf, ca.Intermediate, ca.Root}, claims()),
			func(o *Options) { o.Roots = ecRoots }, `unsupported attestation token algorithm "ES256"`},
		{"fail no x5c", cstest.Mint(t, pki.LeafKey, jose.RS256, nil, claims()), nil, "attestation token x5c is not valid"},
		{"fail untrusted root", otherPKI.Mint(t, claims()), nil, "attestation token x5c is not valid"},
		{"fail leaf key type", cstest.Mint(t, otherRSAKey, jose.RS256, []*x509.Certificate{ecLeaf, ca.Intermediate, ca.Root}, claims()),
			func(o *Options) { o.Roots = ecRoots }, "attestation token x5c leaf has an unsupported key type"},
		{"fail signature", cstest.Mint(t, otherRSAKey, jose.RS256, pki.Chain(), claims()), nil, "error verifying attestation token"},
		{"fail leaf expired", pki.Mint(t, claims()), func(o *Options) { o.Now = now.Add(48 * time.Hour) },
			"attestation token x5c is not valid"},
		{"fail issuer", pki.Mint(t, claimsWith(func(c map[string]any) {
			c["iss"] = "https://portal.trustauthority.intel.com"
		})), nil, "attestation token is not valid"},
		{"fail audience", pki.Mint(t, claimsWith(func(c map[string]any) {
			c["aud"] = "https://sts.googleapis.com"
		})), nil, "attestation token is not valid"},
		{"fail expired", pki.Mint(t, claimsWith(func(c map[string]any) {
			c["iat"] = now.Add(-3 * time.Minute).Unix()
			c["exp"] = now.Add(-2 * time.Minute).Unix()
		})), nil, "attestation token is not valid"},
		{"fail not yet valid", pki.Mint(t, claimsWith(func(c map[string]any) {
			c["nbf"] = now.Add(2 * time.Minute).Unix()
		})), nil, "attestation token is not valid"},
		{"fail issued in the future", pki.Mint(t, claimsWith(func(c map[string]any) {
			c["iat"] = now.Add(2 * time.Minute).Unix()
		})), nil, "attestation token is not valid"},
		{"fail missing exp", pki.Mint(t, claimsWith(func(c map[string]any) { delete(c, "exp") })), nil,
			"attestation token must have exp and iat claims"},
		{"fail missing iat", pki.Mint(t, claimsWith(func(c map[string]any) { delete(c, "iat") })), nil,
			"attestation token must have exp and iat claims"},
		{"fail too old", pki.Mint(t, claimsWith(func(c map[string]any) {
			c["iat"] = now.Add(-10 * time.Minute).Unix()
		})), nil, "attestation token is too old"},
		{"fail single nonce", pki.Mint(t, claimsWith(func(c map[string]any) {
			c["eat_nonce"] = "nonce-for-key-authorization"
		})), nil, "attestation token must have between 2 and 6 nonces, it has 1"},
		{"fail no nonces", pki.Mint(t, claimsWith(func(c map[string]any) { delete(c, "eat_nonce") })), nil,
			"attestation token must have between 2 and 6 nonces, it has 0"},
		{"fail seven nonces", pki.Mint(t, claimsWith(func(c map[string]any) {
			c["eat_nonce"] = append(nonces, "nonce-2", "nonce-3", "nonce-4", "nonce-5", "nonce-6")
		})), nil, "attestation token must have between 2 and 6 nonces, it has 7"},
		{"fail debuggable", pki.Mint(t, claimsWith(func(c map[string]any) { c["dbgstat"] = "enabled" })), nil,
			`attestation token dbgstat is "enabled"`},
		{"fail no dbgstat", pki.Mint(t, claimsWith(func(c map[string]any) { delete(c, "dbgstat") })), nil,
			`attestation token dbgstat is ""`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := defaultOpts
			if tt.opts != nil {
				tt.opts(&opts)
			}
			got, err := Verify(tt.token, opts)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				// A missing root is the caller's error, not the token's.
				assert.Equal(t, opts.Roots != nil, errors.Is(err, attestation.ErrInvalidEvidence))
				return
			}
			require.NoError(t, err)
			assert.Equal(t, pki.Leaf, got.Leaf)
			assert.Equal(t, cstest.InstanceID, got.Claims.Submods.GCE.InstanceID)
			assert.Equal(t, "GCP_INTEL_TDX", got.RawClaims["hwmodel"])
			result := got.Result()
			assert.Equal(t, got.RawClaims, result.Claims)
			assert.Equal(t, pki.Leaf.SerialNumber.String(), result.SignerSerialNumber)
		})
	}

	t.Run("ok default max age and time", func(t *testing.T) {
		_, err := Verify(pki.Mint(t, cstest.Claims(time.Now(), testAudience, nonces...)), Options{
			Roots:    pki.Roots(),
			Audience: testAudience,
		})
		require.NoError(t, err)
	})
}

func TestExpectations(t *testing.T) {
	pki := cstest.New(t)
	now := time.Now()
	tok, err := Verify(pki.Mint(t, cstest.Claims(now, testAudience, "nonce-0", "nonce-1")), Options{
		Roots:    pki.Roots(),
		Audience: testAudience,
		Now:      now,
	})
	require.NoError(t, err)
	claims := &tok.Claims

	tests := []struct {
		name    string
		e       *Expectations
		wantErr string
	}{
		{"ok nil", nil, ""},
		{"ok empty", &Expectations{}, ""},
		{"ok digest", &Expectations{ImageDigests: []string{"sha256:0f0e0d0c0b0a09080706050403020100"}}, ""},
		{"ok signer", &Expectations{ImageSignerKeyIDs: []string{"c0ffee"}}, ""},
		{"ok digest or signer", &Expectations{ImageDigests: []string{"sha256:other"}, ImageSignerKeyIDs: []string{"c0ffee"}}, ""},
		{"ok all", &Expectations{
			RequireSupportAttributes: []string{"STABLE", "USABLE"},
			HWModels:                 []string{"GCP_AMD_SEV", "GCP_INTEL_TDX"},
			SWNames:                  []string{"CONFIDENTIAL_SPACE"},
			ProjectIDs:               []string{"my-project"},
			ServiceAccounts:          []string{"other@my-project.iam.gserviceaccount.com", "workload@my-project.iam.gserviceaccount.com"},
		}, ""},
		{"fail image", &Expectations{ImageDigests: []string{"sha256:other"}, ImageSignerKeyIDs: []string{"other"}},
			"is neither an allowed digest nor signed by an allowed key"},
		{"fail support attribute", &Expectations{RequireSupportAttributes: []string{"EXPERIMENTAL"}}, `support attribute "EXPERIMENTAL"`},
		{"fail hwmodel", &Expectations{HWModels: []string{"GCP_AMD_SEV"}}, `hwmodel "GCP_INTEL_TDX" is not allowed`},
		{"fail swname", &Expectations{SWNames: []string{"OTHER"}}, `swname "CONFIDENTIAL_SPACE" is not allowed`},
		{"fail project", &Expectations{ProjectIDs: []string{"other"}}, `project "my-project" is not allowed`},
		{"fail service account", &Expectations{ServiceAccounts: []string{"other@my-project.iam.gserviceaccount.com"}}, "none of the service accounts"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.e.Check(claims)
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, tt.wantErr)
			assert.ErrorIs(t, err, attestation.ErrInvalidEvidence)
		})
	}
}

func TestExpectations_Validate(t *testing.T) {
	assert.NoError(t, (*Expectations)(nil).Validate())
	assert.NoError(t, (&Expectations{HWModels: []string{"GCP_INTEL_TDX"}}).Validate())
	assert.EqualError(t, (&Expectations{SWNames: []string{""}}).Validate(), "swnames cannot contain empty values")
}
