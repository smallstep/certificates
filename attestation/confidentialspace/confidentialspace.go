// Package confidentialspace verifies the PKI attestation tokens that Google
// Cloud Attestation issues to Confidential Space workloads.
package confidentialspace

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"go.step.sm/crypto/jose"

	"github.com/smallstep/certificates/attestation"
)

// Issuer is the issuer of Google Cloud Attestation tokens.
const Issuer = "https://confidentialcomputing.googleapis.com"

// Leeway is the clock skew allowed when validating the exp, nbf and iat claims
// of a token.
const Leeway = time.Minute

// DefaultMaxTokenAge is the default maximum age of a token, measured from its
// iat claim.
const DefaultMaxTokenAge = 5 * time.Minute

// MaxNonces is the maximum number of nonces Google Cloud Attestation puts in a
// token.
const MaxNonces = 6

// DebugDisabled is the value of the dbgstat claim of a workload that has not
// been debuggable since it booted, which Verify requires.
const DebugDisabled = "disabled-since-boot"

// Nonces is the eat_nonce claim of a token, which is either a string or an
// array of strings.
type Nonces []string

// UnmarshalJSON implements [json.Unmarshaler].
func (n *Nonces) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*n = nil
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*n = Nonces{s}
		return nil
	}
	var ss []string
	if err := json.Unmarshal(data, &ss); err != nil {
		return fmt.Errorf("eat_nonce must be a string or an array of strings: %w", err)
	}
	*n = ss
	return nil
}

// Claims are the claims of a Google Cloud Attestation token that this package
// reads.
type Claims struct {
	jose.Claims
	EATNonce              Nonces   `json:"eat_nonce"`
	HWModel               string   `json:"hwmodel"`
	SWName                string   `json:"swname"`
	DebugStatus           string   `json:"dbgstat"`
	GoogleServiceAccounts []string `json:"google_service_accounts"`
	Submods               struct {
		ConfidentialSpace struct {
			SupportAttributes []string `json:"support_attributes"`
		} `json:"confidential_space"`
		Container struct {
			ImageDigest     string `json:"image_digest"`
			ImageSignatures []struct {
				KeyID string `json:"key_id"`
			} `json:"image_signatures"`
		} `json:"container"`
		GCE struct {
			ProjectID  string `json:"project_id"`
			InstanceID string `json:"instance_id"`
		} `json:"gce"`
	} `json:"submods"`
}

// Token is a verified Google Cloud Attestation token.
type Token struct {
	// Leaf is the certificate that signed the token.
	Leaf *x509.Certificate
	// Claims are the claims this package reads.
	Claims Claims
	// RawClaims are all the claims of the token.
	RawClaims map[string]any
}

// Result returns the token's claims as an attestation result.
func (t *Token) Result() *attestation.ConfidentialSpace {
	return &attestation.ConfidentialSpace{
		Claims:             t.RawClaims,
		SignerSerialNumber: t.Leaf.SerialNumber.String(),
	}
}

// Options are the options Verify verifies a token with.
type Options struct {
	// Roots are the roots of Google Cloud Attestation's PKI. They are
	// required.
	Roots *x509.CertPool
	// Audience is the audience the token must have been requested for.
	Audience string
	// MaxTokenAge is the maximum age of the token. It defaults to
	// DefaultMaxTokenAge.
	MaxTokenAge time.Duration
	// MinNonces is the minimum number of nonces the token must carry. It
	// defaults to 1.
	MinNonces int
	// Now is the time the token is verified at. It defaults to the current
	// time.
	Now time.Time
}

// Verify verifies a Google Cloud Attestation PKI token: the x5c chain of the
// token against the roots, its RS256 signature with the leaf of the chain, the
// issuer, the audience, the exp, nbf and iat claims, the age of the token, the
// number of nonces, and that the workload has not been debuggable since boot.
// Errors of the token match attestation.ErrInvalidEvidence.
func Verify(token string, opts Options) (*Token, error) {
	// A nil pool would make x509 use the system roots.
	if opts.Roots == nil {
		return nil, errors.New("no roots to verify the attestation token with")
	}
	if opts.MaxTokenAge <= 0 {
		opts.MaxTokenAge = DefaultMaxTokenAge
	}
	if opts.MinNonces <= 0 {
		opts.MinNonces = 1
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}

	jwt, err := jose.ParseSigned(token)
	if err != nil {
		return nil, attestation.Invalidf("error parsing attestation token: %w", err)
	}
	if len(jwt.Headers) != 1 {
		return nil, attestation.Invalidf("attestation token must have exactly one signature")
	}
	header := jwt.Headers[0]
	if header.Algorithm != jose.RS256 {
		return nil, attestation.Invalidf("unsupported attestation token algorithm %q", header.Algorithm)
	}

	chains, err := header.Certificates(x509.VerifyOptions{
		Roots:       opts.Roots,
		CurrentTime: opts.Now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return nil, attestation.Invalidf("attestation token x5c is not valid: %w", err)
	}
	leaf := chains[0][0]
	if _, ok := leaf.PublicKey.(*rsa.PublicKey); !ok {
		return nil, attestation.Invalidf("attestation token x5c leaf has an unsupported key type %T", leaf.PublicKey)
	}

	var (
		claims    Claims
		rawClaims map[string]any
	)
	if err := jwt.Claims(leaf.PublicKey, &claims, &rawClaims); err != nil {
		return nil, attestation.Invalidf("error verifying attestation token: %w", err)
	}
	if err := claims.ValidateWithLeeway(jose.Expected{
		Issuer:   Issuer,
		Audience: jose.Audience{opts.Audience},
		Time:     opts.Now,
	}, Leeway); err != nil {
		return nil, attestation.Invalidf("attestation token is not valid: %w", err)
	}
	if claims.Expiry == nil || claims.IssuedAt == nil {
		return nil, attestation.Invalidf("attestation token must have exp and iat claims")
	}
	if age := opts.Now.Sub(claims.IssuedAt.Time()); age > opts.MaxTokenAge {
		return nil, attestation.Invalidf("attestation token is too old: issued %s ago, the maximum is %s", age, opts.MaxTokenAge)
	}
	if n := len(claims.EATNonce); n < opts.MinNonces || n > MaxNonces {
		return nil, attestation.Invalidf("attestation token must have between %d and %d nonces, it has %d", opts.MinNonces, MaxNonces, n)
	}
	if claims.DebugStatus != DebugDisabled {
		return nil, attestation.Invalidf("attestation token dbgstat is %q, not %q", claims.DebugStatus, DebugDisabled)
	}

	return &Token{
		Leaf:      leaf,
		Claims:    claims,
		RawClaims: rawClaims,
	}, nil
}

// Expectations are the values a verified token's workload must match. Each one
// that is set must be met. The field names follow the claims they are compared
// with.
type Expectations struct {
	// ImageDigests are the allowed values of the
	// submods.container.image_digest claim.
	ImageDigests []string `json:"imageDigests,omitempty"`

	// ImageSignerKeyIDs are the allowed values of the key_id of an element
	// of the submods.container.image_signatures claim. If ImageDigests is
	// also set, matching either is enough.
	ImageSignerKeyIDs []string `json:"imageSignerKeyIDs,omitempty"`

	// RequireSupportAttributes are the values that must all be present in
	// the submods.confidential_space.support_attributes claim, for example
	// STABLE.
	RequireSupportAttributes []string `json:"requireSupportAttributes,omitempty"`

	// HWModels are the allowed values of the hwmodel claim, for example
	// GCP_INTEL_TDX.
	HWModels []string `json:"hwmodels,omitempty"`

	// SWNames are the allowed values of the swname claim, for example
	// CONFIDENTIAL_SPACE.
	SWNames []string `json:"swnames,omitempty"`

	// ProjectIDs are the allowed values of the submods.gce.project_id claim.
	ProjectIDs []string `json:"projectIDs,omitempty"`

	// ServiceAccounts are the allowed service accounts; at least one of them
	// must be present in the google_service_accounts claim.
	ServiceAccounts []string `json:"serviceAccounts,omitempty"`
}

// Validate returns an error if an expectation has an empty value.
func (e *Expectations) Validate() error {
	if e == nil {
		return nil
	}
	for _, f := range []struct {
		name   string
		values []string
	}{
		{"imageDigests", e.ImageDigests},
		{"imageSignerKeyIDs", e.ImageSignerKeyIDs},
		{"requireSupportAttributes", e.RequireSupportAttributes},
		{"hwmodels", e.HWModels},
		{"swnames", e.SWNames},
		{"projectIDs", e.ProjectIDs},
		{"serviceAccounts", e.ServiceAccounts},
	} {
		if slices.Contains(f.values, "") {
			return fmt.Errorf("%s cannot contain empty values", f.name)
		}
	}
	return nil
}

// Check returns an error, which matches attestation.ErrInvalidEvidence, if the
// claims do not meet the expectations. It returns nil if none are set.
func (e *Expectations) Check(c *Claims) error {
	if e == nil {
		return nil
	}
	if len(e.ImageDigests) > 0 || len(e.ImageSignerKeyIDs) > 0 {
		allowed := slices.Contains(e.ImageDigests, c.Submods.Container.ImageDigest)
		for _, sig := range c.Submods.Container.ImageSignatures {
			if slices.Contains(e.ImageSignerKeyIDs, sig.KeyID) {
				allowed = true
			}
		}
		if !allowed {
			return attestation.Invalidf("container image %q is neither an allowed digest nor signed by an allowed key", c.Submods.Container.ImageDigest)
		}
	}
	for _, a := range e.RequireSupportAttributes {
		if !slices.Contains(c.Submods.ConfidentialSpace.SupportAttributes, a) {
			return attestation.Invalidf("support attribute %q is not present", a)
		}
	}
	if len(e.HWModels) > 0 && !slices.Contains(e.HWModels, c.HWModel) {
		return attestation.Invalidf("hwmodel %q is not allowed", c.HWModel)
	}
	if len(e.SWNames) > 0 && !slices.Contains(e.SWNames, c.SWName) {
		return attestation.Invalidf("swname %q is not allowed", c.SWName)
	}
	if len(e.ProjectIDs) > 0 && !slices.Contains(e.ProjectIDs, c.Submods.GCE.ProjectID) {
		return attestation.Invalidf("project %q is not allowed", c.Submods.GCE.ProjectID)
	}
	if len(e.ServiceAccounts) > 0 && !slices.ContainsFunc(c.GoogleServiceAccounts, func(sa string) bool {
		return slices.Contains(e.ServiceAccounts, sa)
	}) {
		return attestation.Invalidf("none of the service accounts %q is allowed", c.GoogleServiceAccounts)
	}
	return nil
}
