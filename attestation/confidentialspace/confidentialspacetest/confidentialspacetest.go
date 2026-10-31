// Package confidentialspacetest mints Google Cloud Attestation PKI tokens with
// a synthetic PKI, for tests of code that verifies them.
package confidentialspacetest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"testing"
	"time"

	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/minica"
)

// InstanceID is the Compute Engine instance id in the claims Claims returns.
const InstanceID = "1234567890123456789"

// PKI is a synthetic Google Cloud Attestation PKI: a root, an intermediate and
// an RSA leaf that signs tokens.
type PKI struct {
	Root         *x509.Certificate
	Intermediate *x509.Certificate
	Leaf         *x509.Certificate
	LeafKey      crypto.Signer
}

// New returns a new PKI.
func New(t testing.TB) *PKI {
	t.Helper()
	ca, err := minica.New(minica.WithName("Test Attestation"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.Sign(&x509.Certificate{
		Subject:   pkix.Name{CommonName: "Test Attestation Signer"},
		PublicKey: key.Public(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &PKI{
		Root:         ca.Root,
		Intermediate: ca.Intermediate,
		Leaf:         leaf,
		LeafKey:      key,
	}
}

// RootPEM returns the PKI's root as PEM.
func (p *PKI) RootPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.Root.Raw})
}

// Roots returns a pool with the PKI's root.
func (p *PKI) Roots() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.Root)
	return pool
}

// Chain returns the PKI's chain, leaf first.
func (p *PKI) Chain() []*x509.Certificate {
	return []*x509.Certificate{p.Leaf, p.Intermediate, p.Root}
}

// Mint signs the claims as a PKI token with the leaf of the PKI.
func (p *PKI) Mint(t testing.TB, claims map[string]any) string {
	t.Helper()
	return Mint(t, p.LeafKey, jose.RS256, p.Chain(), claims)
}

// Mint signs the claims with the given key and algorithm, with the chain, if
// any, in the x5c header.
func Mint(t testing.TB, key crypto.Signer, alg jose.SignatureAlgorithm, chain []*x509.Certificate, claims map[string]any) string {
	t.Helper()
	so := new(jose.SignerOptions).WithType("JWT")
	if len(chain) > 0 {
		x5c := make([]string, len(chain))
		for i, c := range chain {
			x5c[i] = base64.StdEncoding.EncodeToString(c.Raw)
		}
		so = so.WithHeader("x5c", x5c)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, so)
	if err != nil {
		t.Fatal(err)
	}
	token, err := jose.Signed(signer).Claims(claims).CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// Claims returns the claims of a Confidential Space token, following the claims
// Google documents, issued at now.
func Claims(now time.Time, audience string, nonces ...string) map[string]any {
	return map[string]any{
		"iss":                     "https://confidentialcomputing.googleapis.com",
		"sub":                     "https://www.googleapis.com/compute/v1/projects/my-project/zones/us-central1-a/instances/workload-1",
		"aud":                     audience,
		"iat":                     now.Unix(),
		"nbf":                     now.Unix(),
		"exp":                     now.Add(time.Hour).Unix(),
		"eat_nonce":               nonces,
		"eat_profile":             "https://cloud.google.com/confidential-computing/confidential-space/docs/reference/token-claims",
		"hwmodel":                 "GCP_INTEL_TDX",
		"swname":                  "CONFIDENTIAL_SPACE",
		"swversion":               []string{"260900"},
		"secboot":                 true,
		"dbgstat":                 "disabled-since-boot",
		"attester_tcb":            []string{"INTEL"},
		"google_service_accounts": []string{"workload@my-project.iam.gserviceaccount.com"},
		"submods": map[string]any{
			"confidential_space": map[string]any{
				"support_attributes": []string{"LATEST", "STABLE", "USABLE"},
			},
			"container": map[string]any{
				"image_reference": "us-docker.pkg.dev/my-project/workload/workload:1",
				"image_digest":    "sha256:0f0e0d0c0b0a09080706050403020100",
				"image_signatures": []map[string]any{
					{"key_id": "c0ffee", "signature_algorithm": "ECDSA_P256_SHA256", "signature": "c2ln"},
				},
				"restart_policy": "Never",
			},
			"gce": map[string]any{
				"project_id":     "my-project",
				"project_number": "123456789012",
				"zone":           "us-central1-a",
				"instance_id":    InstanceID,
				"instance_name":  "workload-1",
			},
		},
	}
}
