package softcas

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	"github.com/smallstep/certificates/cas/apiv1"
)

// Certificate identity and key material are immutable after publication. Cache
// only their path links; expiry is read afresh for every issuance. Configuration
// (including the exported SoftCAS fields) is initialization-time only.
type issuerValidityCache struct {
	mu           sync.Mutex
	chain        []*x509.Certificate
	roots        []*x509.Certificate
	certificates []*x509.Certificate
}

// SetIssuerValidityLimit configures the local issuer policy and copies the root
// slice. An omitted mode preserves an explicitly configured service policy.
func (c *SoftCAS) SetIssuerValidityLimit(mode apiv1.IssuerValidityLimit, roots []*x509.Certificate) error {
	if mode == "" {
		mode = c.IssuerValidityLimit
	}
	if err := mode.Validate(); err != nil {
		return err
	}
	cache := &c.issuerValidityCache
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if mode != "" {
		c.IssuerValidityLimit = mode
	}
	c.RootCertificates = append([]*x509.Certificate(nil), roots...)
	cache.chain = nil
	cache.roots = nil
	cache.certificates = nil
	return nil
}

func (c *SoftCAS) limitCertificateValidity(template *x509.Certificate, chain, roots []*x509.Certificate, now time.Time) ([]apiv1.CertificateWarning, error) {
	if err := c.IssuerValidityLimit.Validate(); err != nil {
		return nil, err
	}
	certificates, err := c.resolveIssuerCertificates(chain, roots)
	if err != nil {
		return nil, err
	}
	limiting := certificates[0]
	limit := limiting.NotAfter.UTC().Truncate(time.Second)
	for _, cert := range certificates {
		if cert.NotAfter.IsZero() {
			return nil, fmt.Errorf("issuing CA certificate has no expiration")
		}
		expiry := cert.NotAfter.UTC().Truncate(time.Second)
		if expiry.Before(limit) {
			limiting, limit = cert, expiry
		}
	}
	requested := template.NotAfter.UTC().Truncate(time.Second)
	effective := requested
	if limit.Before(effective) {
		effective = limit
	}
	if !effective.After(now.UTC().Truncate(time.Second)) || !effective.After(template.NotBefore.UTC().Truncate(time.Second)) {
		return nil, &apiv1.IssuerValidityError{
			RequestedNotAfter: requested, LimitNotAfter: limit, Reason: "no_remaining_validity",
		}
	}
	if requested.After(limit) && c.IssuerValidityLimit == apiv1.IssuerValidityLimitReject {
		return nil, &apiv1.IssuerValidityError{
			RequestedNotAfter: requested, LimitNotAfter: limit, Reason: "exceeds_limit",
		}
	}
	template.NotAfter = effective
	if !requested.After(limit) {
		return nil, nil
	}
	fingerprint := sha256.Sum256(limiting.Raw)
	return []apiv1.CertificateWarning{{
		Code:              "issuer_validity_truncated",
		Message:           fmt.Sprintf("Certificate expiration was reduced from %s to %s because the issuing CA chain expires then. Contact the CA operator to renew the limiting CA certificate.", requested.Format(time.RFC3339), effective.Format(time.RFC3339)),
		RequestedNotAfter: requested,
		EffectiveNotAfter: effective,
		LimitingCertificate: apiv1.LimitingCertificate{
			Subject: limiting.Subject.String(), Fingerprint: fmt.Sprintf("%x", fingerprint), NotAfter: limit,
		},
	}}, nil
}

func (c *SoftCAS) resolveIssuerCertificates(chain, roots []*x509.Certificate) ([]*x509.Certificate, error) {
	cache := &c.issuerValidityCache
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.certificates != nil && sameCertificateSequence(chain, cache.chain) && sameCertificateSequence(roots, cache.roots) {
		return cache.certificates, nil
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("issuing CA certificate chain cannot be empty")
	}
	for i, cert := range chain {
		if cert == nil || cert.NotAfter.IsZero() {
			return nil, fmt.Errorf("issuing CA certificate chain contains an invalid certificate at index %d", i)
		}
	}
	for i := range len(chain) - 1 {
		if !bytes.Equal(chain[i].RawIssuer, chain[i+1].RawSubject) {
			return nil, fmt.Errorf("issuing CA certificate chain is not ordered at index %d", i)
		}
		if err := chain[i].CheckSignatureFrom(chain[i+1]); err != nil {
			return nil, fmt.Errorf("invalid issuing CA certificate chain link at index %d: %w", i, err)
		}
	}
	for i, root := range roots {
		if root == nil || root.NotAfter.IsZero() {
			return nil, fmt.Errorf("issuing CA roots contain an invalid certificate at index %d", i)
		}
	}
	certificates := make([]*x509.Certificate, len(chain), len(chain)+len(roots))
	copy(certificates, chain)
	last := chain[len(chain)-1]
	includedRoot := false
	for _, root := range roots {
		if bytes.Equal(last.Raw, root.Raw) {
			includedRoot = true
			break
		}
	}
	if len(roots) > 0 && !includedRoot {
		for _, root := range roots {
			if bytes.Equal(last.RawIssuer, root.RawSubject) && last.CheckSignatureFrom(root) == nil {
				certificates = append(certificates, root)
			}
		}
		if len(certificates) == len(chain) {
			return nil, fmt.Errorf("issuing CA certificate chain does not match any configured root")
		}
	}
	cache.chain = certificates[:len(chain)]
	cache.roots = append([]*x509.Certificate(nil), roots...)
	cache.certificates = certificates
	return certificates, nil
}

func sameCertificateSequence(a, b []*x509.Certificate) bool {
	if len(a) != len(b) {
		return false
	}
	for i, cert := range a {
		if cert != b[i] {
			return false
		}
	}
	return true
}
