package confidentialspace

import (
	"crypto/x509"
	_ "embed"
	"sync"
)

// rootPEM is the root of Google Cloud Attestation's PKI tokens, "Confidential
// Space Root CA", valid from 2024-01-19 to 2034-01-16. Google publishes its
// location at
// https://confidentialcomputing.googleapis.com/.well-known/attestation-pki-root,
// which names
// https://confidentialcomputing.googleapis.com/.well-known/confidential_space_root.crt,
// documents its SHA-1 fingerprint as
// B9:51:20:74:2C:24:E3:AA:34:04:2E:1C:3B:A3:AA:D2:8B:21:23:21, asks relying
// parties to store it, and rotates it every ten years. Its SHA-256 fingerprint
// is 14:8B:29:38:21:BB:0C:6A:31:7F:41:3C:8B:A4:75:81:40:91:CB:22:D4:9B:9E:3C:94:19:8D:B8:E8:F8:6C:39.
//
//go:embed confidential_space_root.crt
var rootPEM []byte

var roots = sync.OnceValue(func() *x509.CertPool {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(rootPEM) {
		panic("confidentialspace: the embedded root is not valid PEM")
	}
	return pool
})

// Roots returns a pool with Google Cloud Attestation's root, the default for
// verifying PKI tokens.
func Roots() *x509.CertPool {
	return roots()
}
