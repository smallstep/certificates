// Package meter implements stats-related functionality.
package meter

import (
	"net/http"
	"sync/atomic"
)

// M wraps the functionality of a Prometheus-compatible HTTP handler.
type M struct {
	certs struct {
		x509 atomic.Int64 // number of X509 certificates issued
		ssh  atomic.Int64 // number of SSH certificates issued
	}
}

func (m *M) Handler(w http.ResponseWriter, r *http.Request) {
	// TODO(@azazeal): implement prometheus-compatible handler.
}

// X509CertificateIssued implements [authority.Hooks] for M.
func (m *M) X509CertificateIssued(provisioner string) {
	m.certs.x509.Add(1)
}

// SSHCertificateIssued implements [authority.Hooks] for M.
func (m *M) SSHCertificateIssued(provisioner string) {
	m.certs.ssh.Add(1)
}
