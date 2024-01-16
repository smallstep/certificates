// Package metrix implements stats-related functionality.
package metrix

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// New initializes and returns a new [Meter].
func New() (m *Meter) {
	m = &Meter{
		x509: signatures{
			signed: newCounterVec("x509", "signed_total", "Number of X509 CSRs signed",
				"provisioner",
			),
			renewed: newCounterVec("x509", "renewed_total", "Number of X509 certificates renewed",
				"provisioner",
			),
		},
		ssh: signatures{
			signed: newCounterVec("ssh", "signed_total", "Number of SSH CSRs signed",
				"provisioner",
			),
			renewed: newCounterVec("ssh", "renewed_total", "Number of SSH certificates renewed",
				"provisioner",
			),
		},
	}

	reg := prometheus.NewRegistry()

	reg.MustRegister(
		m.x509.renewed,
		m.x509.signed,
		m.ssh.signed,
		m.ssh.renewed,
	)

	h := promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		Registry:            reg,
		Timeout:             5 * time.Second,
		MaxRequestsInFlight: 10,
	})

	mux := http.NewServeMux()
	mux.Handle("/metrics", h)
	m.Handler = mux

	return
}

// Meter wraps the functionality of a Prometheus-compatible HTTP handler.
type Meter struct {
	http.Handler

	x509 signatures
	ssh  signatures
}

type signatures struct {
	signed  *prometheus.CounterVec
	renewed *prometheus.CounterVec
}

// X509Signed implements [authority.Meter] for [Meter].
func (m *Meter) X509Signed(provisioner string) {
	m.x509.signed.WithLabelValues(provisioner).Inc()
}

// X509Renewed implements [authority.Meter] for [Meter].
func (m *Meter) X509Renewed(provisioner string) {
	m.x509.renewed.WithLabelValues(provisioner).Inc()
}

// SSHSigned implements [authority.Meter] for [Meter].
func (m *Meter) SSHSigned(provisioner string) {
	m.ssh.signed.WithLabelValues(provisioner).Inc()
}

// SSHRenewed implements [authority.Meter] for [Meter].
func (m *Meter) SSHRenewed(provisioner string) {
	m.ssh.renewed.WithLabelValues(provisioner).Inc()
}

func newCounterVec(subsystem, name, help string, labels ...string) *prometheus.CounterVec {
	return prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "step_ca",
		Subsystem: subsystem,
		Name:      name,
		Help:      help,
	}, labels)
}
