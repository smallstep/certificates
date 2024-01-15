// Package metrix implements stats-related functionality.
package metrix

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func New() (m *Meter) {
	m = new(Meter)

	m.signatures.ssh = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "step_ca",
			Subsystem: "ssh",
			Name:      "signatures_total",
			Help:      "Number of SSH CSRs signed",
		},
		[]string{
			"provider",
		},
	)

	m.renewals.ssh = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "step_ca",
			Subsystem: "ssh",
			Name:      "renewals_total",
			Help:      "Number of SSH renewals",
		},
		[]string{
			"provider",
		},
	)

	m.signatures.x509 = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "step_ca",
			Subsystem: "x509",
			Name:      "signatures_total",
			Help:      "Number of X509 CSRs signed",
		},
		[]string{
			"provider",
		},
	)

	m.renewals.x509 = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "step_ca",
			Subsystem: "x509",
			Name:      "renewals_total",
			Help:      "Number of X509 renewals",
		},
		[]string{
			"provider",
		},
	)

	reg := prometheus.NewRegistry()

	reg.MustRegister(
		m.signatures.ssh,
		m.signatures.x509,
		m.renewals.ssh,
		m.renewals.x509,
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

	signatures struct {
		x509 *prometheus.CounterVec // X509 CSRs signed
		ssh  *prometheus.CounterVec // SSH CSRs signed
	}

	renewals struct {
		x509 *prometheus.CounterVec // X509 renewals
		ssh  *prometheus.CounterVec // SSH renewals
	}
}

// X509Signatures implements [authority.Meter] for [Meter].
func (m *Meter) X509Signatures(provisioner string) {
	m.signatures.x509.WithLabelValues(provisioner).Inc()
}

// SSHSignatures implements [authority.Meter] for [Meter].
func (m *Meter) SSHSignatures(provisioner string) {
	m.signatures.ssh.WithLabelValues(provisioner).Inc()
}
