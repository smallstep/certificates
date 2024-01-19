// Package metrix implements stats-related functionality.
package metrix

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// New initializes and returns a new [Meter].
func New() (m *Meter) {
	m = &Meter{
		ssh: signatures{
			rekeyed: newCounterVec("ssh", "rekeyed_total", "Number of SSH certificates rekeyed",
				"provisioner",
				"success",
			),
			renewed: newCounterVec("ssh", "renewed_total", "Number of SSH certificates renewed",
				"provisioner",
				"success",
			),
			signed: newCounterVec("ssh", "signed_total", "Number of SSH CSRs signed",
				"provisioner",
				"success",
			),
		},
		x509: signatures{
			rekeyed: newCounterVec("x509", "rekeyed_total", "Number of X509 certificates rekeyed",
				"provisioner",
				"success",
			),
			renewed: newCounterVec("x509", "renewed_total", "Number of X509 certificates renewed",
				"provisioner",
				"success",
			),
			signed: newCounterVec("x509", "signed_total", "Number of X509 CSRs signed",
				"provisioner",
				"success",
			),
		},
	}

	reg := prometheus.NewRegistry()

	reg.MustRegister(
		m.ssh.rekeyed,
		m.ssh.renewed,
		m.ssh.signed,
		m.x509.rekeyed,
		m.x509.renewed,
		m.x509.signed,
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

	ssh  signatures
	x509 signatures
}

type signatures struct {
	rekeyed *prometheus.CounterVec
	renewed *prometheus.CounterVec
	signed  *prometheus.CounterVec
}

// SSHRekeyed implements [authority.Meter] for [Meter].
func (m *Meter) SSHRekeyed(provisioner string, success bool) {
	m.ssh.rekeyed.WithLabelValues(provisioner, strconv.FormatBool(success)).Inc()
}

// SSHRenewed implements [authority.Meter] for [Meter].
func (m *Meter) SSHRenewed(provisioner string, success bool) {
	m.ssh.renewed.WithLabelValues(provisioner, strconv.FormatBool(success)).Inc()
}

// SSHSigned implements [authority.Meter] for [Meter].
func (m *Meter) SSHSigned(provisioner string, success bool) {
	m.ssh.signed.WithLabelValues(provisioner, strconv.FormatBool(success)).Inc()
}

// X509Rekeyed implements [authority.Meter] for [Meter].
func (m *Meter) X509Rekeyed(provisioner string, success bool) {
	m.x509.rekeyed.WithLabelValues(provisioner, strconv.FormatBool(success)).Inc()
}

// X509Renewed implements [authority.Meter] for [Meter].
func (m *Meter) X509Renewed(provisioner string, success bool) {
	m.x509.renewed.WithLabelValues(provisioner, strconv.FormatBool(success)).Inc()
}

// X509Signed implements [authority.Meter] for [Meter].
func (m *Meter) X509Signed(provisioner string, success bool) {
	m.x509.signed.WithLabelValues(provisioner, strconv.FormatBool(success)).Inc()
}

func newCounterVec(subsystem, name, help string, labels ...string) *prometheus.CounterVec {
	return prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "step_ca",
		Subsystem: subsystem,
		Name:      name,
		Help:      help,
	}, labels)
}
