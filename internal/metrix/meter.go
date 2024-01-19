// Package metrix implements stats-related functionality.
package metrix

import (
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// New initializes and returns a new [Meter].
func New() (m *Meter) {
	initializedAt := time.Now()

	m = &Meter{
		uptime: prometheus.NewGaugeFunc(
			prometheus.GaugeOpts(opts(
				"",
				"uptime_seconds",
				"Number of seconds since service start",
			)),
			func() float64 {
				return math.Round(time.Since(initializedAt).Seconds())
			},
		),
		ssh:  newProvisioner("ssh"),
		x509: newProvisioner("x509"),
	}

	reg := prometheus.NewRegistry()

	reg.MustRegister(
		m.uptime,
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

	uptime prometheus.GaugeFunc
	ssh    *provisioner
	x509   *provisioner
}

// SSHRekeyed implements [authority.Meter] for [Meter].
func (m *Meter) SSHRekeyed(p string, success bool) {
	count(m.ssh.rekeyed, p, success)
}

// SSHRenewed implements [authority.Meter] for [Meter].
func (m *Meter) SSHRenewed(provisioner string, success bool) {
	count(m.ssh.renewed, provisioner, success)
}

// SSHSigned implements [authority.Meter] for [Meter].
func (m *Meter) SSHSigned(provisioner string, success bool) {
	count(m.ssh.signed, provisioner, success)
}

// SSHAuthorized implements [authority.Meter] for [Meter].
func (m *Meter) SSHAuthorized(provisioner string, success bool) {
	count(m.ssh.authorized, provisioner, success)
}

// SSHEnriched implements [authority.Meter] for [Meter].
func (m *Meter) SSHEnriched(provisioner string, success bool) {
	count(m.ssh.enriched, provisioner, success)
}

// X509Rekeyed implements [authority.Meter] for [Meter].
func (m *Meter) X509Rekeyed(provisioner string, success bool) {
	count(m.x509.rekeyed, provisioner, success)
}

// X509Renewed implements [authority.Meter] for [Meter].
func (m *Meter) X509Renewed(provisioner string, success bool) {
	count(m.x509.renewed, provisioner, success)
}

// X509Signed implements [authority.Meter] for [Meter].
func (m *Meter) X509Signed(provisioner string, success bool) {
	count(m.x509.signed, provisioner, success)
}

// X509Authorized implements [authority.Meter] for [Meter].
func (m *Meter) X509Authorized(provisioner string, success bool) {
	count(m.x509.authorized, provisioner, success)
}

// X509Enriched implements [authority.Meter] for [Meter].
func (m *Meter) X509Enriched(provisioner string, success bool) {
	count(m.x509.enriched, provisioner, success)
}

func count(cv *prometheus.CounterVec, provisioner string, success bool) {
	cv.WithLabelValues(provisioner, strconv.FormatBool(success)).Inc()
}

// provisioner wraps the counters exported by provisioners.
type provisioner struct {
	rekeyed *prometheus.CounterVec
	renewed *prometheus.CounterVec
	signed  *prometheus.CounterVec

	authorized *prometheus.CounterVec
	enriched   *prometheus.CounterVec
}

func newProvisioner(subsystem string) *provisioner {
	return &provisioner{
		rekeyed: newCounterVec(subsystem, "rekeyed_total", "Number of certificates rekeyed",
			"provisioner",
			"success",
		),
		renewed: newCounterVec(subsystem, "renewed_total", "Number of certificates renewed",
			"provisioner",
			"success",
		),
		signed: newCounterVec(subsystem, "signed_total", "Number of CSRs signed",
			"provisioner",
			"success",
		),
		authorized: newCounterVec(subsystem, "authorized_total", "Number of authorizing webhooks called",
			"provisioner",
			"success",
		),
		enriched: newCounterVec(subsystem, "enriched_total", "Number of enriching webhooks called",
			"provisioner",
			"success",
		),
	}
}

func newCounterVec(subsystem, name, help string, labels ...string) *prometheus.CounterVec {
	opts := opts(subsystem, name, help)

	return prometheus.NewCounterVec(prometheus.CounterOpts(opts), labels)
}

func opts(subsystem, name, help string) prometheus.Opts {
	return prometheus.Opts{
		Namespace: "step_ca",
		Subsystem: subsystem,
		Name:      name,
		Help:      help,
	}
}
