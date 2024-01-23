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
	initializedAt := time.Now()

	m = &Meter{
		uptime: prometheus.NewGaugeFunc(
			prometheus.GaugeOpts(opts(
				"",
				"uptime_seconds",
				"Number of seconds since service start",
			)),
			func() float64 {
				return float64(time.Since(initializedAt) / time.Second)
			},
		),
		ssh:  newProvisioner("ssh"),
		x509: newProvisioner("x509"),
		kms: &kms{
			signed: prometheus.NewCounter(prometheus.CounterOpts(opts("kms", "signed", "Number of KMS-backed signatures"))),
			errors: prometheus.NewCounter(prometheus.CounterOpts(opts("kms", "errors", "Number of KMS-related errors"))),
		},
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
		m.kms.signed,
		m.kms.errors,
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
	kms    *kms
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
func (m *Meter) SSHWebhookAuthorized(provisioner string, success bool) {
	count(m.ssh.webhookAuthorized, provisioner, success)
}

// SSHEnriched implements [authority.Meter] for [Meter].
func (m *Meter) SSHWebhookEnriched(provisioner string, success bool) {
	count(m.ssh.webhookEnriched, provisioner, success)
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
func (m *Meter) X509WebhookAuthorized(provisioner string, success bool) {
	count(m.x509.webhookAuthorized, provisioner, success)
}

// X509Enriched implements [authority.Meter] for [Meter].
func (m *Meter) X509WebhookEnriched(provisioner string, success bool) {
	count(m.x509.webhookEnriched, provisioner, success)
}

func count(cv *prometheus.CounterVec, provisioner string, success bool) {
	cv.WithLabelValues(provisioner, strconv.FormatBool(success)).Inc()
}

// KMSSigned implements [authority.Meter] for [Meter].
func (m *Meter) KMSSigned() {
	m.kms.signed.Inc()
}

// KMSErrors implements [authority.Meter] for [Meter].
func (m *Meter) KMSError() {
	m.kms.errors.Inc()
}

// provisioner wraps the counters exported by provisioners.
type provisioner struct {
	rekeyed *prometheus.CounterVec
	renewed *prometheus.CounterVec
	signed  *prometheus.CounterVec

	webhookAuthorized *prometheus.CounterVec
	webhookEnriched   *prometheus.CounterVec
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
		signed: newCounterVec(subsystem, "signed_total", "Number of certificates signed",
			"provisioner",
			"success",
		),
		webhookAuthorized: newCounterVec(subsystem, "webhook_authorized_total", "Number of authorizing webhooks called",
			"provisioner",
			"success",
		),
		webhookEnriched: newCounterVec(subsystem, "webhook_enriched_total", "Number of enriching webhooks called",
			"provisioner",
			"success",
		),
	}
}

type kms struct {
	signed prometheus.Counter
	errors prometheus.Counter
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
