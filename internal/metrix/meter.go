// Package metrix implements stats-related functionality.
package metrix

import (
	"net/http"
	"strconv"
	"time"

	"github.com/smallstep/certificates/authority/provisioner"

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
		ssh:  newProvisionerInstruments("ssh"),
		x509: newProvisionerInstruments("x509"),
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
		m.ssh.webhookAuthorized,
		m.ssh.webhookEnriched,
		m.x509.rekeyed,
		m.x509.renewed,
		m.x509.signed,
		m.x509.webhookAuthorized,
		m.x509.webhookEnriched,
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
	ssh    *provisionerInstruments
	x509   *provisionerInstruments
	kms    *kms
}

// SSHRekeyed implements [authority.Meter] for [Meter].
func (m *Meter) SSHRekeyed(p provisioner.Interface, err error) {
	incrProvisionerCounter(m.ssh.rekeyed, p, err)
}

// SSHRenewed implements [authority.Meter] for [Meter].
func (m *Meter) SSHRenewed(p provisioner.Interface, err error) {
	incrProvisionerCounter(m.ssh.renewed, p, err)
}

// SSHSigned implements [authority.Meter] for [Meter].
func (m *Meter) SSHSigned(p provisioner.Interface, err error) {
	incrProvisionerCounter(m.ssh.signed, p, err)
}

// SSHWebhookAuthorized implements [authority.Meter] for [Meter].
func (m *Meter) SSHWebhookAuthorized(p provisioner.Interface, err error) {
	incrProvisionerCounter(m.ssh.webhookAuthorized, p, err)
}

// SSHWebhookEnriched implements [authority.Meter] for [Meter].
func (m *Meter) SSHWebhookEnriched(p provisioner.Interface, err error) {
	incrProvisionerCounter(m.ssh.webhookEnriched, p, err)
}

// X509Rekeyed implements [authority.Meter] for [Meter].
func (m *Meter) X509Rekeyed(p provisioner.Interface, err error) {
	incrProvisionerCounter(m.x509.rekeyed, p, err)
}

// X509Renewed implements [authority.Meter] for [Meter].
func (m *Meter) X509Renewed(p provisioner.Interface, err error) {
	incrProvisionerCounter(m.x509.renewed, p, err)
}

// X509Signed implements [authority.Meter] for [Meter].
func (m *Meter) X509Signed(p provisioner.Interface, err error) {
	incrProvisionerCounter(m.x509.signed, p, err)
}

// X509WebhookAuthorized implements [authority.Meter] for [Meter].
func (m *Meter) X509WebhookAuthorized(p provisioner.Interface, err error) {
	incrProvisionerCounter(m.x509.webhookAuthorized, p, err)
}

// X509WebhookEnriched implements [authority.Meter] for [Meter].
func (m *Meter) X509WebhookEnriched(p provisioner.Interface, err error) {
	incrProvisionerCounter(m.x509.webhookEnriched, p, err)
}

func incrProvisionerCounter(cv *prometheus.CounterVec, p provisioner.Interface, err error) {
	var name string
	if p != nil {
		name = p.GetName()
	}

	cv.WithLabelValues(name, strconv.FormatBool(err == nil)).Inc()
}

// KMSSigned implements [authority.Meter] for [Meter].
func (m *Meter) KMSSigned(err error) {
	if err == nil {
		m.kms.signed.Inc()
	} else {
		m.kms.errors.Inc()
	}
}

// provisionerInstruments wraps the counters exported by provisioners.
type provisionerInstruments struct {
	rekeyed *prometheus.CounterVec
	renewed *prometheus.CounterVec
	signed  *prometheus.CounterVec

	webhookAuthorized *prometheus.CounterVec
	webhookEnriched   *prometheus.CounterVec
}

func newProvisionerInstruments(subsystem string) *provisionerInstruments {
	return &provisionerInstruments{
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
