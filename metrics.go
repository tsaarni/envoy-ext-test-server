package main

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// checkMetrics holds the Prometheus metrics. They carry the same information as the
// CHECK log line, so verdicts can be verified without per-request logging (--quiet).
// A nil *checkMetrics disables metrics.
type checkMetrics struct {
	checks     *prometheus.CounterVec
	controls   *prometheus.CounterVec
	headers    *prometheus.CounterVec
	contextExt *prometheus.CounterVec
	duration   *prometheus.HistogramVec
}

// newMetrics creates the metrics and a registry that serves them. All authz_* metrics
// carry a constant label name=<server name>.
func newMetrics(name string) (*checkMetrics, *prometheus.Registry) {
	m := &checkMetrics{
		checks: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "authz_checks_total",
			Help: "Authorization checks handled, by verdict and request attributes. status is empty when no status was sent. sni and client_cert are of the Envoy-to-server connection.",
		}, []string{"protocol", "verdict", "status", "tag", "host", "path", "sni", "client_cert"}),
		controls: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "authz_controls_total",
			Help: "Controls in checks after merging, by the carrier they came from.",
		}, []string{"control", "carrier"}),
		headers: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "authz_request_headers_total",
			Help: "Checks that carried the request header, by lowercase header name.",
		}, []string{"header"}),
		contextExt: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "authz_context_extensions_total",
			Help: "gRPC context extensions received in checks.",
		}, []string{"key", "value"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "authz_check_duration_seconds",
			Help:    "Time to handle a check, including the requested delay.",
			Buckets: prometheus.DefBuckets,
		}, []string{"protocol", "verdict"}),
	}
	reg := prometheus.NewRegistry()
	prometheus.WrapRegistererWith(prometheus.Labels{"name": name}, reg).MustRegister(
		m.checks, m.controls, m.headers, m.contextExt, m.duration)
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return m, reg
}

func metricsHandler(reg *prometheus.Registry) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	return mux
}

// labelValue makes client-controlled text safe as a label value; invalid UTF-8 is rejected by the client library.
func labelValue(s string) string {
	return strings.ToValidUTF8(s, "\uFFFD")
}

// pathWithoutQuery drops the query string so that it does not multiply series.
func pathWithoutQuery(p string) string {
	path, _, _ := strings.Cut(p, "?")
	return path
}

func (m *checkMetrics) observe(r checkRecord, elapsed time.Duration) {
	if m == nil {
		return
	}
	status := ""
	if r.Status != 0 {
		status = strconv.Itoa(r.Status)
	}
	// Errors are ignored: a label problem must never break request handling.
	if c, err := m.checks.GetMetricWithLabelValues(r.Protocol, r.Verdict, status, labelValue(r.Tag),
		labelValue(r.Request.Host), labelValue(pathWithoutQuery(r.Request.Path)),
		labelValue(r.EnvoyConnection.SNI), labelValue(r.EnvoyConnection.ClientCert)); err == nil {
		c.Inc()
	}
	if o, err := m.duration.GetMetricWithLabelValues(r.Protocol, r.Verdict); err == nil {
		o.Observe(elapsed.Seconds())
	}
	for name, c := range r.Controls {
		if c, err := m.controls.GetMetricWithLabelValues(name, c.Carrier); err == nil {
			c.Inc()
		}
	}
	for h := range r.Request.Headers {
		if c, err := m.headers.GetMetricWithLabelValues(labelValue(h)); err == nil {
			c.Inc()
		}
	}
	if r.Attributes == nil {
		return
	}
	for k, v := range r.Attributes.ContextExtensions {
		if c, err := m.contextExt.GetMetricWithLabelValues(labelValue(k), labelValue(v)); err == nil {
			c.Inc()
		}
	}
}
