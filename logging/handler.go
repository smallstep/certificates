package logging

import (
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/smallstep/certificates/internal/userid"
	"github.com/smallstep/certificates/middleware/requestid"
)

// LoggerHandler creates a logger handler
type LoggerHandler struct {
	name    string
	logger  *logrus.Logger
	options options
	next    http.Handler
}

// options encapsulates any overriding parameters for the logger handler
type options struct {
	// onlyTraceHealthEndpoint determines if the kube-probe requests to the /health
	// endpoint should only be logged at the TRACE level in the (expected) HTTP
	// 200 case
	onlyTraceHealthEndpoint bool
}

// NewLoggerHandler returns the given http.Handler with the logger integrated.
func NewLoggerHandler(name string, logger *Logger, next http.Handler) http.Handler {
	onlyTraceHealthEndpoint, _ := strconv.ParseBool(os.Getenv("STEP_LOGGER_ONLY_TRACE_HEALTH_ENDPOINT"))
	return &LoggerHandler{
		name:   name,
		logger: logger.GetImpl(),
		options: options{
			onlyTraceHealthEndpoint: onlyTraceHealthEndpoint,
		},
		next: next,
	}
}

// ServeHTTP implements the http.Handler and call to the handler to log with a
// custom http.ResponseWriter that records the response code and the number of
// bytes sent.
func (l *LoggerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t := time.Now()
	rw := NewResponseLogger(w)
	l.next.ServeHTTP(rw, r)
	d := time.Since(t)
	l.writeEntry(rw, r, t, d)
}

// writeEntry writes to the Logger writer the request information in the logger.
func (l *LoggerHandler) writeEntry(w ResponseLogger, r *http.Request, t time.Time, d time.Duration) {
	var requestID, userID string

	ctx := r.Context()
	if v, ok := requestid.FromContext(ctx); ok {
		requestID = v
	}
	if v, ok := userid.FromContext(ctx); ok {
		userID = v
	}

	// Remote hostname
	addr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		addr = r.RemoteAddr
	}

	// From https://github.com/gorilla/handlers
	uri := r.RequestURI
	// Requests using the CONNECT method over HTTP/2.0 must use
	// the authority field (aka r.Host) to identify the target.
	// Refer: https://httpwg.github.io/specs/rfc7540.html#CONNECT
	if r.ProtoMajor == 2 && r.Method == "CONNECT" {
		uri = r.Host
	}
	if uri == "" {
		uri = sanitizeLogEntry(r.URL.RequestURI())
	}

	status := w.StatusCode()

	fields := logrus.Fields{
		"request-id":     requestID,
		"remote-address": addr,
		"name":           l.name,
		"user-id":        userID,
		"time":           t.Format(time.RFC3339),
		"duration-ns":    d.Nanoseconds(),
		"duration":       d.String(),
		"method":         r.Method,
		"path":           uri,
		"protocol":       r.Proto,
		"status":         status,
		"size":           w.Size(),
		"referer":        sanitizeLogEntry(r.Referer()),
		"user-agent":     sanitizeLogEntry(r.UserAgent()),
	}

	for k, v := range w.Fields() {
		fields[k] = v
	}

	switch {
	case status < http.StatusBadRequest:
		if l.options.onlyTraceHealthEndpoint && uri == "/health" {
			l.logger.WithFields(fields).Trace()
		} else {
			l.logger.WithFields(fields).Info()
		}
	case status < http.StatusInternalServerError:
		l.logger.WithFields(fields).Warn()
	default:
		l.logger.WithFields(fields).Error()
	}
}

func sanitizeLogEntry(s string) string {
	escaped := strings.ReplaceAll(s, "\n", "")
	return strings.ReplaceAll(escaped, "\r", "")
}
