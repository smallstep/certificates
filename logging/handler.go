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

// Common headers used for identifying the originating IP address of a client
// connecting to a web server through a proxy server
var (
	trueClientIP  = http.CanonicalHeaderKey("True-Client-IP")
	xRealIP       = http.CanonicalHeaderKey("X-Real-IP")
	xForwardedFor = http.CanonicalHeaderKey("X-Forwarded-For")
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

	// logRealIP determines if the real IP address of the client should be logged
	// instead of the IP address of the proxy
	logRealIP bool
}

// NewLoggerHandler returns the given http.Handler with the logger integrated.
func NewLoggerHandler(name string, logger *Logger, next http.Handler) http.Handler {
	onlyTraceHealthEndpoint, _ := strconv.ParseBool(os.Getenv("STEP_LOGGER_ONLY_TRACE_HEALTH_ENDPOINT"))
	logRealIP, _ := strconv.ParseBool(os.Getenv("STEP_LOGGER_LOG_REAL_IP"))

	return &LoggerHandler{
		name:   name,
		logger: logger.GetImpl(),
		options: options{
			onlyTraceHealthEndpoint: onlyTraceHealthEndpoint,
			logRealIP:               logRealIP,
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
	addr := r.RemoteAddr
	if l.options.logRealIP {
		addr = realIP(r)
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		addr = host
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

// realIP returns the real IP address of the client connecting to the server by
// parsing either the True-Client-IP, X-Real-IP or the X-Forwarded-For headers
// (in that order). If the headers are not set or set to an invalid IP, it
// returns the RemoteAddr of the request.
func realIP(r *http.Request) string {
	var ip string

	if tcip := r.Header.Get(trueClientIP); tcip != "" {
		ip = tcip
	} else if xrip := r.Header.Get(xRealIP); xrip != "" {
		ip = xrip
	} else if xff := r.Header.Get(xForwardedFor); xff != "" {
		i := strings.Index(xff, ",")
		if i == -1 {
			i = len(xff)
		}
		ip = xff[:i]
	}
	if ip == "" || net.ParseIP(ip) == nil {
		return r.RemoteAddr
	}
	return ip
}
