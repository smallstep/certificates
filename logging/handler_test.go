package logging

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/smallstep/assert"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
)

// TestHealthOKHandling ensures that http requests from the Kubernetes
// liveness/readiness probes are only logged at Trace level if they are HTTP
// 200 (which is normal operation) and the user has opted-in. If the user has
// not opted-in then they continue to be logged at Info level.
func TestHealthOKHandling(t *testing.T) {
	statusHandler := func(statusCode int) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(statusCode)
			fmt.Fprint(w, "{}")
		}
	}

	tests := []struct {
		name    string
		path    string
		options options
		handler http.HandlerFunc
		want    logrus.Level
	}{
		{
			name:    "200 should be logged at Info level for /health request without explicit opt-in",
			path:    "/health",
			handler: statusHandler(http.StatusOK),
			want:    logrus.InfoLevel,
		},
		{
			name: "200 should be logged only at Trace level for /health request if opt-in",
			path: "/health",
			options: options{
				onlyTraceHealthEndpoint: true,
			},
			handler: statusHandler(http.StatusOK),
			want:    logrus.TraceLevel,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, hook := test.NewNullLogger()
			logger.SetLevel(logrus.TraceLevel)
			l := &LoggerHandler{
				logger:  logger,
				options: tt.options,
				next:    tt.handler,
			}

			r := httptest.NewRequest("GET", tt.path, nil)
			w := httptest.NewRecorder()
			l.ServeHTTP(w, r)

			if assert.Equals(t, 1, len(hook.AllEntries())) {
				assert.Equals(t, tt.want, hook.LastEntry().Level)
			}
		})
	}
}

// TestHandlingRegardlessOfOptions ensures that http requests are treated like
// any other request if they are for a non-health uri or fall within the
// warn/error ranges of the http status codes, regardless of the
// "onlyTraceHealthEndpoint" option.
func TestHandlingRegardlessOfOptions(t *testing.T) {
	statusHandler := func(statusCode int) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(statusCode)
			fmt.Fprint(w, "{}")
		}
	}

	tests := []struct {
		name    string
		path    string
		handler http.HandlerFunc
		want    logrus.Level
	}{
		{
			name:    "200 should be logged at Info level for non-health requests",
			path:    "/info",
			handler: statusHandler(http.StatusOK),
			want:    logrus.InfoLevel,
		},
		{
			name:    "400 should be logged at Warn level for non-health requests",
			path:    "/info",
			handler: statusHandler(http.StatusBadRequest),
			want:    logrus.WarnLevel,
		},
		{
			name:    "500 should be logged at Error level for non-health requests",
			path:    "/info",
			handler: statusHandler(http.StatusInternalServerError),
			want:    logrus.ErrorLevel,
		},
		{
			name:    "400 should be logged at Warn level even for /health requests",
			path:    "/health",
			handler: statusHandler(http.StatusBadRequest),
			want:    logrus.WarnLevel,
		},
		{
			name:    "500 should be logged at Error level even for /health requests",
			path:    "/health",
			handler: statusHandler(http.StatusInternalServerError),
			want:    logrus.ErrorLevel,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, b := range []bool{true, false} {
				logger, hook := test.NewNullLogger()
				logger.SetLevel(logrus.TraceLevel)
				l := &LoggerHandler{
					logger: logger,
					options: options{
						onlyTraceHealthEndpoint: b,
					},
					next: tt.handler,
				}

				r := httptest.NewRequest("GET", tt.path, nil)
				w := httptest.NewRecorder()
				l.ServeHTTP(w, r)

				if assert.Equals(t, 1, len(hook.AllEntries())) {
					assert.Equals(t, tt.want, hook.LastEntry().Level)
				}
			}
		})
	}
}
