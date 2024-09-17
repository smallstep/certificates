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

			r := httptest.NewRequest("GET", tt.path, http.NoBody)
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

				r := httptest.NewRequest("GET", tt.path, http.NoBody)
				w := httptest.NewRecorder()
				l.ServeHTTP(w, r)

				if assert.Equals(t, 1, len(hook.AllEntries())) {
					assert.Equals(t, tt.want, hook.LastEntry().Level)
				}
			}
		})
	}
}

// TestLogRealIP ensures that the real originating IP is logged instead of the
// proxy IP when STEP_LOGGER_LOG_REAL_IP is set to true and specific headers are
// present.
func TestLogRealIP(t *testing.T) {
	statusHandler := func(statusCode int) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(statusCode)
			w.Write([]byte("{}"))
		}
	}

	proxyIP := "1.1.1.1"

	tests := []struct {
		name      string
		logRealIP string
		headers   map[string]string
		expected  string
	}{
		{
			name:      "setting is turned on, no header is set",
			logRealIP: "true",
			expected:  "1.1.1.1",
			headers:   map[string]string{},
		},
		{
			name:      "setting is turned on, True-Client-IP header is set",
			logRealIP: "true",
			headers: map[string]string{
				"True-Client-IP": "2.2.2.2",
			},
			expected: "2.2.2.2",
		},
		{
			name:      "setting is turned on, True-Client-IP header is set with invalid value",
			logRealIP: "true",
			headers: map[string]string{
				"True-Client-IP": "a.b.c.d",
			},
			expected: "1.1.1.1",
		},
		{
			name:      "setting is turned on, X-Real-IP header is set",
			logRealIP: "true",
			headers: map[string]string{
				"X-Real-IP": "3.3.3.3",
			},
			expected: "3.3.3.3",
		},
		{
			name:      "setting is turned on, X-Forwarded-For header is set",
			logRealIP: "true",
			headers: map[string]string{
				"X-Forwarded-For": "4.4.4.4",
			},
			expected: "4.4.4.4",
		},
		{
			name:      "setting is turned on, X-Forwarded-For header is set with multiple IPs",
			logRealIP: "true",
			headers: map[string]string{
				"X-Forwarded-For": "4.4.4.4, 5.5.5.5, 6.6.6.6",
			},
			expected: "4.4.4.4",
		},
		{
			name:      "setting is turned on, all headers are set",
			logRealIP: "true",
			headers: map[string]string{
				"True-Client-IP":  "2.2.2.2",
				"X-Real-IP":       "3.3.3.3",
				"X-Forwarded-For": "4.4.4.4",
			},
			expected: "2.2.2.2",
		},
		{
			name:      "setting is turned off, True-Client-IP header is set",
			logRealIP: "false",
			expected:  "1.1.1.1",
			headers: map[string]string{
				"True-Client-IP": "2.2.2.2",
			},
		},
		{
			name:      "setting is turned off, no header is set",
			logRealIP: "false",
			expected:  "1.1.1.1",
			headers:   map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("STEP_LOGGER_LOG_REAL_IP", tt.logRealIP)

			baseLogger, hook := test.NewNullLogger()
			logger := &Logger{
				Logger: baseLogger,
			}
			l := NewLoggerHandler("test", logger, statusHandler(http.StatusOK))

			r := httptest.NewRequest("GET", "/test", http.NoBody)
			r.RemoteAddr = proxyIP
			for k, v := range tt.headers {
				r.Header.Set(k, v)
			}
			w := httptest.NewRecorder()
			l.ServeHTTP(w, r)

			if assert.Equals(t, 1, len(hook.AllEntries())) {
				entry := hook.LastEntry()
				assert.Equals(t, tt.expected, entry.Data["remote-address"])
			}
		})
	}
}
