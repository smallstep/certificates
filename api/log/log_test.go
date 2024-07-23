package log

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"unsafe"

	pkgerrors "github.com/pkg/errors"
	"github.com/stretchr/testify/assert"

	"github.com/smallstep/certificates/logging"
)

type stackTracedError struct{}

func (stackTracedError) Error() string {
	return "a stacktraced error"
}

func (stackTracedError) StackTrace() pkgerrors.StackTrace {
	f := struct{}{}
	return pkgerrors.StackTrace{ // fake stacktrace
		pkgerrors.Frame(unsafe.Pointer(&f)),
		pkgerrors.Frame(unsafe.Pointer(&f)),
	}
}

func TestError(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{}))
	req := httptest.NewRequest("GET", "/test", http.NoBody)
	reqWithLogger := req.WithContext(WithErrorLogger(req.Context(), func(w http.ResponseWriter, r *http.Request, err error) {
		if err != nil {
			logger.ErrorContext(r.Context(), "request failed", slog.Any("error", err))
		}
	}))

	tests := []struct {
		name string
		error
		rw               http.ResponseWriter
		r                *http.Request
		isFieldCarrier   bool
		isSlogLogger     bool
		stepDebug        bool
		expectStackTrace bool
	}{
		{"noLogger", nil, nil, req, false, false, false, false},
		{"noError", nil, logging.NewResponseLogger(httptest.NewRecorder()), req, true, false, false, false},
		{"noErrorDebug", nil, logging.NewResponseLogger(httptest.NewRecorder()), req, true, false, true, false},
		{"anError", assert.AnError, logging.NewResponseLogger(httptest.NewRecorder()), req, true, false, false, false},
		{"anErrorDebug", assert.AnError, logging.NewResponseLogger(httptest.NewRecorder()), req, true, false, true, false},
		{"stackTracedError", new(stackTracedError), logging.NewResponseLogger(httptest.NewRecorder()), req, true, false, true, true},
		{"stackTracedErrorDebug", new(stackTracedError), logging.NewResponseLogger(httptest.NewRecorder()), req, true, false, true, true},
		{"slogWithNoError", nil, logging.NewResponseLogger(httptest.NewRecorder()), reqWithLogger, true, true, false, false},
		{"slogWithError", assert.AnError, logging.NewResponseLogger(httptest.NewRecorder()), reqWithLogger, true, true, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.stepDebug {
				t.Setenv("STEPDEBUG", "1")
			} else {
				t.Setenv("STEPDEBUG", "0")
			}

			Error(tt.rw, tt.r, tt.error)

			// return early if test case doesn't use logger
			if !tt.isFieldCarrier && !tt.isSlogLogger {
				return
			}

			if tt.isFieldCarrier {
				fields := tt.rw.(logging.ResponseLogger).Fields()

				// expect the error field to be (not) set and to be the same error that was fed to Error
				if tt.error == nil {
					assert.Nil(t, fields["error"])
				} else {
					assert.Same(t, tt.error, fields["error"])
				}

				// check if stack-trace is set when expected
				if _, hasStackTrace := fields["stack-trace"]; tt.expectStackTrace && !hasStackTrace {
					t.Error(`ResponseLogger["stack-trace"] not set`)
				} else if !tt.expectStackTrace && hasStackTrace {
					t.Error(`ResponseLogger["stack-trace"] was set`)
				}
			}

			if tt.isSlogLogger {
				b := buf.Bytes()
				if tt.error == nil {
					assert.Empty(t, b)
				} else if assert.NotEmpty(t, b) {
					var m map[string]any
					assert.NoError(t, json.Unmarshal(b, &m))
					assert.Equal(t, tt.error.Error(), m["error"])
				}
				buf.Reset()
			}
		})
	}
}
