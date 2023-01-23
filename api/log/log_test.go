package log

import (
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
	tests := []struct {
		name string
		error
		rw               http.ResponseWriter
		isFieldCarrier   bool
		stepDebug        bool
		expectStackTrace bool
	}{
		{"noLogger", nil, nil, false, false, false},
		{"noError", nil, logging.NewResponseLogger(httptest.NewRecorder()), true, false, false},
		{"noErrorDebug", nil, logging.NewResponseLogger(httptest.NewRecorder()), true, true, false},
		{"anError", assert.AnError, logging.NewResponseLogger(httptest.NewRecorder()), true, false, false},
		{"anErrorDebug", assert.AnError, logging.NewResponseLogger(httptest.NewRecorder()), true, true, false},
		{"stackTracedError", new(stackTracedError), logging.NewResponseLogger(httptest.NewRecorder()), true, true, true},
		{"stackTracedErrorDebug", new(stackTracedError), logging.NewResponseLogger(httptest.NewRecorder()), true, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.stepDebug {
				t.Setenv("STEPDEBUG", "1")
			} else {
				t.Setenv("STEPDEBUG", "0")
			}

			Error(tt.rw, tt.error)

			// return early if test case doesn't use logger
			if !tt.isFieldCarrier {
				return
			}

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
		})
	}
}
