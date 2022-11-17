package log

import (
	"net/http/httptest"
	"strconv"
	"testing"
	"unsafe"

	pkgerrors "github.com/pkg/errors"
	"github.com/stretchr/testify/assert"

	"github.com/smallstep/certificates/logging"
)

func TestError(t *testing.T) {
	cases := []struct {
		error
		stepDebug        bool
		expectStackTrace bool
	}{
		0: {nil, false, false},
		1: {nil, true, false},
		2: {assert.AnError, false, false},
		3: {assert.AnError, true, false},
		4: {new(stackTracedError), false, false},
		5: {new(stackTracedError), true, true},
	}

	for caseIndex := range cases {
		kase := cases[caseIndex]

		t.Run(strconv.Itoa(caseIndex), func(t *testing.T) {
			if kase.stepDebug {
				t.Setenv("STEPDEBUG", "1")
			} else {
				t.Setenv("STEPDEBUG", "0")
			}

			rw := logging.NewResponseLogger(httptest.NewRecorder())
			Error(rw, kase.error)

			fields := rw.Fields()

			// expect the error field to be set and to be the same error that was fed to Error
			if kase.error == nil {
				assert.Nil(t, fields["error"])
			} else {
				assert.Same(t, kase.error, fields["error"])
			}

			if _, hasStackTrace := fields["stack-trace"]; kase.expectStackTrace && !hasStackTrace {
				t.Error("stack-trace was not set")
			} else if !kase.expectStackTrace && hasStackTrace {
				t.Error("stack-trace was set")
			}
		})
	}
}

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
