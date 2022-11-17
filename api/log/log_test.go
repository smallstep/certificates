package log

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"unsafe"

	pkgerrors "github.com/pkg/errors"

	"github.com/smallstep/certificates/logging"
)

func TestError(t *testing.T) {

	t.Setenv("STEPDEBUG", "1") // force to end of `Error` function instead of early return
	theError := errors.New("the error")

	type args struct {
		rw  http.ResponseWriter
		err error
	}
	tests := []struct {
		name       string
		args       args
		withFields bool
		want       string
	}{
		{"normalLogger", args{httptest.NewRecorder(), theError}, false, "the error"},
		{"responseLogger", args{logging.NewResponseLogger(httptest.NewRecorder()), theError}, true, "the error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Error(tt.args.rw, tt.args.err)
			if tt.withFields {
				if rl, ok := tt.args.rw.(logging.ResponseLogger); ok {
					fields := rl.Fields()
					if fields["error"].(error).Error() != tt.want {
						t.Errorf(`ResponseLogger["error"] = %s, wants %s`, fields["error"], tt.want)
					}
				} else {
					t.Error("ResponseWriter does not implement logging.ResponseLogger")
				}
			}
		})
	}
}

type mockStackTracedError struct{}

func (t *mockStackTracedError) Error() string {
	return "a stacktraced error"
}

func (t *mockStackTracedError) StackTrace() pkgerrors.StackTrace {
	f := struct{}{}
	return pkgerrors.StackTrace{ // fake stacktrace
		pkgerrors.Frame(unsafe.Pointer(&f)),
		pkgerrors.Frame(unsafe.Pointer(&f)),
	}
}

func TestError_StackTracedError(t *testing.T) {

	t.Setenv("STEPDEBUG", "1")
	aStackTracedError := mockStackTracedError{}

	type args struct {
		rw  http.ResponseWriter
		err error
	}
	tests := []struct {
		name       string
		args       args
		withFields bool
		want       string
	}{
		{"responseLoggerWithStackTracedError", args{logging.NewResponseLogger(httptest.NewRecorder()), &aStackTracedError}, true, "a stacktraced error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Error(tt.args.rw, tt.args.err)
			if tt.withFields {
				if rl, ok := tt.args.rw.(logging.ResponseLogger); ok {
					fields := rl.Fields()
					if fields["error"].(error).Error() != tt.want {
						t.Errorf(`ResponseLogger["error"] = %s, wants %s`, fields["error"], tt.want)
					}
					// `stack-trace` expected to be set; not interested in actual output
					if _, ok := fields["stack-trace"]; !ok {
						t.Errorf(`ResponseLogger["stack-trace"] not set`)
					}
				} else {
					t.Error("ResponseWriter does not implement logging.ResponseLogger")
				}
			}
		})
	}
}
