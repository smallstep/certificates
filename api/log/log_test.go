package log

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/smallstep/certificates/logging"
)

func TestError(t *testing.T) {
	theError := errors.New("the error")

	type args struct {
		rw  http.ResponseWriter
		err error
	}
	tests := []struct {
		name       string
		args       args
		withFields bool
	}{
		{"normalLogger", args{httptest.NewRecorder(), theError}, false},
		{"responseLogger", args{logging.NewResponseLogger(httptest.NewRecorder()), theError}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Error(tt.args.rw, tt.args.err)
			if tt.withFields {
				if rl, ok := tt.args.rw.(logging.ResponseLogger); ok {
					fields := rl.Fields()
					if !reflect.DeepEqual(fields["error"], theError) {
						t.Errorf("ResponseLogger[\"error\"] = %s, wants %s", fields["error"], theError)
					}
				} else {
					t.Error("ResponseWriter does not implement logging.ResponseLogger")
				}
			}
		})
	}
}
