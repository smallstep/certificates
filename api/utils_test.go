package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/smallstep/certificates/logging"
)

func TestJSON(t *testing.T) {
	type args struct {
		rw http.ResponseWriter
		v  interface{}
	}
	tests := []struct {
		name string
		args args
		ok   bool
	}{
		{"ok", args{httptest.NewRecorder(), map[string]interface{}{"foo": "bar"}}, true},
		{"fail", args{httptest.NewRecorder(), make(chan int)}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rw := logging.NewResponseLogger(tt.args.rw)
			JSON(rw, tt.args.v)

			rr, ok := tt.args.rw.(*httptest.ResponseRecorder)
			if !ok {
				t.Error("ResponseWriter does not implement *httptest.ResponseRecorder")
				return
			}

			fields := rw.Fields()
			if tt.ok {
				if body := rr.Body.String(); body != "{\"foo\":\"bar\"}\n" {
					t.Errorf(`Unexpected body = %v, want {"foo":"bar"}`, body)
				}
				if len(fields) != 0 {
					t.Errorf("ResponseLogger fields = %v, wants 0 elements", fields)
				}
			} else {
				if body := rr.Body.String(); body != "" {
					t.Errorf("Unexpected body = %s, want empty string", body)
				}
				if len(fields) != 1 {
					t.Errorf("ResponseLogger fields = %v, wants 1 element", fields)
				}
			}
		})
	}
}
