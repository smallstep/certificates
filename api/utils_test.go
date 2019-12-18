package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/errs"
	"github.com/smallstep/certificates/logging"
)

func TestLogError(t *testing.T) {
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
			LogError(tt.args.rw, tt.args.err)
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

func TestReadJSON(t *testing.T) {
	type args struct {
		r io.Reader
		v interface{}
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"ok", args{strings.NewReader(`{"foo":"bar"}`), make(map[string]interface{})}, false},
		{"fail", args{strings.NewReader(`{"foo"}`), make(map[string]interface{})}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ReadJSON(tt.args.r, &tt.args.v)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				e, ok := err.(*errs.Error)
				if ok {
					if code := e.StatusCode(); code != 400 {
						t.Errorf("error.StatusCode() = %v, wants 400", code)
					}
				} else {
					t.Errorf("error type = %T, wants *Error", err)
				}
			} else if !reflect.DeepEqual(tt.args.v, map[string]interface{}{"foo": "bar"}) {
				t.Errorf("ReadJSON value = %v, wants %v", tt.args.v, map[string]interface{}{"foo": "bar"})
			}
		})
	}
}
