package read

import (
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/smallstep/certificates/errs"
)

func TestJSON(t *testing.T) {
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
			err := JSON(tt.args.r, &tt.args.v)
			if (err != nil) != tt.wantErr {
				t.Errorf("JSON() error = %v, wantErr %v", err, tt.wantErr)
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
				t.Errorf("JSON value = %v, wants %v", tt.args.v, map[string]interface{}{"foo": "bar"})
			}
		})
	}
}
