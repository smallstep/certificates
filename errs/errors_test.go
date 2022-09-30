package errs

import (
	"fmt"
	"reflect"
	"testing"
)

func TestError_MarshalJSON(t *testing.T) {
	type fields struct {
		Status int
		Err    error
	}
	tests := []struct {
		name    string
		fields  fields
		want    []byte
		wantErr bool
	}{
		{"ok", fields{400, fmt.Errorf("bad request")}, []byte(`{"status":400,"message":"Bad Request"}`), false},
		{"ok no error", fields{500, nil}, []byte(`{"status":500,"message":"Internal Server Error"}`), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Error{
				Status: tt.fields.Status,
				Err:    tt.fields.Err,
			}
			got, err := e.MarshalJSON()
			if (err != nil) != tt.wantErr {
				t.Errorf("Error.MarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Error.MarshalJSON() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestError_UnmarshalJSON(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name     string
		args     args
		expected *Error
		wantErr  bool
	}{
		{"ok", args{[]byte(`{"status":400,"message":"bad request"}`)}, &Error{Status: 400, Err: fmt.Errorf("bad request")}, false},
		{"fail", args{[]byte(`{"status":"400","message":"bad request"}`)}, &Error{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := new(Error)
			if err := e.UnmarshalJSON(tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("Error.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			//nolint:govet // best option
			if !reflect.DeepEqual(tt.expected, e) {
				t.Errorf("Error.UnmarshalJSON() wants = %+v, got %+v", tt.expected, e)
			}
		})
	}
}
