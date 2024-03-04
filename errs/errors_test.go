package errs

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
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
			if tt.wantErr {
				assert.Error(t, err)
				assert.Empty(t, got)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
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
			err := e.UnmarshalJSON(tt.args.data)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.expected, e)
		})
	}
}
