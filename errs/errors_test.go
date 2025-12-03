package errs

import (
	"errors"
	"fmt"
	"net/http"
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

func TestError_Unwrap(t *testing.T) {
	err := errors.New("wrapped error")
	tests := []struct {
		name  string
		error error
		want  string
	}{
		{"ok New", New(http.StatusBadRequest, "some error"), "some error"},
		{"ok New v-wrap", New(http.StatusBadRequest, "some error: %v", err), "some error: wrapped error"},
		{"ok NewError", NewError(http.StatusBadRequest, err, "some error"), "some error: wrapped error"},
		{"ok NewErr", NewErr(http.StatusBadRequest, err), "wrapped error"},
		{"ok NewErr wit message", NewErr(http.StatusBadRequest, err, WithMessage("some message")), "wrapped error"},
		{"ok Errorf", Errorf(http.StatusBadRequest, "some error: %w", err), "some error: wrapped error"},
		{"ok Errorf v-wrap", Errorf(http.StatusBadRequest, "some error: %v", err), "some error: wrapped error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := errors.Unwrap(tt.error)
			assert.EqualError(t, got, tt.want)
		})
	}
}

type customError struct {
	Message string
}

func (e *customError) Error() string {
	return e.Message
}

func TestError_Unwrap_As(t *testing.T) {
	err := &customError{Message: "wrapped error"}

	tests := []struct {
		name    string
		error   error
		want    bool
		wantErr *customError
	}{
		{"ok NewError", NewError(http.StatusBadRequest, err, "some error"), true, err},
		{"ok NewErr", NewErr(http.StatusBadRequest, err), true, err},
		{"ok NewErr wit message", NewErr(http.StatusBadRequest, err, WithMessage("some message")), true, err},
		{"ok Errorf", Errorf(http.StatusBadRequest, "some error: %w", err), true, err},
		{"fail New", New(http.StatusBadRequest, "some error"), false, nil},
		{"fail New v-wrap", New(http.StatusBadRequest, "some error: %v", err), false, nil},
		{"fail Errorf", Errorf(http.StatusBadRequest, "some error"), false, nil},
		{"fail Errorf v-wrap", Errorf(http.StatusBadRequest, "some error: %v", err), false, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cerr *customError
			assert.Equal(t, tt.want, errors.As(tt.error, &cerr))
			assert.Equal(t, tt.wantErr, cerr)
		})
	}
}

func TestErrorf(t *testing.T) {
	tests := []struct {
		name   string
		code   int
		format string
		args   []any
		want   error
	}{
		{"bad request", 400, "test error string", nil, &Error{
			Status: 400,
			Err:    errors.New("test error string"),
			Msg:    BadRequestDefaultMsg,
		}},
		{"unauthorized", 401, "test error string", nil, &Error{
			Status: 401,
			Err:    errors.New("test error string"),
			Msg:    UnauthorizedDefaultMsg,
		}},
		{"forbidden", 403, "test error string", nil, &Error{
			Status: 403,
			Err:    errors.New("test error string"),
			Msg:    ForbiddenDefaultMsg,
		}},
		{"not found", 404, "test error string", nil, &Error{
			Status: 404,
			Err:    errors.New("test error string"),
			Msg:    NotFoundDefaultMsg,
		}},
		{"internal server error", 500, "test error string", nil, &Error{
			Status: 500,
			Err:    errors.New("test error string"),
			Msg:    InternalServerErrorDefaultMsg,
		}},
		{"not implemented", 501, "test error string", nil, &Error{
			Status: 501,
			Err:    errors.New("test error string"),
			Msg:    NotImplementedDefaultMsg,
		}},
		{"other", 502, "test error string", nil, &Error{
			Status: 502,
			Err:    errors.New("test error string"),
			Msg:    defaultMsg,
		}},
		{"formatted args", 401, "test error string: %s", []any{"some reason"}, &Error{
			Status: 401,
			Err:    errors.New("test error string: some reason"),
			Msg:    UnauthorizedDefaultMsg,
		}},
		{"WithMessage", 403, "test error string", []any{WithMessage("%s failed", "something")}, &Error{
			Status: 403,
			Err:    errors.New("test error string"),
			Msg:    "something failed",
		}},
		{"WithErrorMessage", 404, "test error string", []any{WithErrorMessage()}, &Error{
			Status: 404,
			Err:    errors.New("test error string"),
			Msg:    "test error string",
		}},
		{"WithKeyValue", 500, "test error string", []any{WithKeyVal("foo", 1), WithKeyVal("bar", "zar")}, &Error{
			Status:  500,
			Err:     errors.New("test error string"),
			Msg:     InternalServerErrorDefaultMsg,
			Details: map[string]interface{}{"foo": 1, "bar": "zar"},
		}},
		{"withDefaultMessage", 501, "test error string", []any{withDefaultMessage("some message")}, &Error{
			Status: 501,
			Err:    errors.New("test error string"),
			Msg:    "some message",
		}},
		{"withFormattedMessage", 502, "test error string", []any{withFormattedMessage("some message: %s", "the reason")}, &Error{
			Status: 502,
			Err:    errors.New("test error string"),
			Msg:    "some message: the reason",
		}},
		{"WithMessage and withDefaultMessage", 500, "test error string", []any{WithMessage("the message"), withDefaultMessage("some message")}, &Error{
			Status: 500,
			Err:    errors.New("test error string"),
			Msg:    "the message",
		}},
		{"WithErrorMessage and withFormattedMessage", 500, "test error string", []any{WithErrorMessage(), withFormattedMessage("some message: %s", "the reason")}, &Error{
			Status: 500,
			Err:    errors.New("test error string"),
			Msg:    "test error string",
		}},
		{"formatted args and withMessage", 500, "test error string: %s, code %d", []any{"reason", 1234, WithMessage("the message")}, &Error{
			Status: 500,
			Err:    errors.New("test error string: reason, code 1234"),
			Msg:    "the message",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotErr := Errorf(tt.code, tt.format, tt.args...)
			assert.Equal(t, tt.want, gotErr)
		})
	}
}
