package read

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"go.step.sm/linkedca"

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
				var e *errs.Error
				if errors.As(err, &e) {
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

func TestProtoJSON(t *testing.T) {

	p := new(linkedca.Policy) // TODO(hs): can we use something different, so we don't need the import?

	type args struct {
		r io.Reader
		m proto.Message
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "fail/io.ReadAll",
			args: args{
				r: iotest.ErrReader(errors.New("read error")),
				m: p,
			},
			wantErr: true,
		},
		{
			name: "fail/proto",
			args: args{
				r: strings.NewReader(`{?}`),
				m: p,
			},
			wantErr: true,
		},
		{
			name: "ok",
			args: args{
				r: strings.NewReader(`{"x509":{}}`),
				m: p,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ProtoJSON(tt.args.r, tt.args.m)
			if (err != nil) != tt.wantErr {
				t.Errorf("ProtoJSON() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr {
				var (
					ee  *errs.Error
					bpe badProtoJSONError
				)
				switch {
				case errors.As(err, &bpe):
					assert.Contains(t, err.Error(), "syntax error")
				case errors.As(err, &ee):
					assert.Equal(t, http.StatusBadRequest, ee.Status)
				}
				return
			}

			assert.Equal(t, protoreflect.FullName("linkedca.Policy"), proto.MessageName(tt.args.m))
			assert.True(t, proto.Equal(&linkedca.Policy{X509: &linkedca.X509Policy{}}, tt.args.m))
		})
	}
}

func Test_badProtoJSONError_Render(t *testing.T) {
	tests := []struct {
		name     string
		e        badProtoJSONError
		expected string
	}{
		{
			name:     "bad proto normal space",
			e:        badProtoJSONError("proto: syntax error (line 1:2): invalid value ?"),
			expected: "syntax error (line 1:2): invalid value ?",
		},
		{
			name:     "bad proto non breaking space",
			e:        badProtoJSONError("proto: syntax error (line 1:2): invalid value ?"),
			expected: "syntax error (line 1:2): invalid value ?",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			w := httptest.NewRecorder()
			tt.e.Render(w)
			res := w.Result()
			defer res.Body.Close()

			data, err := io.ReadAll(res.Body)
			assert.NoError(t, err)

			v := struct {
				Type    string `json:"type"`
				Detail  string `json:"detail"`
				Message string `json:"message"`
			}{}

			assert.NoError(t, json.Unmarshal(data, &v))
			assert.Equal(t, "badRequest", v.Type)
			assert.Equal(t, "bad request", v.Detail)
			assert.Equal(t, "syntax error (line 1:2): invalid value ?", v.Message)

		})
	}
}
