// Package api implements a SCEP HTTP server.
package api

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_decodeRequest(t *testing.T) {
	randomB64 := "wx/1mQ49TpdLRfvVjQhXNSe8RB3hjZEarqYp5XVIxpSbvOhQSs8hP2TgucID1IputbA8JC6CbsUpcVae3+8hRNqs5pTsSHP2aNxsw8AHGSX9dZVymSclkUV8irk+ztfEfs7aLA=="
	expectedRandom, err := base64.StdEncoding.DecodeString(randomB64)
	require.NoError(t, err)
	weirdMacOSCase := "wx/1mQ49TpdLRfvVjQhXNSe8RB3hjZEarqYp5XVIxpSbvOhQSs8hP2TgucID1IputbA8JC6CbsUpcVae3+8hRNqs5pTsSHP2aNxsw8AHGSX9dZVymSclkUV8irk+ztfEfs7aLA%3D%3D"
	expectedWeirdMacOSCase, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(weirdMacOSCase, "%3D", "="))
	require.NoError(t, err)
	type args struct {
		r *http.Request
	}
	tests := []struct {
		name    string
		args    args
		want    request
		wantErr bool
	}{
		{
			name: "fail/invalid-query",
			args: args{
				r: httptest.NewRequest(http.MethodGet, "http://scep:8080/?operation=bla;message=invalid-separator", http.NoBody),
			},
			want:    request{},
			wantErr: true,
		},
		{
			name: "fail/empty-operation",
			args: args{
				r: httptest.NewRequest(http.MethodGet, "http://scep:8080/?operation=", http.NoBody),
			},
			want:    request{},
			wantErr: true,
		},
		{
			name: "fail/unsupported-method",
			args: args{
				r: httptest.NewRequest(http.MethodPatch, "http://scep:8080/?operation=AnUnsupportOperation", http.NoBody),
			},
			want:    request{},
			wantErr: true,
		},
		{
			name: "fail/get-unsupported-operation",
			args: args{
				r: httptest.NewRequest(http.MethodGet, "http://scep:8080/?operation=AnUnsupportOperation", http.NoBody),
			},
			want:    request{},
			wantErr: true,
		},
		{
			name: "fail/get-PKIOperation-empty-message",
			args: args{
				r: httptest.NewRequest(http.MethodGet, "http://scep:8080/?operation=PKIOperation&message=", http.NoBody),
			},
			want:    request{},
			wantErr: true,
		},
		{
			name: "fail/get-PKIOperation",
			args: args{
				r: httptest.NewRequest(http.MethodGet, "http://scep:8080/?operation=PKIOperation&message='somewronginput'", http.NoBody),
			},
			want:    request{},
			wantErr: true,
		},
		{
			name: "fail/post-PKIOperation",
			args: args{
				r: httptest.NewRequest(http.MethodPost, "http://scep:8080/?operation=PKIOperation", iotest.ErrReader(errors.New("a read error"))),
			},
			want:    request{},
			wantErr: true,
		},
		{
			name: "ok/get-GetCACert",
			args: args{
				r: httptest.NewRequest(http.MethodGet, "http://scep:8080/?operation=GetCACert", http.NoBody),
			},
			want: request{
				Operation: "GetCACert",
				Message:   []byte{},
			},
			wantErr: false,
		},
		{
			name: "ok/get-GetCACaps",
			args: args{
				r: httptest.NewRequest(http.MethodGet, "http://scep:8080/?operation=GetCACaps", http.NoBody),
			},
			want: request{
				Operation: "GetCACaps",
				Message:   []byte{},
			},
			wantErr: false,
		},
		{
			name: "ok/get-PKIOperation",
			args: args{
				r: httptest.NewRequest(http.MethodGet, "http://scep:8080/?operation=PKIOperation&message=MTIzNA==", http.NoBody),
			},
			want: request{
				Operation: "PKIOperation",
				Message:   []byte("1234"),
			},
			wantErr: false,
		},
		{
			name: "ok/get-PKIOperation-escaped",
			args: args{
				r: httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://scep:8080/?operation=PKIOperation&message=%s", url.QueryEscape(randomB64)), http.NoBody),
			},
			want: request{
				Operation: "PKIOperation",
				Message:   expectedRandom,
			},
			wantErr: false,
		},
		{
			name: "ok/get-PKIOperation-not-escaped", // bit of a special case, but this is supported because of the macOS case now
			args: args{
				r: httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://scep:8080/?operation=PKIOperation&message=%s", randomB64), http.NoBody),
			},
			want: request{
				Operation: "PKIOperation",
				Message:   expectedRandom,
			},
			wantErr: false,
		},
		{
			name: "ok/get-PKIOperation-weird-macos-case", // a special case for macOS, which seems to result in the message not arriving fully percent-encoded
			args: args{
				r: httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://scep:8080/?operation=PKIOperation&message=%s", weirdMacOSCase), http.NoBody),
			},
			want: request{
				Operation: "PKIOperation",
				Message:   expectedWeirdMacOSCase,
			},
			wantErr: false,
		},
		{
			name: "ok/post-PKIOperation",
			args: args{
				r: httptest.NewRequest(http.MethodPost, "http://scep:8080/?operation=PKIOperation", bytes.NewBufferString("1234")),
			},
			want: request{
				Operation: "PKIOperation",
				Message:   []byte("1234"),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeRequest(tt.args.r)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Equal(t, tt.want, got)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
