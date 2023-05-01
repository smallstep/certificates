// Package api implements a SCEP HTTP server.
package api

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"testing/iotest"

	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/linkedca"
)

func Test_decodeRequest(t *testing.T) {
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
			name: "fail/unsupported-method",
			args: args{
				r: httptest.NewRequest(http.MethodPatch, "http://scep:8080/?operation=AnUnsupportOperation", nil),
			},
			want:    request{},
			wantErr: true,
		},
		{
			name: "fail/get-unsupported-operation",
			args: args{
				r: httptest.NewRequest(http.MethodGet, "http://scep:8080/?operation=AnUnsupportOperation", nil),
			},
			want:    request{},
			wantErr: true,
		},
		{
			name: "fail/get-PKIOperation",
			args: args{
				r: httptest.NewRequest(http.MethodGet, "http://scep:8080/?operation=PKIOperation&message='somewronginput'", nil),
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
				r: httptest.NewRequest(http.MethodGet, "http://scep:8080/?operation=GetCACert", nil),
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
				r: httptest.NewRequest(http.MethodGet, "http://scep:8080/?operation=GetCACaps", nil),
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
				r: httptest.NewRequest(http.MethodGet, "http://scep:8080/?operation=PKIOperation&message=MTIzNA==", nil),
			},
			want: request{
				Operation: "PKIOperation",
				Message:   []byte("1234"),
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
			if (err != nil) != tt.wantErr {
				t.Errorf("decodeRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("decodeRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_selectValidationMethod(t *testing.T) {
	tests := []struct {
		name string
		p    *provisioner.SCEP
		want validationMethod
	}{
		{"webhooks", &provisioner.SCEP{
			Name: "SCEP",
			Type: "SCEP",
			Options: &provisioner.Options{
				Webhooks: []*provisioner.Webhook{
					{
						Kind: linkedca.Webhook_SCEPCHALLENGE.String(),
					},
				},
			},
			Claims: &provisioner.Claims{},
		}, "webhook"},
		{"challenge", &provisioner.SCEP{
			Name:              "SCEP",
			Type:              "SCEP",
			ChallengePassword: "pass",
			Options:           &provisioner.Options{},
			Claims:            &provisioner.Claims{},
		}, "static"},
		{"none", &provisioner.SCEP{
			Name:    "SCEP",
			Type:    "SCEP",
			Options: &provisioner.Options{},
			Claims:  &provisioner.Claims{},
		}, "none"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.p.Init(provisioner.Config{
				Claims: config.GlobalProvisionerClaims,
			})
			require.NoError(t, err)
			got := selectValidationMethod(tt.p)
			assert.Equal(t, tt.want, got)
		})
	}
}
