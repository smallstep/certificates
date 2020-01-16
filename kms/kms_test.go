package kms

import (
	"context"
	"reflect"
	"testing"

	"github.com/smallstep/certificates/kms/apiv1"
	"github.com/smallstep/certificates/kms/cloudkms"
	"github.com/smallstep/certificates/kms/softkms"
)

func TestNew(t *testing.T) {
	ctx := context.Background()

	type args struct {
		ctx  context.Context
		opts apiv1.Options
	}
	tests := []struct {
		name    string
		args    args
		want    KeyManager
		wantErr bool
	}{
		{"softkms", args{ctx, apiv1.Options{Type: "softkms"}}, &softkms.SoftKMS{}, false},
		{"default", args{ctx, apiv1.Options{}}, &softkms.SoftKMS{}, false},
		{"cloudkms", args{ctx, apiv1.Options{Type: "cloudkms"}}, &cloudkms.CloudKMS{}, true}, // fails because not credentials
		{"awskms", args{ctx, apiv1.Options{Type: "awskms"}}, nil, true},                      // not yet supported
		{"pkcs11", args{ctx, apiv1.Options{Type: "pkcs11"}}, nil, true},                      // not yet supported
		{"fail validation", args{ctx, apiv1.Options{Type: "foobar"}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.args.ctx, tt.args.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if reflect.TypeOf(got) != reflect.TypeOf(tt.want) {
				t.Errorf("New() = %T, want %T", got, tt.want)
			}
		})
	}
}
