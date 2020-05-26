package kms

import (
	"context"
	"os"
	"reflect"
	"testing"

	"github.com/smallstep/certificates/kms/apiv1"
	"github.com/smallstep/certificates/kms/awskms"
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
		name     string
		skipOnCI bool
		args     args
		want     KeyManager
		wantErr  bool
	}{
		{"softkms", false, args{ctx, apiv1.Options{Type: "softkms"}}, &softkms.SoftKMS{}, false},
		{"default", false, args{ctx, apiv1.Options{}}, &softkms.SoftKMS{}, false},
		{"awskms", false, args{ctx, apiv1.Options{Type: "awskms"}}, &awskms.KMS{}, false},
		{"cloudkms", true, args{ctx, apiv1.Options{Type: "cloudkms"}}, &cloudkms.CloudKMS{}, true}, // fails because not credentials
		{"pkcs11", false, args{ctx, apiv1.Options{Type: "pkcs11"}}, nil, true},                     // not yet supported
		{"fail validation", false, args{ctx, apiv1.Options{Type: "foobar"}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipOnCI && os.Getenv("CI") == "true" {
				t.SkipNow()
			}

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
