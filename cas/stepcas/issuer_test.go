package stepcas

import (
	"context"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/cas/apiv1"
	"go.step.sm/crypto/jose"
)

type mockErrIssuer struct{}

func (m mockErrIssuer) SignToken(subject string, sans []string, info *raInfo) (string, error) {
	return "", apiv1.NotImplementedError{}
}

func (m mockErrIssuer) RevokeToken(subject string) (string, error) {
	return "", apiv1.NotImplementedError{}
}

func (m mockErrIssuer) Lifetime(d time.Duration) time.Duration {
	return d
}

type mockErrSigner struct{}

func (s *mockErrSigner) Sign(payload []byte) (*jose.JSONWebSignature, error) {
	return nil, apiv1.NotImplementedError{}
}

func (s *mockErrSigner) Options() jose.SignerOptions {
	return jose.SignerOptions{}
}

func Test_newServerEndpointID(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{"ok", args{"foo"}, []byte{
			0x8f, 0x63, 0x69, 0x20, 0x8a, 0x7a, 0x57, 0x0c, 0xbe, 0x4c, 0x46, 0x66, 0x77, 0xf8, 0x54, 0xe7,
		}},
		{"ok uuid", args{"e4fa6d2d-fa9c-4fdc-913e-7484cc9516e4"}, []byte{
			0x8d, 0x8d, 0x7f, 0x04, 0x73, 0xd4, 0x5f, 0x2f, 0xa8, 0xe1, 0x28, 0x9a, 0xd1, 0xa8, 0xcf, 0x7e,
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var want uuid.UUID
			copy(want[:], tt.want)
			got := newServerEndpointID(tt.args.name)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("newServerEndpointID() = %v, want %v", got, tt.want)
			}
			// Check version
			if v := (got[6] & 0xf0) >> 4; v != 5 {
				t.Errorf("newServerEndpointID() version = %d, want 5", v)
			}
			// Check variant
			if v := (got[8] & 0x80) >> 6; v != 2 {
				t.Errorf("newServerEndpointID() variant = %d, want 2", v)
			}
		})
	}
}

func Test_newStepIssuer(t *testing.T) {
	caURL, client := testCAHelper(t)
	signer, err := newJWKSignerFromEncryptedKey(testKeyID, testEncryptedJWKKey, testPassword)
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		caURL  *url.URL
		client *ca.Client
		iss    *apiv1.CertificateIssuer
	}
	tests := []struct {
		name    string
		args    args
		want    stepIssuer
		wantErr bool
	}{
		{"x5c", args{caURL, client, &apiv1.CertificateIssuer{
			Type:        "x5c",
			Provisioner: "X5C",
			Certificate: testX5CPath,
			Key:         testX5CKeyPath,
		}}, &x5cIssuer{
			caURL:    caURL,
			certFile: testX5CPath,
			keyFile:  testX5CKeyPath,
			issuer:   "X5C",
		}, false},
		{"jwk", args{caURL, client, &apiv1.CertificateIssuer{
			Type:        "jwk",
			Provisioner: "ra@doe.org",
			Key:         testX5CKeyPath,
		}}, &jwkIssuer{
			caURL:  caURL,
			issuer: "ra@doe.org",
			signer: signer,
		}, false},
		{"fail", args{caURL, client, &apiv1.CertificateIssuer{
			Type:        "unknown",
			Provisioner: "ra@doe.org",
			Key:         testX5CKeyPath,
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newStepIssuer(context.TODO(), tt.args.caURL, tt.args.client, tt.args.iss)
			if (err != nil) != tt.wantErr {
				t.Errorf("newStepIssuer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.args.iss.Type == "jwk" && got != nil && tt.want != nil {
				got.(*jwkIssuer).signer = tt.want.(*jwkIssuer).signer
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newStepIssuer() = %v, want %v", got, tt.want)
			}
		})
	}
}
