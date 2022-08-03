package stepcas

import (
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/cas/apiv1"
	"go.step.sm/crypto/jose"
)

type mockErrIssuer struct{}

func (m mockErrIssuer) SignToken(subject string, sans []string, info *raInfo) (string, error) {
	return "", apiv1.ErrNotImplemented{}
}

func (m mockErrIssuer) RevokeToken(subject string) (string, error) {
	return "", apiv1.ErrNotImplemented{}
}

func (m mockErrIssuer) Lifetime(d time.Duration) time.Duration {
	return d
}

type mockErrSigner struct{}

func (s *mockErrSigner) Sign(payload []byte) (*jose.JSONWebSignature, error) {
	return nil, apiv1.ErrNotImplemented{}
}

func (s *mockErrSigner) Options() jose.SignerOptions {
	return jose.SignerOptions{}
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
			got, err := newStepIssuer(tt.args.caURL, tt.args.client, tt.args.iss)
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
