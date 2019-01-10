package authority

import (
	"crypto/x509"
	"net/http"
	"reflect"
	"testing"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/cli/crypto/keys"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/crypto/x509util"
)

func TestRoot(t *testing.T) {
	a := testAuthority(t)
	a.certificates.Store("invaliddata", "a string") // invalid cert for testing

	tests := map[string]struct {
		sum string
		err *apiError
	}{
		"not-found":                  {"foo", &apiError{errors.New("certificate with fingerprint foo was not found"), http.StatusNotFound, context{}}},
		"invalid-stored-certificate": {"invaliddata", &apiError{errors.New("stored value is not a *x509.Certificate"), http.StatusInternalServerError, context{}}},
		"success":                    {"189f573cfa159251e445530847ef80b1b62a3a380ee670dcb49e33ed34da0616", nil},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			crt, err := a.Root(tc.sum)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					switch v := err.(type) {
					case *apiError:
						assert.HasPrefix(t, v.err.Error(), tc.err.Error())
						assert.Equals(t, v.code, tc.err.code)
						assert.Equals(t, v.context, tc.err.context)
					default:
						t.Errorf("unexpected error type: %T", v)
					}
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, crt, a.rootX509Certs[0])
				}
			}
		})
	}
}

func TestAuthority_GetRootCertificate(t *testing.T) {
	cert, err := pemutil.ReadCertificate("testdata/secrets/root_ca.crt")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		want *x509.Certificate
	}{
		{"ok", cert},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := testAuthority(t)
			if got := a.GetRootCertificate(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Authority.GetRootCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthority_GetRootCertificates(t *testing.T) {
	cert, err := pemutil.ReadCertificate("testdata/secrets/root_ca.crt")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		want []*x509.Certificate
	}{
		{"ok", []*x509.Certificate{cert}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := testAuthority(t)
			if got := a.GetRootCertificates(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Authority.GetRootCertificates() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthority_GetRoots(t *testing.T) {
	cert, err := pemutil.ReadCertificate("testdata/secrets/root_ca.crt")
	if err != nil {
		t.Fatal(err)
	}

	a := testAuthority(t)
	pub, _, err := keys.GenerateDefaultKeyPair()
	assert.FatalError(t, err)
	leaf, err := x509util.NewLeafProfile("test", a.intermediateIdentity.Crt, a.intermediateIdentity.Key,
		withDefaultASN1DN(a.config.AuthorityConfig.Template), x509util.WithPublicKey(pub), x509util.WithHosts("test"))
	assert.FatalError(t, err)
	crtBytes, err := leaf.CreateCertificate()
	assert.FatalError(t, err)
	crt, err := x509.ParseCertificate(crtBytes)
	assert.FatalError(t, err)

	leafFail, err := x509util.NewLeafProfile("test", a.intermediateIdentity.Crt, a.intermediateIdentity.Key,
		withDefaultASN1DN(a.config.AuthorityConfig.Template), x509util.WithPublicKey(pub), x509util.WithHosts("test"),
		withProvisionerOID("dev", a.config.AuthorityConfig.Provisioners[2].Key.KeyID),
	)
	assert.FatalError(t, err)
	crtFailBytes, err := leafFail.CreateCertificate()
	assert.FatalError(t, err)
	crtFail, err := x509.ParseCertificate(crtFailBytes)
	assert.FatalError(t, err)

	type args struct {
		peer *x509.Certificate
	}
	tests := []struct {
		name    string
		args    args
		want    []*x509.Certificate
		wantErr bool
	}{
		{"ok", args{crt}, []*x509.Certificate{cert}, false},
		{"fail", args{crtFail}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := a.GetRoots(tt.args.peer)
			if (err != nil) != tt.wantErr {
				t.Errorf("Authority.GetRoots() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Authority.GetRoots() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthority_GetFederation(t *testing.T) {
	cert, err := pemutil.ReadCertificate("testdata/secrets/root_ca.crt")
	if err != nil {
		t.Fatal(err)
	}

	a := testAuthority(t)
	pub, _, err := keys.GenerateDefaultKeyPair()
	assert.FatalError(t, err)
	leaf, err := x509util.NewLeafProfile("test", a.intermediateIdentity.Crt, a.intermediateIdentity.Key,
		withDefaultASN1DN(a.config.AuthorityConfig.Template), x509util.WithPublicKey(pub), x509util.WithHosts("test"))
	assert.FatalError(t, err)
	crtBytes, err := leaf.CreateCertificate()
	assert.FatalError(t, err)
	crt, err := x509.ParseCertificate(crtBytes)
	assert.FatalError(t, err)

	leafFail, err := x509util.NewLeafProfile("test", a.intermediateIdentity.Crt, a.intermediateIdentity.Key,
		withDefaultASN1DN(a.config.AuthorityConfig.Template), x509util.WithPublicKey(pub), x509util.WithHosts("test"),
		withProvisionerOID("dev", a.config.AuthorityConfig.Provisioners[2].Key.KeyID),
	)
	assert.FatalError(t, err)
	crtFailBytes, err := leafFail.CreateCertificate()
	assert.FatalError(t, err)
	crtFail, err := x509.ParseCertificate(crtFailBytes)
	assert.FatalError(t, err)

	type args struct {
		peer *x509.Certificate
	}
	tests := []struct {
		name           string
		args           args
		wantFederation []*x509.Certificate
		wantErr        bool
		fn             func()
	}{
		{"ok", args{crt}, []*x509.Certificate{cert}, false, nil},
		{"fail", args{crtFail}, nil, true, nil},
		{"fail not a certificate", args{crt}, nil, true, func() {
			a.certificates.Store("foo", "bar")
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.fn != nil {
				tt.fn()
			}
			gotFederation, err := a.GetFederation(tt.args.peer)
			if (err != nil) != tt.wantErr {
				t.Errorf("Authority.GetFederation() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotFederation, tt.wantFederation) {
				t.Errorf("Authority.GetFederation() = %v, want %v", gotFederation, tt.wantFederation)
			}
		})
	}
}
