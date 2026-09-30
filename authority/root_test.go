package authority

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"testing"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/api/render"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/minica"
	"go.step.sm/crypto/pemutil"
)

func TestRoot(t *testing.T) {
	a := testAuthority(t)
	a.certificates.Store("invaliddata", "a string") // invalid cert for testing

	tests := map[string]struct {
		sum  string
		err  error
		code int
	}{
		"not-found":                  {"foo", errors.New("certificate with fingerprint foo was not found"), http.StatusNotFound},
		"invalid-stored-certificate": {"invaliddata", errors.New("stored value is not a *x509.Certificate"), http.StatusInternalServerError},
		"success":                    {"189f573cfa159251e445530847ef80b1b62a3a380ee670dcb49e33ed34da0616", nil, http.StatusOK},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			crt, err := a.Root(tc.sum)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					var sc render.StatusCodedError
					assert.Fatal(t, errors.As(err, &sc), "error does not implement StatusCodedError interface")
					assert.Equals(t, sc.StatusCode(), tc.code)
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, crt, a.rootX509Certs[0])
				}
			}
		})
	}
}

func TestAuthority_Intermediate(t *testing.T) {
	ca, err := minica.New()
	require.NoError(t, err)

	// Create a second intermediate certificate for multi-cert testing.
	signer, err := keyutil.GenerateDefaultSigner()
	require.NoError(t, err)
	secondIntermediate, err := ca.Sign(&x509.Certificate{
		Subject:               pkix.Name{CommonName: "Second Intermediate CA"},
		PublicKey:             signer.Public(),
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	})
	require.NoError(t, err)

	// Pre-compute fingerprints.
	firstFP := fmt.Sprintf("%x", sha256.Sum256(ca.Intermediate.Raw))
	secondFP := fmt.Sprintf("%x", sha256.Sum256(secondIntermediate.Raw))

	tests := []struct {
		name          string
		intermediates []*x509.Certificate
		sum           string
		want          *x509.Certificate
		wantErr       bool
		errCode       int
	}{
		{
			name:          "found",
			intermediates: []*x509.Certificate{ca.Intermediate},
			sum:           firstFP,
			want:          ca.Intermediate,
		},
		{
			name:          "not found",
			intermediates: []*x509.Certificate{ca.Intermediate},
			sum:           "0000000000000000000000000000000000000000000000000000000000000000",
			wantErr:       true,
			errCode:       http.StatusNotFound,
		},
		{
			name:          "empty list",
			intermediates: []*x509.Certificate{},
			sum:           firstFP,
			wantErr:       true,
			errCode:       http.StatusNotFound,
		},
		{
			name:          "multiple intermediates - select first",
			intermediates: []*x509.Certificate{ca.Intermediate, secondIntermediate},
			sum:           firstFP,
			want:          ca.Intermediate,
		},
		{
			name:          "multiple intermediates - select second",
			intermediates: []*x509.Certificate{ca.Intermediate, secondIntermediate},
			sum:           secondFP,
			want:          secondIntermediate,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Authority{
				intermediateX509Certs: tt.intermediates,
			}
			got, err := a.Intermediate(tt.sum)
			if tt.wantErr {
				require.Error(t, err)
				var sc render.StatusCodedError
				require.ErrorAs(t, err, &sc)
				require.Equal(t, tt.errCode, sc.StatusCode())
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.want, got)
			}
		})
	}
}

func TestAuthority_GetRootCertificate(t *testing.T) {
	cert, err := pemutil.ReadCertificate("testdata/certs/root_ca.crt")
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
	cert, err := pemutil.ReadCertificate("testdata/certs/root_ca.crt")
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
	cert, err := pemutil.ReadCertificate("testdata/certs/root_ca.crt")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		want    []*x509.Certificate
		wantErr bool
	}{
		{"ok", []*x509.Certificate{cert}, false},
	}
	for _, tt := range tests {
		a := testAuthority(t)
		t.Run(tt.name, func(t *testing.T) {
			got, err := a.GetRoots()
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
	cert, err := pemutil.ReadCertificate("testdata/certs/root_ca.crt")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name           string
		wantFederation []*x509.Certificate
		wantErr        bool
		fn             func(a *Authority)
	}{
		{"ok", []*x509.Certificate{cert}, false, nil},
		{"fail", nil, true, func(a *Authority) {
			a.certificates.Store("foo", "bar")
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := testAuthority(t)
			if tt.fn != nil {
				tt.fn(a)
			}
			gotFederation, err := a.GetFederation()
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

func TestAuthority_GetIntermediateCertificate(t *testing.T) {
	ca, err := minica.New(minica.WithRootTemplate(`{
		"subject": {{ toJson .Subject }},
		"issuer": {{ toJson .Subject }},
		"keyUsage": ["certSign", "crlSign"],
		"basicConstraints": {
			"isCA": true,
			"maxPathLen": -1
		}
	}`), minica.WithIntermediateTemplate(`{
		"subject": {{ toJson .Subject }},
		"keyUsage": ["certSign", "crlSign"],
		"basicConstraints": {
			"isCA": true,
			"maxPathLen": 1
		}
	}`))
	require.NoError(t, err)

	signer, err := keyutil.GenerateDefaultSigner()
	require.NoError(t, err)

	cert, err := ca.Sign(&x509.Certificate{
		Subject:               pkix.Name{CommonName: "MiniCA Intermediate CA 0"},
		PublicKey:             signer.Public(),
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	})
	require.NoError(t, err)

	type fields struct {
		intermediateX509Certs []*x509.Certificate
	}
	tests := []struct {
		name      string
		fields    fields
		want      *x509.Certificate
		wantSlice []*x509.Certificate
	}{
		{"ok one", fields{[]*x509.Certificate{ca.Intermediate}}, ca.Intermediate, []*x509.Certificate{ca.Intermediate}},
		{"ok multiple", fields{[]*x509.Certificate{cert, ca.Intermediate}}, cert, []*x509.Certificate{cert, ca.Intermediate}},
		{"ok empty", fields{[]*x509.Certificate{}}, nil, []*x509.Certificate{}},
		{"ok nil", fields{nil}, nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Authority{
				intermediateX509Certs: tt.fields.intermediateX509Certs,
			}
			if got := a.GetIntermediateCertificate(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Authority.GetIntermediateCertificate() = %v, want %v", got, tt.want)
			}
			if got := a.GetIntermediateCertificates(); !reflect.DeepEqual(got, tt.wantSlice) {
				t.Errorf("Authority.GetIntermediateCertificates() = %v, want %v", got, tt.wantSlice)
			}
		})
	}
}
