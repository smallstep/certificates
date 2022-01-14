package vaultcas

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	vault "github.com/hashicorp/vault/api"
	"github.com/smallstep/certificates/cas/apiv1"
)

var (
	testCertificateSigned = `-----BEGIN CERTIFICATE-----
MIIB/DCCAaKgAwIBAgIQHHFuGMz0cClfde5kqP5prTAKBggqhkjOPQQDAjAqMSgw
JgYDVQQDEx9Hb29nbGUgQ0FTIFRlc3QgSW50ZXJtZWRpYXRlIENBMB4XDTIwMDkx
NTAwMDQ0M1oXDTMwMDkxMzAwMDQ0MFowHTEbMBkGA1UEAxMSdGVzdC5zbWFsbHN0
ZXAuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMqNCiXMvbn74LsHzRv+8
17m9vEzH6RHrg3m82e0uEc36+fZWV/zJ9SKuONmnl5VP79LsjL5SVH0RDj73U2XO
DKOBtjCBszAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsG
AQUFBwMCMB0GA1UdDgQWBBRTA2cTs7PCNjnps/+T0dS8diqv0DAfBgNVHSMEGDAW
gBRIOVqyLDSlErJLuWWEvRm5UU1r1TBCBgwrBgEEAYKkZMYoQAIEMjAwEwhjbG91
ZGNhcxMkZDhkMThhNjgtNTI5Ni00YWYzLWFlNGItMmY4NzdkYTNmYmQ5MAoGCCqG
SM49BAMCA0gAMEUCIGxl+pqJ50WYWUqK2l4V1FHoXSi0Nht5kwTxFxnWZu1xAiEA
zemu3bhWLFaGg3s8i+HTEhw4RqkHP74vF7AVYp88bAw=
-----END CERTIFICATE-----`
	testCertificateCsrEc = `-----BEGIN CERTIFICATE REQUEST-----
MIHoMIGPAgEAMA0xCzAJBgNVBAMTAkVDMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD
QgAEUVVVZGD6eUrB20T/qrjKZoYzseQ18AIm9jtUNpQn5hIClpdk2zKy5bja3iUa
nmqRKCIz/B/MU55zuNDeckqqX6AgMB4GCSqGSIb3DQEJDjERMA8wDQYDVR0RBAYw
BIICRUMwCgYIKoZIzj0EAwIDSAAwRQIhAJxpWyH7cctbzcnK1JBWDAmc/G61bq9y
otHrQDfYvS8bAiBVGQz2cfO2SqhvkkQbOqWUFjk1wHzISvlTjyc3IJ7FLw==
-----END CERTIFICATE REQUEST-----`
	testCertificateCsrRsa = `-----BEGIN CERTIFICATE REQUEST-----
MIICdDCCAVwCAQAwDjEMMAoGA1UEAxMDUlNBMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAxe5XLSZrTCzzH0FJCXvZwghAY5XztzjseSRcm0jL8Q7nvNWi
Vpu1n7EmfVU9b8sbvtVYqMQV+hMdj2C/NIw4Yal4Wg+BgunYOrRqfY7oDm4csG0R
g5v0h2yQw14kqVrftNyojX0Nv/CPboCGl64PA9zsEXQTB3Y1AUWrUGPiBWNACYIH
mjv70Ay9JKBBAqov38I7nka/RgYAl5DCHzU2vvODriBYFWagnzycA4Ni5EKTz93W
SPdDEhkWi3ugUqal3SvgHl8re+8d7ghLn85Y3TFuyU2nSMDPHaymsiNFw1mRwOw3
lAseidHJkPQs7q6FiYXaeqetf1j/gw0n23ZogwIDAQABoCEwHwYJKoZIhvcNAQkO
MRIwEDAOBgNVHREEBzAFggNSU0EwDQYJKoZIhvcNAQELBQADggEBALnO5vcDkgGO
GQoSINa2NmNFxAtYQGYHok5KXYX+S+etmOmDrmrhsl/pSjN3GPCPlThFlbLStB70
oJw67nEjGf0hPEBVlm+qFUsYQ1KGRZFAWDSMQ//pU225XFDCmlzHfV7gZjSkP9GN
Gc5VECOzx6hAFR+IEL/l/1GG5HHkPPrr/8OvuIfm2V5ofYmhsXMVVYH52qPofMAV
B8UdNnZK3nyLdUqVd+PYUUJmN4bJ8YfxofKKgbLkhvkKp4OZ9vkwUi2+61NdHTf2
wIauOyxEoTlJpU6oA/sxu/2Ht2DP+8y6mognLBuKklE/VH3/2iqQWyg1NV5hyg3b
loVSdLsIh5Y=
-----END CERTIFICATE REQUEST-----`
	testCertificateCsrEd25519 = `-----BEGIN CERTIFICATE REQUEST-----
MIGuMGICAQAwDjEMMAoGA1UEAxMDT0tQMCowBQYDK2VwAyEAopc6daK4zYR6BDAM
pV/v53oR/ewbtrkHZQkN/amFMLagITAfBgkqhkiG9w0BCQ4xEjAQMA4GA1UdEQQH
MAWCA09LUDAFBgMrZXADQQDJi47MAgl/WKAz+V/kDu1k/zbKk1nrHHAUonbofHUW
M6ihSD43+awq3BPeyPbToeH5orSH9l3MuTfbxPb5BVEH
-----END CERTIFICATE REQUEST-----`
	testRootFingerprint = `e7678acf0d8de731262bce2fe792c48f19547285f5976805125a40867c77464e`
)

func mustParseCertificate(t *testing.T, pemCert string) *x509.Certificate {
	t.Helper()
	crt, err := parseCertificate(pemCert)
	if err != nil {
		t.Fatal(err)
	}
	return crt
}

func mustParseCertificateRequest(t *testing.T, pemCert string) *x509.CertificateRequest {
	t.Helper()
	crt, err := parseCertificateRequest(pemCert)
	if err != nil {
		t.Fatal(err)
	}
	return crt
}

func testCAHelper(t *testing.T) (*url.URL, *vault.Client) {
	t.Helper()

	writeJSON := func(w http.ResponseWriter, v interface{}) {
		_ = json.NewEncoder(w).Encode(v)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.RequestURI == "/v1/auth/auth/approle/login":
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{
				  "auth": {
					"client_token": "98a4c7ab-b1fe-361b-ba0b-e307aacfd587"
				  }
				}`)
		case r.RequestURI == "/v1/pki/sign/ec":
			w.WriteHeader(http.StatusOK)
			cert := map[string]interface{}{"data": map[string]interface{}{"certificate": testCertificateSigned}}
			writeJSON(w, cert)
			return
		case r.RequestURI == "/v1/pki/sign/rsa":
			w.WriteHeader(http.StatusOK)
			cert := map[string]interface{}{"data": map[string]interface{}{"certificate": testCertificateSigned}}
			writeJSON(w, cert)
			return
		case r.RequestURI == "/v1/pki/sign/ed25519":
			w.WriteHeader(http.StatusOK)
			cert := map[string]interface{}{"data": map[string]interface{}{"certificate": testCertificateSigned}}
			writeJSON(w, cert)
			return
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, `{"error":"not found"}`)
		}
	}))
	t.Cleanup(func() {
		srv.Close()
	})
	u, err := url.Parse(srv.URL)
	if err != nil {
		srv.Close()
		t.Fatal(err)
	}

	config := vault.DefaultConfig()
	config.Address = srv.URL

	client, err := vault.NewClient(config)
	if err != nil {
		srv.Close()
		t.Fatal(err)
	}

	return u, client
}

func TestNew_register(t *testing.T) {
	caURL, _ := testCAHelper(t)

	fn, ok := apiv1.LoadCertificateAuthorityServiceNewFunc(apiv1.VaultCAS)
	if !ok {
		t.Errorf("apiv1.Register() ok = %v, want true", ok)
		return
	}
	_, err := fn(context.Background(), apiv1.Options{
		CertificateAuthority:            caURL.String(),
		CertificateAuthorityFingerprint: testRootFingerprint,
		Config: map[string]interface{}{
			"PKI":             "pki",
			"PKIRole":         "pki-role",
			"RoleID":          "roleID",
			"SecretID":        "secretID",
			"IsWrappingToken": false,
		},
	})

	if err != nil {
		t.Errorf("New() error = %v", err)
		return
	}
}

func TestVaultCAS_CreateCertificate(t *testing.T) {
	_, client := testCAHelper(t)

	options := VaultOptions{
		PKI:             "pki",
		PKIRole:         "role",
		PKIRoleRSA:      "rsa",
		PKIRoleEC:       "ec",
		PKIRoleED25519:  "ed25519",
		RoleID:          "roleID",
		SecretID:        "secretID",
		AppRole:         "approle",
		IsWrappingToken: false,
	}

	type fields struct {
		client  *vault.Client
		options VaultOptions
	}

	type args struct {
		req *apiv1.CreateCertificateRequest
	}

	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *apiv1.CreateCertificateResponse
		wantErr bool
	}{
		{"ok ec", fields{client, options}, args{&apiv1.CreateCertificateRequest{
			CSR:      mustParseCertificateRequest(t, testCertificateCsrEc),
			Lifetime: time.Hour,
		}}, &apiv1.CreateCertificateResponse{
			Certificate:      mustParseCertificate(t, testCertificateSigned),
			CertificateChain: []*x509.Certificate{},
		}, false},
		{"ok rsa", fields{client, options}, args{&apiv1.CreateCertificateRequest{
			CSR:      mustParseCertificateRequest(t, testCertificateCsrRsa),
			Lifetime: time.Hour,
		}}, &apiv1.CreateCertificateResponse{
			Certificate:      mustParseCertificate(t, testCertificateSigned),
			CertificateChain: []*x509.Certificate{},
		}, false},
		{"ok ed25519", fields{client, options}, args{&apiv1.CreateCertificateRequest{
			CSR:      mustParseCertificateRequest(t, testCertificateCsrEd25519),
			Lifetime: time.Hour,
		}}, &apiv1.CreateCertificateResponse{
			Certificate:      mustParseCertificate(t, testCertificateSigned),
			CertificateChain: []*x509.Certificate{},
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &VaultCAS{
				client: tt.fields.client,
				config: tt.fields.options,
			}
			got, err := c.CreateCertificate(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("VaultCAS.CreateCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("VaultCAS.CreateCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}
