package ca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	"go.step.sm/crypto/x509util"
	"golang.org/x/crypto/ssh"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/api/read"
	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/errs"
)

const (
	rootPEM = `-----BEGIN CERTIFICATE-----
MIIEBDCCAuygAwIBAgIDAjppMA0GCSqGSIb3DQEBBQUAMEIxCzAJBgNVBAYTAlVT
MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i
YWwgQ0EwHhcNMTMwNDA1MTUxNTU1WhcNMTUwNDA0MTUxNTU1WjBJMQswCQYDVQQG
EwJVUzETMBEGA1UEChMKR29vZ2xlIEluYzElMCMGA1UEAxMcR29vZ2xlIEludGVy
bmV0IEF1dGhvcml0eSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AJwqBHdc2FCROgajguDYUEi8iT/xGXAaiEZ+4I/F8YnOIe5a/mENtzJEiaB0C1NP
VaTOgmKV7utZX8bhBYASxF6UP7xbSDj0U/ck5vuR6RXEz/RTDfRK/J9U3n2+oGtv
h8DQUB8oMANA2ghzUWx//zo8pzcGjr1LEQTrfSTe5vn8MXH7lNVg8y5Kr0LSy+rE
ahqyzFPdFUuLH8gZYR/Nnag+YyuENWllhMgZxUYi+FOVvuOAShDGKuy6lyARxzmZ
EASg8GF6lSWMTlJ14rbtCMoU/M4iarNOz0YDl5cDfsCx3nuvRTPPuj5xt970JSXC
DTWJnZ37DhF5iR43xa+OcmkCAwEAAaOB+zCB+DAfBgNVHSMEGDAWgBTAephojYn7
qwVkDBF9qn1luMrMTjAdBgNVHQ4EFgQUSt0GFhu89mi1dvWBtrtiGrpagS8wEgYD
VR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwOgYDVR0fBDMwMTAvoC2g
K4YpaHR0cDovL2NybC5nZW90cnVzdC5jb20vY3Jscy9ndGdsb2JhbC5jcmwwPQYI
KwYBBQUHAQEEMTAvMC0GCCsGAQUFBzABhiFodHRwOi8vZ3RnbG9iYWwtb2NzcC5n
ZW90cnVzdC5jb20wFwYDVR0gBBAwDjAMBgorBgEEAdZ5AgUBMA0GCSqGSIb3DQEB
BQUAA4IBAQA21waAESetKhSbOHezI6B1WLuxfoNCunLaHtiONgaX4PCVOzf9G0JY
/iLIa704XtE7JW4S615ndkZAkNoUyHgN7ZVm2o6Gb4ChulYylYbc3GrKBIxbf/a/
zG+FA1jDaFETzf3I93k9mTXwVqO94FntT0QJo544evZG0R0SnU++0ED8Vf4GXjza
HFa9llF7b1cq26KqltyMdMKVvvBulRP/F/A8rLIQjcxz++iPAsbw+zOzlTvjwsto
WHPbqCRiOwY1nQ2pM714A5AuTHhdUDqB1O6gyHA43LL5Z/qHQF1hwFGPa4NrzQU6
yuGnBXj8ytqU0CwIPX4WecigUCAkVDNx
-----END CERTIFICATE-----`

	certPEM = `-----BEGIN CERTIFICATE-----
MIIDujCCAqKgAwIBAgIIE31FZVaPXTUwDQYJKoZIhvcNAQEFBQAwSTELMAkGA1UE
BhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMxJTAjBgNVBAMTHEdvb2dsZSBJbnRl
cm5ldCBBdXRob3JpdHkgRzIwHhcNMTQwMTI5MTMyNzQzWhcNMTQwNTI5MDAwMDAw
WjBpMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwN
TW91bnRhaW4gVmlldzETMBEGA1UECgwKR29vZ2xlIEluYzEYMBYGA1UEAwwPbWFp
bC5nb29nbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfRrObuSW5T7q
5CnSEqefEmtH4CCv6+5EckuriNr1CjfVvqzwfAhopXkLrq45EQm8vkmf7W96XJhC
7ZM0dYi1/qOCAU8wggFLMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAa
BgNVHREEEzARgg9tYWlsLmdvb2dsZS5jb20wCwYDVR0PBAQDAgeAMGgGCCsGAQUF
BwEBBFwwWjArBggrBgEFBQcwAoYfaHR0cDovL3BraS5nb29nbGUuY29tL0dJQUcy
LmNydDArBggrBgEFBQcwAYYfaHR0cDovL2NsaWVudHMxLmdvb2dsZS5jb20vb2Nz
cDAdBgNVHQ4EFgQUiJxtimAuTfwb+aUtBn5UYKreKvMwDAYDVR0TAQH/BAIwADAf
BgNVHSMEGDAWgBRK3QYWG7z2aLV29YG2u2IaulqBLzAXBgNVHSAEEDAOMAwGCisG
AQQB1nkCBQEwMAYDVR0fBCkwJzAloCOgIYYfaHR0cDovL3BraS5nb29nbGUuY29t
L0dJQUcyLmNybDANBgkqhkiG9w0BAQUFAAOCAQEAH6RYHxHdcGpMpFE3oxDoFnP+
gtuBCHan2yE2GRbJ2Cw8Lw0MmuKqHlf9RSeYfd3BXeKkj1qO6TVKwCh+0HdZk283
TZZyzmEOyclm3UGFYe82P/iDFt+CeQ3NpmBg+GoaVCuWAARJN/KfglbLyyYygcQq
0SgeDh8dRKUiaW3HQSoYvTvdTuqzwK4CXsr3b5/dAOY8uMuG/IAR3FgwTbZ1dtoW
RvOTa8hYiU6A475WuZKyEHcwnGYe57u2I2KbMgcKjPniocj4QzgYsVAVKW3IwaOh
yE+vPxsiUkvQHdO2fojCkY8jg70jxM+gu59tPDNbw3Uh/2Ij310FgTHsnGQMyA==
-----END CERTIFICATE-----`

	csrPEM = `-----BEGIN CERTIFICATE REQUEST-----
MIIEYjCCAkoCAQAwHTEbMBkGA1UEAxMSdGVzdC5zbWFsbHN0ZXAuY29tMIICIjAN
BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAuCpifZfoZhYNywfpnPa21NezXgtn
wrWBFE6xhVzE7YDSIqtIsj8aR7R8zwEymxfv5j5298LUy/XSmItVH31CsKyfcGqN
QM0PZr9XY3z5V6qchGMqjzt/jqlYMBHujcxIFBfz4HATxSgKyvHqvw14ESsS2huu
7jowx+XTKbFYgKcXrjBkvOej5FXD3ehkg0jDA2UAJNdfKmrc1BBEaaqOtfh7eyU2
HU7+5gxH8C27IiCAmNj719E0B99Nu2MUw6aLFIM4xAcRga33Avevx6UuXZZIEepe
V1sihrkcnDK9Vsxkme5erXzvAoOiRusiC2iIomJHJrdRM5ReEU+N+Tl1Kxq+rk7H
/qAq78wVm07M1/GGi9SUMObZS4WuJpM6whlikIAEbv9iV+CK0sv/Jr/AADdGMmQU
lwk+Q0ZNE8p4ZuWILv/dtLDtDVBpnrrJ9e8duBtB0lGcG8MdaUCQ346EI4T0Sgx0
hJ+wMq8zYYFfPIZEHC8o9p1ywWN9ySpJ8Zj/5ubmx9v2bY67GbuVFEa8iAp+S00x
/Z8nD6/JsoKtexuHyGr3ixWFzlBqXDuugukIDFUOVDCbuGw4Io4/hEMu4Zz0TIFk
Uu/wf2z75Tt8EkosKLu2wieKcY7n7Vhog/0tqexqWlWtJH0tvq4djsGoSvA62WPs
0iXXj+aZIARPNhECAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4ICAQA0vyHIndAkIs/I
Nnz5yZWCokRjokoKv3Aj4VilyjncL+W0UIPULLU/47ZyoHVSUj2t8gknr9xu/Kd+
g/2z0RiF3CIp8IUH49w/HYWaR95glzVNAAzr8qD9UbUqloLVQW3lObSRGtezhdZO
sspw5dC+inhAb1LZhx8PVxB3SAeJ8h11IEBr0s2Hxt9viKKd7YPtIFZkZdOkVx4R
if1DMawj1P6fEomf8z7m+dmbUYTqqosbCbRL01mzEga/kF6JyH/OzpNlcsAiyM8e
BxPWH6TtPqwmyy4y7j1outmM0RnyUw5A0HmIbWh+rHpXiHVsnNqse0XfzmaxM8+z
dxYeDax8aMWZKfvY1Zew+xIxl7DtEy1BpxrZcawumJYt5+LL+bwF/OtL0inQLnw8
zyqydsXNdrpIQJnfmWPld7ThWbQw2FBE70+nFSxHeG2ULnpF3M9xf6ZNAF4gqaNE
Q7vMNPBWrJWu+A++vHY61WGET+h4lY3GFr2I8OE4IiHPQi1D7Y0+fwOmStwuRPM4
2rARcJChNdiYBkkuvs4kixKTTjdXhB8RQtuBSrJ0M1tzq2qMbm7F8G01rOg4KlXU
58jHzJwr1K7cx0lpWfGTtc5bseCGtTKmDBXTziw04yl8eE1+ZFOganixGwCtl4Tt
DCbKzWTW8lqVdp9Kyf7XEhhc2R8C5w==
-----END CERTIFICATE REQUEST-----`
)

func mustKey() *ecdsa.PrivateKey {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return priv
}

func parseCertificate(data string) *x509.Certificate {
	block, _ := pem.Decode([]byte(data))
	if block == nil {
		panic("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}
	return cert
}

func parseCertificateRequest(data string) *x509.CertificateRequest {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		panic("failed to parse certificate request PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		panic("failed to parse certificate request: " + err.Error())
	}
	return csr
}

func equalJSON(t *testing.T, a, b interface{}) bool {
	if reflect.DeepEqual(a, b) {
		return true
	}
	ab, err := json.Marshal(a)
	if err != nil {
		t.Error(err)
		return false
	}
	bb, err := json.Marshal(b)
	if err != nil {
		t.Error(err)
		return false
	}
	return bytes.Equal(ab, bb)
}

func TestClient_Version(t *testing.T) {
	ok := &api.VersionResponse{Version: "test"}

	tests := []struct {
		name         string
		response     interface{}
		responseCode int
		wantErr      bool
		expectedErr  error
	}{
		{"ok", ok, 200, false, nil},
		{"500", errs.InternalServer("force"), 500, true, errors.New(errs.InternalServerErrorDefaultMsg)},
		{"404", errs.NotFound("force"), 404, true, errors.New(errs.NotFoundDefaultMsg)},
	}

	srv := httptest.NewServer(nil)
	defer srv.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(srv.URL, WithTransport(http.DefaultTransport))
			if err != nil {
				t.Errorf("NewClient() error = %v", err)
				return
			}

			srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				render.JSONStatus(w, tt.response, tt.responseCode)
			})

			got, err := c.Version()
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.Version() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			switch {
			case err != nil:
				if got != nil {
					t.Errorf("Client.Version() = %v, want nil", got)
				}
				assert.HasPrefix(t, tt.expectedErr.Error(), err.Error())
			default:
				if !reflect.DeepEqual(got, tt.response) {
					t.Errorf("Client.Version() = %v, want %v", got, tt.response)
				}
			}
		})
	}
}

func TestClient_Health(t *testing.T) {
	ok := &api.HealthResponse{Status: "ok"}

	tests := []struct {
		name         string
		response     interface{}
		responseCode int
		wantErr      bool
		expectedErr  error
	}{
		{"ok", ok, 200, false, nil},
		{"not ok", errs.InternalServer("force"), 500, true, errors.New(errs.InternalServerErrorDefaultMsg)},
	}

	srv := httptest.NewServer(nil)
	defer srv.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(srv.URL, WithTransport(http.DefaultTransport))
			if err != nil {
				t.Errorf("NewClient() error = %v", err)
				return
			}

			srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				render.JSONStatus(w, tt.response, tt.responseCode)
			})

			got, err := c.Health()
			if (err != nil) != tt.wantErr {
				fmt.Printf("%+v", err)
				t.Errorf("Client.Health() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			switch {
			case err != nil:
				if got != nil {
					t.Errorf("Client.Health() = %v, want nil", got)
				}
				assert.HasPrefix(t, tt.expectedErr.Error(), err.Error())
			default:
				if !reflect.DeepEqual(got, tt.response) {
					t.Errorf("Client.Health() = %v, want %v", got, tt.response)
				}
			}
		})
	}
}

func TestClient_Root(t *testing.T) {
	ok := &api.RootResponse{
		RootPEM: api.Certificate{Certificate: parseCertificate(rootPEM)},
	}

	tests := []struct {
		name         string
		shasum       string
		response     interface{}
		responseCode int
		wantErr      bool
		expectedErr  error
	}{
		{"ok", "a047a37fa2d2e118a4f5095fe074d6cfe0e352425a7632bf8659c03919a6c81d", ok, 200, false, nil},
		{"not found", "invalid", errs.NotFound("force"), 404, true, errors.New(errs.NotFoundDefaultMsg)},
	}

	srv := httptest.NewServer(nil)
	defer srv.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(srv.URL, WithTransport(http.DefaultTransport))
			if err != nil {
				t.Errorf("NewClient() error = %v", err)
				return
			}

			srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				expected := "/root/" + tt.shasum
				if req.RequestURI != expected {
					t.Errorf("RequestURI = %s, want %s", req.RequestURI, expected)
				}
				render.JSONStatus(w, tt.response, tt.responseCode)
			})

			got, err := c.Root(tt.shasum)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.Root() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			switch {
			case err != nil:
				if got != nil {
					t.Errorf("Client.Root() = %v, want nil", got)
				}
				assert.HasPrefix(t, tt.expectedErr.Error(), err.Error())
			default:
				if !reflect.DeepEqual(got, tt.response) {
					t.Errorf("Client.Root() = %v, want %v", got, tt.response)
				}
			}
		})
	}
}

func TestClient_Sign(t *testing.T) {
	ok := &api.SignResponse{
		ServerPEM: api.Certificate{Certificate: parseCertificate(certPEM)},
		CaPEM:     api.Certificate{Certificate: parseCertificate(rootPEM)},
		CertChainPEM: []api.Certificate{
			{Certificate: parseCertificate(certPEM)},
			{Certificate: parseCertificate(rootPEM)},
		},
	}
	request := &api.SignRequest{
		CsrPEM:    api.CertificateRequest{CertificateRequest: parseCertificateRequest(csrPEM)},
		OTT:       "the-ott",
		NotBefore: api.NewTimeDuration(time.Now()),
		NotAfter:  api.NewTimeDuration(time.Now().AddDate(0, 1, 0)),
	}

	tests := []struct {
		name         string
		request      *api.SignRequest
		response     interface{}
		responseCode int
		wantErr      bool
		expectedErr  error
	}{
		{"ok", request, ok, 200, false, nil},
		{"unauthorized", request, errs.Unauthorized("force"), 401, true, errors.New(errs.UnauthorizedDefaultMsg)},
		{"empty request", &api.SignRequest{}, errs.BadRequest("force"), 400, true, errors.New(errs.BadRequestPrefix + "force.")},
		{"nil request", nil, errs.BadRequest("force"), 400, true, errors.New(errs.BadRequestPrefix + "force.")},
	}

	srv := httptest.NewServer(nil)
	defer srv.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(srv.URL, WithTransport(http.DefaultTransport))
			if err != nil {
				t.Errorf("NewClient() error = %v", err)
				return
			}

			srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				body := new(api.SignRequest)
				if err := read.JSON(req.Body, body); err != nil {
					e, ok := tt.response.(error)
					assert.Fatal(t, ok, "response expected to be error type")
					render.Error(w, e)
					return
				} else if !equalJSON(t, body, tt.request) {
					if tt.request == nil {
						if !reflect.DeepEqual(body, &api.SignRequest{}) {
							t.Errorf("Client.Sign() request = %v, wants %v", body, tt.request)
						}
					} else {
						t.Errorf("Client.Sign() request = %v, wants %v", body, tt.request)
					}
				}
				render.JSONStatus(w, tt.response, tt.responseCode)
			})

			got, err := c.Sign(tt.request)
			if (err != nil) != tt.wantErr {
				fmt.Printf("%+v", err)
				t.Errorf("Client.Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			switch {
			case err != nil:
				if got != nil {
					t.Errorf("Client.Sign() = %v, want nil", got)
				}
				assert.HasPrefix(t, tt.expectedErr.Error(), err.Error())
			default:
				if !reflect.DeepEqual(got, tt.response) {
					t.Errorf("Client.Sign() = %v, want %v", got, tt.response)
				}
			}
		})
	}
}

func TestClient_Revoke(t *testing.T) {
	ok := &api.RevokeResponse{Status: "ok"}
	request := &api.RevokeRequest{
		Serial:     "sn",
		OTT:        "the-ott",
		ReasonCode: 4,
	}
	tests := []struct {
		name         string
		request      *api.RevokeRequest
		response     interface{}
		responseCode int
		wantErr      bool
		expectedErr  error
	}{
		{"ok", request, ok, 200, false, nil},
		{"unauthorized", request, errs.Unauthorized("force"), 401, true, errors.New(errs.UnauthorizedDefaultMsg)},
		{"nil request", nil, errs.BadRequest("force"), 400, true, errors.New(errs.BadRequestPrefix)},
	}

	srv := httptest.NewServer(nil)
	defer srv.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(srv.URL, WithTransport(http.DefaultTransport))
			if err != nil {
				t.Errorf("NewClient() error = %v", err)
				return
			}

			srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				body := new(api.RevokeRequest)
				if err := read.JSON(req.Body, body); err != nil {
					e, ok := tt.response.(error)
					assert.Fatal(t, ok, "response expected to be error type")
					render.Error(w, e)
					return
				} else if !equalJSON(t, body, tt.request) {
					if tt.request == nil {
						if !reflect.DeepEqual(body, &api.RevokeRequest{}) {
							t.Errorf("Client.Revoke() request = %v, wants %v", body, tt.request)
						}
					} else {
						t.Errorf("Client.Revoke() request = %v, wants %v", body, tt.request)
					}
				}
				render.JSONStatus(w, tt.response, tt.responseCode)
			})

			got, err := c.Revoke(tt.request, nil)
			if (err != nil) != tt.wantErr {
				fmt.Printf("%+v", err)
				t.Errorf("Client.Revoke() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			switch {
			case err != nil:
				if got != nil {
					t.Errorf("Client.Revoke() = %v, want nil", got)
				}
				assert.HasPrefix(t, err.Error(), tt.expectedErr.Error())
			default:
				if !reflect.DeepEqual(got, tt.response) {
					t.Errorf("Client.Revoke() = %v, want %v", got, tt.response)
				}
			}
		})
	}
}

func TestClient_Renew(t *testing.T) {
	ok := &api.SignResponse{
		ServerPEM: api.Certificate{Certificate: parseCertificate(certPEM)},
		CaPEM:     api.Certificate{Certificate: parseCertificate(rootPEM)},
		CertChainPEM: []api.Certificate{
			{Certificate: parseCertificate(certPEM)},
			{Certificate: parseCertificate(rootPEM)},
		},
	}

	tests := []struct {
		name         string
		response     interface{}
		responseCode int
		wantErr      bool
		err          error
	}{
		{"ok", ok, 200, false, nil},
		{"unauthorized", errs.Unauthorized("force"), 401, true, errors.New(errs.UnauthorizedDefaultMsg)},
		{"empty request", errs.BadRequest("force"), 400, true, errors.New(errs.BadRequestPrefix)},
		{"nil request", errs.BadRequest("force"), 400, true, errors.New(errs.BadRequestPrefix)},
	}

	srv := httptest.NewServer(nil)
	defer srv.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(srv.URL, WithTransport(http.DefaultTransport))
			if err != nil {
				t.Errorf("NewClient() error = %v", err)
				return
			}

			srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				render.JSONStatus(w, tt.response, tt.responseCode)
			})

			got, err := c.Renew(nil)
			if (err != nil) != tt.wantErr {
				fmt.Printf("%+v", err)
				t.Errorf("Client.Renew() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			switch {
			case err != nil:
				if got != nil {
					t.Errorf("Client.Renew() = %v, want nil", got)
				}

				var sc render.StatusCodedError
				if assert.True(t, errors.As(err, &sc), "error does not implement StatusCodedError interface") {
					assert.Equals(t, sc.StatusCode(), tt.responseCode)
				}
				assert.HasPrefix(t, err.Error(), tt.err.Error())
			default:
				if !reflect.DeepEqual(got, tt.response) {
					t.Errorf("Client.Renew() = %v, want %v", got, tt.response)
				}
			}
		})
	}
}

func TestClient_RenewWithToken(t *testing.T) {
	ok := &api.SignResponse{
		ServerPEM: api.Certificate{Certificate: parseCertificate(certPEM)},
		CaPEM:     api.Certificate{Certificate: parseCertificate(rootPEM)},
		CertChainPEM: []api.Certificate{
			{Certificate: parseCertificate(certPEM)},
			{Certificate: parseCertificate(rootPEM)},
		},
	}

	tests := []struct {
		name         string
		response     interface{}
		responseCode int
		wantErr      bool
		err          error
	}{
		{"ok", ok, 200, false, nil},
		{"unauthorized", errs.Unauthorized("force"), 401, true, errors.New(errs.UnauthorizedDefaultMsg)},
		{"empty request", errs.BadRequest("force"), 400, true, errors.New(errs.BadRequestPrefix)},
		{"nil request", errs.BadRequest("force"), 400, true, errors.New(errs.BadRequestPrefix)},
	}

	srv := httptest.NewServer(nil)
	defer srv.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(srv.URL, WithTransport(http.DefaultTransport))
			if err != nil {
				t.Errorf("NewClient() error = %v", err)
				return
			}

			srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.Header.Get("Authorization") != "Bearer token" {
					render.JSONStatus(w, errs.InternalServer("force"), 500)
				} else {
					render.JSONStatus(w, tt.response, tt.responseCode)
				}
			})

			got, err := c.RenewWithToken("token")
			if (err != nil) != tt.wantErr {
				fmt.Printf("%+v", err)
				t.Errorf("Client.RenewWithToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			switch {
			case err != nil:
				if got != nil {
					t.Errorf("Client.RenewWithToken() = %v, want nil", got)
				}

				var sc render.StatusCodedError
				if assert.True(t, errors.As(err, &sc), "error does not implement StatusCodedError interface") {
					assert.Equals(t, sc.StatusCode(), tt.responseCode)
				}
				assert.HasPrefix(t, err.Error(), tt.err.Error())
			default:
				if !reflect.DeepEqual(got, tt.response) {
					t.Errorf("Client.RenewWithToken() = %v, want %v", got, tt.response)
				}
			}
		})
	}
}

func TestClient_Rekey(t *testing.T) {
	ok := &api.SignResponse{
		ServerPEM: api.Certificate{Certificate: parseCertificate(certPEM)},
		CaPEM:     api.Certificate{Certificate: parseCertificate(rootPEM)},
		CertChainPEM: []api.Certificate{
			{Certificate: parseCertificate(certPEM)},
			{Certificate: parseCertificate(rootPEM)},
		},
	}

	request := &api.RekeyRequest{
		CsrPEM: api.CertificateRequest{CertificateRequest: parseCertificateRequest(csrPEM)},
	}

	tests := []struct {
		name         string
		request      *api.RekeyRequest
		response     interface{}
		responseCode int
		wantErr      bool
		err          error
	}{
		{"ok", request, ok, 200, false, nil},
		{"unauthorized", request, errs.Unauthorized("force"), 401, true, errors.New(errs.UnauthorizedDefaultMsg)},
		{"empty request", &api.RekeyRequest{}, errs.BadRequest("force"), 400, true, errors.New(errs.BadRequestPrefix)},
		{"nil request", nil, errs.BadRequest("force"), 400, true, errors.New(errs.BadRequestPrefix)},
	}

	srv := httptest.NewServer(nil)
	defer srv.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(srv.URL, WithTransport(http.DefaultTransport))
			if err != nil {
				t.Errorf("NewClient() error = %v", err)
				return
			}

			srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				render.JSONStatus(w, tt.response, tt.responseCode)
			})

			got, err := c.Rekey(tt.request, nil)
			if (err != nil) != tt.wantErr {
				fmt.Printf("%+v", err)
				t.Errorf("Client.Renew() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			switch {
			case err != nil:
				if got != nil {
					t.Errorf("Client.Renew() = %v, want nil", got)
				}

				var sc render.StatusCodedError
				if assert.True(t, errors.As(err, &sc), "error does not implement StatusCodedError interface") {
					assert.Equals(t, sc.StatusCode(), tt.responseCode)
				}
				assert.HasPrefix(t, err.Error(), tt.err.Error())
			default:
				if !reflect.DeepEqual(got, tt.response) {
					t.Errorf("Client.Renew() = %v, want %v", got, tt.response)
				}
			}
		})
	}
}

func TestClient_Provisioners(t *testing.T) {
	ok := &api.ProvisionersResponse{
		Provisioners: provisioner.List{},
	}
	internalServerError := errs.InternalServer("Internal Server Error")

	tests := []struct {
		name         string
		args         []ProvisionerOption
		expectedURI  string
		response     interface{}
		responseCode int
		wantErr      bool
	}{
		{"ok", nil, "/provisioners", ok, 200, false},
		{"ok with cursor", []ProvisionerOption{WithProvisionerCursor("abc")}, "/provisioners?cursor=abc", ok, 200, false},
		{"ok with limit", []ProvisionerOption{WithProvisionerLimit(10)}, "/provisioners?limit=10", ok, 200, false},
		{"ok with cursor+limit", []ProvisionerOption{WithProvisionerCursor("abc"), WithProvisionerLimit(10)}, "/provisioners?cursor=abc&limit=10", ok, 200, false},
		{"fail", nil, "/provisioners", internalServerError, 500, true},
	}

	srv := httptest.NewServer(nil)
	defer srv.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(srv.URL, WithTransport(http.DefaultTransport))
			if err != nil {
				t.Errorf("NewClient() error = %v", err)
				return
			}

			srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.RequestURI != tt.expectedURI {
					t.Errorf("RequestURI = %s, want %s", req.RequestURI, tt.expectedURI)
				}
				render.JSONStatus(w, tt.response, tt.responseCode)
			})

			got, err := c.Provisioners(tt.args...)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.Provisioners() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			switch {
			case err != nil:
				if got != nil {
					t.Errorf("Client.Provisioners() = %v, want nil", got)
				}
				assert.HasPrefix(t, errs.InternalServerErrorDefaultMsg, err.Error())
			default:
				if !reflect.DeepEqual(got, tt.response) {
					t.Errorf("Client.Provisioners() = %v, want %v", got, tt.response)
				}
			}
		})
	}
}

func TestClient_ProvisionerKey(t *testing.T) {
	ok := &api.ProvisionerKeyResponse{
		Key: "an encrypted key",
	}

	tests := []struct {
		name         string
		kid          string
		response     interface{}
		responseCode int
		wantErr      bool
		err          error
	}{
		{"ok", "kid", ok, 200, false, nil},
		{"fail", "invalid", errs.NotFound("force"), 404, true, errors.New(errs.NotFoundDefaultMsg)},
	}

	srv := httptest.NewServer(nil)
	defer srv.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(srv.URL, WithTransport(http.DefaultTransport))
			if err != nil {
				t.Errorf("NewClient() error = %v", err)
				return
			}

			srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				expected := "/provisioners/" + tt.kid + "/encrypted-key"
				if req.RequestURI != expected {
					t.Errorf("RequestURI = %s, want %s", req.RequestURI, expected)
				}
				render.JSONStatus(w, tt.response, tt.responseCode)
			})

			got, err := c.ProvisionerKey(tt.kid)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.ProvisionerKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			switch {
			case err != nil:
				if got != nil {
					t.Errorf("Client.ProvisionerKey() = %v, want nil", got)
				}

				var sc render.StatusCodedError
				if assert.True(t, errors.As(err, &sc), "error does not implement StatusCodedError interface") {
					assert.Equals(t, sc.StatusCode(), tt.responseCode)
				}
				assert.HasPrefix(t, tt.err.Error(), err.Error())
			default:
				if !reflect.DeepEqual(got, tt.response) {
					t.Errorf("Client.ProvisionerKey() = %v, want %v", got, tt.response)
				}
			}
		})
	}
}

func TestClient_Roots(t *testing.T) {
	ok := &api.RootsResponse{
		Certificates: []api.Certificate{
			{Certificate: parseCertificate(rootPEM)},
		},
	}

	tests := []struct {
		name         string
		response     interface{}
		responseCode int
		wantErr      bool
		err          error
	}{
		{"ok", ok, 200, false, nil},
		{"unauthorized", errs.Unauthorized("force"), 401, true, errors.New(errs.UnauthorizedDefaultMsg)},
		{"bad-request", errs.BadRequest("force"), 400, true, errors.New(errs.BadRequestPrefix)},
	}

	srv := httptest.NewServer(nil)
	defer srv.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(srv.URL, WithTransport(http.DefaultTransport))
			if err != nil {
				t.Errorf("NewClient() error = %v", err)
				return
			}

			srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				render.JSONStatus(w, tt.response, tt.responseCode)
			})

			got, err := c.Roots()
			if (err != nil) != tt.wantErr {
				fmt.Printf("%+v", err)
				t.Errorf("Client.Roots() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			switch {
			case err != nil:
				if got != nil {
					t.Errorf("Client.Roots() = %v, want nil", got)
				}
				var sc render.StatusCodedError
				if assert.True(t, errors.As(err, &sc), "error does not implement StatusCodedError interface") {
					assert.Equals(t, sc.StatusCode(), tt.responseCode)
				}
				assert.HasPrefix(t, err.Error(), tt.err.Error())
			default:
				if !reflect.DeepEqual(got, tt.response) {
					t.Errorf("Client.Roots() = %v, want %v", got, tt.response)
				}
			}
		})
	}
}

func TestClient_Federation(t *testing.T) {
	ok := &api.FederationResponse{
		Certificates: []api.Certificate{
			{Certificate: parseCertificate(rootPEM)},
		},
	}

	tests := []struct {
		name         string
		response     interface{}
		responseCode int
		wantErr      bool
		err          error
	}{
		{"ok", ok, 200, false, nil},
		{"unauthorized", errs.Unauthorized("force"), 401, true, errors.New(errs.UnauthorizedDefaultMsg)},
	}

	srv := httptest.NewServer(nil)
	defer srv.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(srv.URL, WithTransport(http.DefaultTransport))
			if err != nil {
				t.Errorf("NewClient() error = %v", err)
				return
			}

			srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				render.JSONStatus(w, tt.response, tt.responseCode)
			})

			got, err := c.Federation()
			if (err != nil) != tt.wantErr {
				fmt.Printf("%+v", err)
				t.Errorf("Client.Federation() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			switch {
			case err != nil:
				if got != nil {
					t.Errorf("Client.Federation() = %v, want nil", got)
				}
				var sc render.StatusCodedError
				if assert.True(t, errors.As(err, &sc), "error does not implement StatusCodedError interface") {
					assert.Equals(t, sc.StatusCode(), tt.responseCode)
				}
				assert.HasPrefix(t, tt.err.Error(), err.Error())
			default:
				if !reflect.DeepEqual(got, tt.response) {
					t.Errorf("Client.Federation() = %v, want %v", got, tt.response)
				}
			}
		})
	}
}

func TestClient_SSHRoots(t *testing.T) {
	key, err := ssh.NewPublicKey(mustKey().Public())
	if err != nil {
		t.Fatal(err)
	}

	ok := &api.SSHRootsResponse{
		HostKeys: []api.SSHPublicKey{{PublicKey: key}},
		UserKeys: []api.SSHPublicKey{{PublicKey: key}},
	}

	tests := []struct {
		name         string
		response     interface{}
		responseCode int
		wantErr      bool
		err          error
	}{
		{"ok", ok, 200, false, nil},
		{"not found", errs.NotFound("force"), 404, true, errors.New(errs.NotFoundDefaultMsg)},
	}

	srv := httptest.NewServer(nil)
	defer srv.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(srv.URL, WithTransport(http.DefaultTransport))
			if err != nil {
				t.Errorf("NewClient() error = %v", err)
				return
			}

			srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				render.JSONStatus(w, tt.response, tt.responseCode)
			})

			got, err := c.SSHRoots()
			if (err != nil) != tt.wantErr {
				fmt.Printf("%+v", err)
				t.Errorf("Client.SSHKeys() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			switch {
			case err != nil:
				if got != nil {
					t.Errorf("Client.SSHKeys() = %v, want nil", got)
				}
				var sc render.StatusCodedError
				if assert.True(t, errors.As(err, &sc), "error does not implement StatusCodedError interface") {
					assert.Equals(t, sc.StatusCode(), tt.responseCode)
				}
				assert.HasPrefix(t, tt.err.Error(), err.Error())
			default:
				if !reflect.DeepEqual(got, tt.response) {
					t.Errorf("Client.SSHKeys() = %v, want %v", got, tt.response)
				}
			}
		})
	}
}

func Test_parseEndpoint(t *testing.T) {
	expected1 := &url.URL{Scheme: "https", Host: "ca.smallstep.com"}
	expected2 := &url.URL{Scheme: "https", Host: "ca.smallstep.com", Path: "/1.0/sign"}
	type args struct {
		endpoint string
	}
	tests := []struct {
		name    string
		args    args
		want    *url.URL
		wantErr bool
	}{
		{"ok", args{"https://ca.smallstep.com"}, expected1, false},
		{"ok no scheme", args{"//ca.smallstep.com"}, expected1, false},
		{"ok only host", args{"ca.smallstep.com"}, expected1, false},
		{"ok no bars", args{"https://ca.smallstep.com"}, expected1, false},
		{"ok schema, host and path", args{"https://ca.smallstep.com/1.0/sign"}, expected2, false},
		{"ok no bars with path", args{"https://ca.smallstep.com/1.0/sign"}, expected2, false},
		{"ok host and path", args{"ca.smallstep.com/1.0/sign"}, expected2, false},
		{"ok host and port", args{"ca.smallstep.com:443"}, &url.URL{Scheme: "https", Host: "ca.smallstep.com:443"}, false},
		{"ok host, path and port", args{"ca.smallstep.com:443/1.0/sign"}, &url.URL{Scheme: "https", Host: "ca.smallstep.com:443", Path: "/1.0/sign"}, false},
		{"fail bad url", args{"://ca.smallstep.com"}, nil, true},
		{"fail no host", args{"https://"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseEndpoint(tt.args.endpoint)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseEndpoint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseEndpoint() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClient_RootFingerprint(t *testing.T) {
	ok := &api.HealthResponse{Status: "ok"}
	nok := errs.InternalServer("Internal Server Error")

	httpsServer := httptest.NewTLSServer(nil)
	defer httpsServer.Close()
	httpsServerFingerprint := x509util.Fingerprint(httpsServer.Certificate())

	httpServer := httptest.NewServer(nil)
	defer httpServer.Close()

	tests := []struct {
		name         string
		server       *httptest.Server
		response     interface{}
		responseCode int
		want         string
		wantErr      bool
	}{
		{"ok", httpsServer, ok, 200, httpsServerFingerprint, false},
		{"ok with error", httpsServer, nok, 500, httpsServerFingerprint, false},
		{"fail", httpServer, ok, 200, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := tt.server.Client().Transport
			c, err := NewClient(tt.server.URL, WithTransport(tr))
			if err != nil {
				t.Errorf("NewClient() error = %v", err)
				return
			}

			tt.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				render.JSONStatus(w, tt.response, tt.responseCode)
			})

			got, err := c.RootFingerprint()
			if (err != nil) != tt.wantErr {
				fmt.Printf("%+v", err)
				t.Errorf("Client.RootFingerprint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Client.RootFingerprint() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClient_RootFingerprintWithServer(t *testing.T) {
	srv := startCABootstrapServer()
	defer srv.Close()

	client, err := NewClient(srv.URL+"/sign", WithRootFile("testdata/secrets/root_ca.crt"))
	assert.FatalError(t, err)

	fp, err := client.RootFingerprint()
	assert.FatalError(t, err)
	assert.Equals(t, "ef742f95dc0d8aa82d3cca4017af6dac3fce84290344159891952d18c53eefe7", fp)
}

func TestClient_SSHBastion(t *testing.T) {
	ok := &api.SSHBastionResponse{
		Hostname: "host.local",
		Bastion: &authority.Bastion{
			Hostname: "bastion.local",
		},
	}

	tests := []struct {
		name         string
		request      *api.SSHBastionRequest
		response     interface{}
		responseCode int
		wantErr      bool
		err          error
	}{
		{"ok", &api.SSHBastionRequest{Hostname: "host.local"}, ok, 200, false, nil},
		{"bad-response", &api.SSHBastionRequest{Hostname: "host.local"}, "bad json", 200, true, nil},
		{"bad-request", &api.SSHBastionRequest{}, errs.BadRequest("force"), 400, true, errors.New(errs.BadRequestPrefix)},
	}

	srv := httptest.NewServer(nil)
	defer srv.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(srv.URL, WithTransport(http.DefaultTransport))
			if err != nil {
				t.Errorf("NewClient() error = %v", err)
				return
			}

			srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				render.JSONStatus(w, tt.response, tt.responseCode)
			})

			got, err := c.SSHBastion(tt.request)
			if (err != nil) != tt.wantErr {
				fmt.Printf("%+v", err)
				t.Errorf("Client.SSHBastion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			switch {
			case err != nil:
				if got != nil {
					t.Errorf("Client.SSHBastion() = %v, want nil", got)
				}
				if tt.responseCode != 200 {
					var sc render.StatusCodedError
					if assert.True(t, errors.As(err, &sc), "error does not implement StatusCodedError interface") {
						assert.Equals(t, sc.StatusCode(), tt.responseCode)
					}
					assert.HasPrefix(t, err.Error(), tt.err.Error())
				}
			default:
				if !reflect.DeepEqual(got, tt.response) {
					t.Errorf("Client.SSHBastion() = %v, want %v", got, tt.response)
				}
			}
		})
	}
}

func TestClient_GetCaURL(t *testing.T) {
	tests := []struct {
		name  string
		caURL string
		want  string
	}{
		{"ok", "https://ca.com", "https://ca.com"},
		{"ok no schema", "ca.com", "https://ca.com"},
		{"ok with port", "https://ca.com:9000", "https://ca.com:9000"},
		{"ok with version", "https://ca.com/1.0", "https://ca.com/1.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(tt.caURL, WithTransport(http.DefaultTransport))
			if err != nil {
				t.Errorf("NewClient() error = %v", err)
				return
			}
			if got := c.GetCaURL(); got != tt.want {
				t.Errorf("Client.GetCaURL() = %v, want %v", got, tt.want)
			}
		})
	}
}
