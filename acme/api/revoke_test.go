package api

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"github.com/go-chi/chi"
	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/provisioner"
	"go.step.sm/crypto/jose"
	"golang.org/x/crypto/ocsp"
)

const (
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
)

func v(v int) *int {
	return &v
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

type mockCA struct {
	MockIsRevoked func(sn string) (bool, error)
	MockRevoke    func(ctx context.Context, opts *authority.RevokeOptions) error
}

func (m *mockCA) Sign(cr *x509.CertificateRequest, opts provisioner.SignOptions, signOpts ...provisioner.SignOption) ([]*x509.Certificate, error) {
	return nil, nil
}

func (m *mockCA) IsRevoked(sn string) (bool, error) {
	if m.MockIsRevoked != nil {
		return m.MockIsRevoked(sn)
	}
	return false, nil
}

func (m *mockCA) Revoke(ctx context.Context, opts *authority.RevokeOptions) error {
	if m.MockRevoke != nil {
		return m.MockRevoke(ctx, opts)
	}
	return nil
}

func (m *mockCA) LoadProvisionerByName(string) (provisioner.Interface, error) {
	return nil, nil
}

func Test_validateReasonCode(t *testing.T) {
	tests := []struct {
		name       string
		reasonCode *int
		want       *acme.Error
	}{
		{
			name:       "ok",
			reasonCode: v(ocsp.Unspecified),
			want:       nil,
		},
		{
			name:       "fail/too-low",
			reasonCode: v(-1),
			want:       acme.NewError(acme.ErrorBadRevocationReasonType, "reasonCode out of bounds"),
		},
		{
			name:       "fail/too-high",
			reasonCode: v(11),
			want:       acme.NewError(acme.ErrorBadRevocationReasonType, "reasonCode out of bounds"),
		},
		{
			name:       "fail/missing-7",
			reasonCode: v(7),

			want: acme.NewError(acme.ErrorBadRevocationReasonType, "reasonCode out of bounds"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateReasonCode(tt.reasonCode)
			if (err != nil) != (tt.want != nil) {
				t.Errorf("validateReasonCode() = %v, want %v", err, tt.want)
			}
			if err != nil {
				assert.Equals(t, err.Type, tt.want.Type)
				assert.Equals(t, err.Detail, tt.want.Detail)
				assert.Equals(t, err.Status, tt.want.Status)
				assert.Equals(t, err.Err.Error(), tt.want.Err.Error())
				assert.Equals(t, err.Detail, tt.want.Detail)
			}
		})
	}
}

func Test_reason(t *testing.T) {

	// 	case ocsp.RemoveFromCRL:
	// 		return "remove from crl"
	// 	case ocsp.PrivilegeWithdrawn:
	// 		return "privilege withdrawn"
	// 	case ocsp.AACompromise:
	// 		return "aa compromised"
	// 	default:
	// 		return "unspecified reason"
	// 	}
	// }
	tests := []struct {
		name       string
		reasonCode int
		want       string
	}{
		{
			name:       "unspecified reason",
			reasonCode: ocsp.Unspecified,
			want:       "unspecified reason",
		},
		{
			name:       "key compromised",
			reasonCode: ocsp.KeyCompromise,
			want:       "key compromised",
		},
		{
			name:       "ca compromised",
			reasonCode: ocsp.CACompromise,
			want:       "ca compromised",
		},
		{
			name:       "affiliation changed",
			reasonCode: ocsp.AffiliationChanged,
			want:       "affiliation changed",
		},
		{
			name:       "superseded",
			reasonCode: ocsp.Superseded,
			want:       "superseded",
		},
		{
			name:       "cessation of operation",
			reasonCode: ocsp.CessationOfOperation,
			want:       "cessation of operation",
		},
		{
			name:       "certificate hold",
			reasonCode: ocsp.CertificateHold,
			want:       "certificate hold",
		},
		{
			name:       "remove from crl",
			reasonCode: ocsp.RemoveFromCRL,
			want:       "remove from crl",
		},
		{
			name:       "privilege withdrawn",
			reasonCode: ocsp.PrivilegeWithdrawn,
			want:       "privilege withdrawn",
		},
		{
			name:       "aa compromised",
			reasonCode: ocsp.AACompromise,
			want:       "aa compromised",
		},
		{
			name:       "default",
			reasonCode: -1,
			want:       "unspecified reason",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reason(tt.reasonCode); got != tt.want {
				t.Errorf("reason() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_revokeOptions(t *testing.T) {
	var cert *x509.Certificate
	type args struct {
		serial          string
		certToBeRevoked *x509.Certificate
		reasonCode      *int
	}
	tests := []struct {
		name string
		args args
		want *authority.RevokeOptions
	}{
		{
			name: "ok/no-reasoncode",
			args: args{
				serial:          "1234",
				certToBeRevoked: cert,
			},
			want: &authority.RevokeOptions{
				Serial: "1234",
				Crt:    nil,
				ACME:   true,
			},
		},
		{
			name: "ok/including-reasoncode",
			args: args{
				serial:          "1234",
				certToBeRevoked: cert,
				reasonCode:      v(ocsp.KeyCompromise),
			},
			want: &authority.RevokeOptions{
				Serial:     "1234",
				Crt:        nil,
				ACME:       true,
				ReasonCode: 1,
				Reason:     "key compromised",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := revokeOptions(tt.args.serial, tt.args.certToBeRevoked, tt.args.reasonCode); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("revokeOptions() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHandler_RevokeCert(t *testing.T) {
	prov := &provisioner.ACME{
		Type: "ACME",
		Name: "testprov",
	}
	escProvName := url.PathEscape(prov.GetName())
	baseURL := &url.URL{Scheme: "https", Host: "test.ca.smallstep.com"}

	chiCtx := chi.NewRouteContext()
	revokeURL := fmt.Sprintf("%s/acme/%s/revoke-cert", baseURL.String(), escProvName)

	cert := parseCertificate(certPEM)
	rp := &revokePayload{
		Certificate: base64.RawURLEncoding.EncodeToString(cert.Raw),
	}
	payloadBytes, err := json.Marshal(rp)
	assert.FatalError(t, err)

	type test struct {
		db         acme.DB
		ca         acme.CertificateAuthority
		ctx        context.Context
		statusCode int
		err        *acme.Error
	}

	var tests = map[string]func(t *testing.T) test{
		"fail/wrong-certificate-encoding": func(t *testing.T) test {
			rp := &revokePayload{
				Certificate: base64.StdEncoding.EncodeToString(cert.Raw),
			}
			wronglyEncodedPayloadBytes, err := json.Marshal(rp)
			assert.FatalError(t, err)
			jws := &jose.JSONWebSignature{
				Signatures: []jose.Signature{
					{
						Protected: jose.Header{
							Algorithm: jose.ES256,
							KeyID:     "bar",
							ExtraHeaders: map[jose.HeaderKey]interface{}{
								"url": revokeURL,
							},
						},
					},
				},
			}
			acc := &acme.Account{ID: "accountID", Status: acme.StatusInvalid}
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: wronglyEncodedPayloadBytes})
			ctx = context.WithValue(ctx, jwsContextKey, jws)
			ctx = context.WithValue(ctx, baseURLContextKey, baseURL)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			db := &acme.MockDB{}
			ca := &mockCA{}
			return test{
				db:         db,
				ca:         ca,
				ctx:        ctx,
				statusCode: 400,
				err: &acme.Error{
					Type:   "urn:ietf:params:acme:error:malformed",
					Status: 400,
					Detail: "The request message was malformed",
				},
			}
		},
		"fail/no-certificate-encoded": func(t *testing.T) test {
			rp := &revokePayload{
				Certificate: base64.RawURLEncoding.EncodeToString([]byte{}),
			}
			wrongPayloadBytes, err := json.Marshal(rp)
			assert.FatalError(t, err)
			jws := &jose.JSONWebSignature{
				Signatures: []jose.Signature{
					{
						Protected: jose.Header{
							Algorithm: jose.ES256,
							KeyID:     "bar",
							ExtraHeaders: map[jose.HeaderKey]interface{}{
								"url": revokeURL,
							},
						},
					},
				},
			}
			acc := &acme.Account{ID: "accountID", Status: acme.StatusInvalid}
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: wrongPayloadBytes})
			ctx = context.WithValue(ctx, jwsContextKey, jws)
			ctx = context.WithValue(ctx, baseURLContextKey, baseURL)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			db := &acme.MockDB{}
			ca := &mockCA{}
			return test{
				db:         db,
				ca:         ca,
				ctx:        ctx,
				statusCode: 400,
				err: &acme.Error{
					Type:   "urn:ietf:params:acme:error:malformed",
					Status: 400,
					Detail: "The request message was malformed",
				},
			}
		},
		"fail/account-not-valid": func(t *testing.T) test {
			jws := &jose.JSONWebSignature{
				Signatures: []jose.Signature{
					{
						Protected: jose.Header{
							Algorithm: jose.ES256,
							KeyID:     "bar",
							ExtraHeaders: map[jose.HeaderKey]interface{}{
								"url": revokeURL,
							},
						},
					},
				},
			}
			acc := &acme.Account{ID: "accountID", Status: acme.StatusInvalid}
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: payloadBytes})
			ctx = context.WithValue(ctx, jwsContextKey, jws)
			ctx = context.WithValue(ctx, baseURLContextKey, baseURL)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			db := &acme.MockDB{
				MockGetCertificateBySerial: func(ctx context.Context, serial string) (*acme.Certificate, error) {
					assert.Equals(t, cert.SerialNumber.String(), serial)
					return &acme.Certificate{
						AccountID: "accountID",
					}, nil
				},
			}
			ca := &mockCA{}
			return test{
				db:         db,
				ca:         ca,
				ctx:        ctx,
				statusCode: 403,
				err: &acme.Error{
					Type:   "urn:ietf:params:acme:error:unauthorized",
					Detail: fmt.Sprintf("No authorization provided for name %s", cert.Subject.String()),
					Status: 403,
				},
			}
		},
		"fail/account-not-authorized": func(t *testing.T) test {
			jws := &jose.JSONWebSignature{
				Signatures: []jose.Signature{
					{
						Protected: jose.Header{
							Algorithm: jose.ES256,
							KeyID:     "bar",
							ExtraHeaders: map[jose.HeaderKey]interface{}{
								"url": revokeURL,
							},
						},
					},
				},
			}
			acc := &acme.Account{ID: "accountID", Status: acme.StatusValid}
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: payloadBytes})
			ctx = context.WithValue(ctx, jwsContextKey, jws)
			ctx = context.WithValue(ctx, baseURLContextKey, baseURL)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			db := &acme.MockDB{
				MockGetCertificateBySerial: func(ctx context.Context, serial string) (*acme.Certificate, error) {
					assert.Equals(t, cert.SerialNumber.String(), serial)
					return &acme.Certificate{
						AccountID: "differentAccountID",
					}, nil
				},
			}
			ca := &mockCA{}
			return test{
				db:         db,
				ca:         ca,
				ctx:        ctx,
				statusCode: 403,
				err: &acme.Error{
					Type:   "urn:ietf:params:acme:error:unauthorized",
					Detail: fmt.Sprintf("No authorization provided for name %s", cert.Subject.String()),
					Status: 403,
				},
			}
		},
		"fail/certificate-revoked-check-fails": func(t *testing.T) test {
			jws := &jose.JSONWebSignature{
				Signatures: []jose.Signature{
					{
						Protected: jose.Header{
							Algorithm: jose.ES256,
							KeyID:     "bar",
							ExtraHeaders: map[jose.HeaderKey]interface{}{
								"url": revokeURL,
							},
						},
					},
				},
			}
			acc := &acme.Account{ID: "accountID", Status: acme.StatusValid}
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: payloadBytes})
			ctx = context.WithValue(ctx, jwsContextKey, jws)
			ctx = context.WithValue(ctx, baseURLContextKey, baseURL)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			db := &acme.MockDB{
				MockGetCertificateBySerial: func(ctx context.Context, serial string) (*acme.Certificate, error) {
					assert.Equals(t, cert.SerialNumber.String(), serial)
					return &acme.Certificate{
						AccountID: "accountID",
					}, nil
				},
			}
			ca := &mockCA{
				MockIsRevoked: func(sn string) (bool, error) {
					return false, errors.New("force")
				},
			}
			return test{
				db:         db,
				ca:         ca,
				ctx:        ctx,
				statusCode: 500,
				err: &acme.Error{
					Type:   "urn:ietf:params:acme:error:serverInternal",
					Detail: "The server experienced an internal error",
					Status: 500,
				},
			}
		},
		"fail/certificate-already-revoked": func(t *testing.T) test {
			jws := &jose.JSONWebSignature{
				Signatures: []jose.Signature{
					{
						Protected: jose.Header{
							Algorithm: jose.ES256,
							KeyID:     "bar",
							ExtraHeaders: map[jose.HeaderKey]interface{}{
								"url": revokeURL,
							},
						},
					},
				},
			}
			acc := &acme.Account{ID: "accountID", Status: acme.StatusValid}
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: payloadBytes})
			ctx = context.WithValue(ctx, jwsContextKey, jws)
			ctx = context.WithValue(ctx, baseURLContextKey, baseURL)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			db := &acme.MockDB{
				MockGetCertificateBySerial: func(ctx context.Context, serial string) (*acme.Certificate, error) {
					assert.Equals(t, cert.SerialNumber.String(), serial)
					return &acme.Certificate{
						AccountID: "accountID",
					}, nil
				},
			}
			ca := &mockCA{
				MockIsRevoked: func(sn string) (bool, error) {
					return true, nil
				},
			}
			return test{
				db:         db,
				ca:         ca,
				ctx:        ctx,
				statusCode: 400,
				err: &acme.Error{
					Type:   "urn:ietf:params:acme:error:alreadyRevoked",
					Detail: "Certificate already revoked",
					Status: 400,
				},
			}
		},
		"fail/certificate-revoke-fails": func(t *testing.T) test {
			jws := &jose.JSONWebSignature{
				Signatures: []jose.Signature{
					{
						Protected: jose.Header{
							Algorithm: jose.ES256,
							KeyID:     "bar",
							ExtraHeaders: map[jose.HeaderKey]interface{}{
								"url": revokeURL,
							},
						},
					},
				},
			}
			acc := &acme.Account{ID: "accountID", Status: acme.StatusValid}
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: payloadBytes})
			ctx = context.WithValue(ctx, jwsContextKey, jws)
			ctx = context.WithValue(ctx, baseURLContextKey, baseURL)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			db := &acme.MockDB{
				MockGetCertificateBySerial: func(ctx context.Context, serial string) (*acme.Certificate, error) {
					assert.Equals(t, cert.SerialNumber.String(), serial)
					return &acme.Certificate{
						AccountID: "accountID",
					}, nil
				},
			}
			ca := &mockCA{
				MockRevoke: func(ctx context.Context, opts *authority.RevokeOptions) error {
					return errors.New("force")
				},
			}
			return test{
				db:         db,
				ca:         ca,
				ctx:        ctx,
				statusCode: 500,
				err: &acme.Error{
					Type:   "urn:ietf:params:acme:error:serverInternal",
					Detail: "The server experienced an internal error",
					Status: 500,
				},
			}
		},
		"ok/using-account-key": func(t *testing.T) test {
			jws := &jose.JSONWebSignature{
				Signatures: []jose.Signature{
					{
						Protected: jose.Header{
							Algorithm: jose.ES256,
							KeyID:     "bar",
							ExtraHeaders: map[jose.HeaderKey]interface{}{
								"url": revokeURL,
							},
						},
					},
				},
			}
			acc := &acme.Account{ID: "accountID", Status: acme.StatusValid}
			ctx := context.WithValue(context.Background(), provisionerContextKey, prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: payloadBytes})
			ctx = context.WithValue(ctx, jwsContextKey, jws)
			ctx = context.WithValue(ctx, baseURLContextKey, baseURL)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			db := &acme.MockDB{
				MockGetCertificateBySerial: func(ctx context.Context, serial string) (*acme.Certificate, error) {
					assert.Equals(t, cert.SerialNumber.String(), serial)
					return &acme.Certificate{
						AccountID: "accountID",
					}, nil
				},
			}
			ca := &mockCA{}
			return test{
				db:         db,
				ca:         ca,
				ctx:        ctx,
				statusCode: 200,
			}
		},
	}
	for name, setup := range tests {
		tc := setup(t)
		t.Run(name, func(t *testing.T) {
			h := &Handler{linker: NewLinker("dns", "acme"), db: tc.db, ca: tc.ca}
			req := httptest.NewRequest("POST", revokeURL, nil)
			req = req.WithContext(tc.ctx)
			w := httptest.NewRecorder()
			h.RevokeCert(w, req)
			res := w.Result()

			assert.Equals(t, res.StatusCode, tc.statusCode)

			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			assert.FatalError(t, err)

			if res.StatusCode >= 400 && assert.NotNil(t, tc.err) {
				var ae acme.Error
				assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &ae))

				assert.Equals(t, ae.Type, tc.err.Type)
				assert.Equals(t, ae.Detail, tc.err.Detail)
				assert.Equals(t, ae.Identifier, tc.err.Identifier)
				assert.Equals(t, ae.Subproblems, tc.err.Subproblems)
				assert.Equals(t, res.Header["Content-Type"], []string{"application/problem+json"})
			} else {
				assert.True(t, bytes.Equal(bytes.TrimSpace(body), []byte{}))
				assert.Equals(t, int64(0), req.ContentLength)
				assert.Equals(t, []string{fmt.Sprintf("<%s/acme/%s/directory>;rel=\"index\"", baseURL.String(), escProvName)}, res.Header["Link"])
			}
		})
	}
}
