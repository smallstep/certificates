package acme

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.step.sm/crypto/jose"

	"github.com/smallstep/assert"
)

type mockClient struct {
	get       func(url string) (*http.Response, error)
	lookupTxt func(name string) ([]string, error)
	tlsDial   func(network, addr string, config *tls.Config) (*tls.Conn, error)
}

func (m *mockClient) Get(url string) (*http.Response, error)  { return m.get(url) }
func (m *mockClient) LookupTxt(name string) ([]string, error) { return m.lookupTxt(name) }
func (m *mockClient) TLSDial(network, addr string, config *tls.Config) (*tls.Conn, error) {
	return m.tlsDial(network, addr, config)
}

func Test_storeError(t *testing.T) {
	type test struct {
		ch          *Challenge
		db          DB
		markInvalid bool
		err         *Error
	}
	err := NewError(ErrorMalformedType, "foo")
	tests := map[string]func(t *testing.T) test{
		"fail/db.UpdateChallenge-error": func(t *testing.T) test {
			ch := &Challenge{
				ID:     "chID",
				Token:  "token",
				Value:  "zap.internal",
				Status: StatusValid,
			}
			return test{
				ch: ch,
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Value, ch.Value)
						assert.Equals(t, updch.Status, StatusValid)

						assert.HasPrefix(t, updch.Error.Err.Error(), err.Err.Error())
						assert.Equals(t, updch.Error.Type, err.Type)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						assert.Equals(t, updch.Error.Status, err.Status)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						return errors.New("force")
					},
				},
				err: NewErrorISE("failure saving error to acme challenge: force"),
			}
		},
		"fail/db.UpdateChallenge-acme-error": func(t *testing.T) test {
			ch := &Challenge{
				ID:     "chID",
				Token:  "token",
				Value:  "zap.internal",
				Status: StatusValid,
			}
			return test{
				ch: ch,
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Value, ch.Value)
						assert.Equals(t, updch.Status, StatusValid)

						assert.HasPrefix(t, updch.Error.Err.Error(), err.Err.Error())
						assert.Equals(t, updch.Error.Type, err.Type)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						assert.Equals(t, updch.Error.Status, err.Status)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						return NewError(ErrorMalformedType, "bar")
					},
				},
				err: NewError(ErrorMalformedType, "failure saving error to acme challenge: bar"),
			}
		},
		"ok": func(t *testing.T) test {
			ch := &Challenge{
				ID:     "chID",
				Token:  "token",
				Value:  "zap.internal",
				Status: StatusValid,
			}
			return test{
				ch: ch,
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Value, ch.Value)
						assert.Equals(t, updch.Status, StatusValid)

						assert.HasPrefix(t, updch.Error.Err.Error(), err.Err.Error())
						assert.Equals(t, updch.Error.Type, err.Type)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						assert.Equals(t, updch.Error.Status, err.Status)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						return nil
					},
				},
			}
		},
		"ok/mark-invalid": func(t *testing.T) test {
			ch := &Challenge{
				ID:     "chID",
				Token:  "token",
				Value:  "zap.internal",
				Status: StatusValid,
			}
			return test{
				ch: ch,
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Value, ch.Value)
						assert.Equals(t, updch.Status, StatusInvalid)

						assert.HasPrefix(t, updch.Error.Err.Error(), err.Err.Error())
						assert.Equals(t, updch.Error.Type, err.Type)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						assert.Equals(t, updch.Error.Status, err.Status)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						return nil
					},
				},
				markInvalid: true,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if err := storeError(context.Background(), tc.db, tc.ch, tc.markInvalid, err); err != nil {
				if assert.NotNil(t, tc.err) {
					switch k := err.(type) {
					case *Error:
						assert.Equals(t, k.Type, tc.err.Type)
						assert.Equals(t, k.Detail, tc.err.Detail)
						assert.Equals(t, k.Status, tc.err.Status)
						assert.Equals(t, k.Err.Error(), tc.err.Err.Error())
						assert.Equals(t, k.Detail, tc.err.Detail)
					default:
						assert.FatalError(t, errors.New("unexpected error type"))
					}
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

func TestKeyAuthorization(t *testing.T) {
	type test struct {
		token string
		jwk   *jose.JSONWebKey
		exp   string
		err   *Error
	}
	tests := map[string]func(t *testing.T) test{
		"fail/jwk-thumbprint-error": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			jwk.Key = "foo"
			return test{
				token: "1234",
				jwk:   jwk,
				err:   NewErrorISE("error generating JWK thumbprint: square/go-jose: unknown key type 'string'"),
			}
		},
		"ok": func(t *testing.T) test {
			token := "1234"
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			thumbprint, err := jwk.Thumbprint(crypto.SHA256)
			assert.FatalError(t, err)
			encPrint := base64.RawURLEncoding.EncodeToString(thumbprint)
			return test{
				token: token,
				jwk:   jwk,
				exp:   fmt.Sprintf("%s.%s", token, encPrint),
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if ka, err := KeyAuthorization(tc.token, tc.jwk); err != nil {
				if assert.NotNil(t, tc.err) {
					switch k := err.(type) {
					case *Error:
						assert.Equals(t, k.Type, tc.err.Type)
						assert.Equals(t, k.Detail, tc.err.Detail)
						assert.Equals(t, k.Status, tc.err.Status)
						assert.Equals(t, k.Err.Error(), tc.err.Err.Error())
						assert.Equals(t, k.Detail, tc.err.Detail)
					default:
						assert.FatalError(t, errors.New("unexpected error type"))
					}
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, tc.exp, ka)
				}
			}
		})
	}
}

func TestChallenge_Validate(t *testing.T) {
	type test struct {
		ch  *Challenge
		vc  Client
		jwk *jose.JSONWebKey
		db  DB
		srv *httptest.Server
		err *Error
	}
	tests := map[string]func(t *testing.T) test{
		"ok/already-valid": func(t *testing.T) test {
			ch := &Challenge{
				Status: StatusValid,
			}
			return test{
				ch: ch,
			}
		},
		"fail/already-invalid": func(t *testing.T) test {
			ch := &Challenge{
				Status: StatusInvalid,
			}
			return test{
				ch: ch,
			}
		},
		"fail/unexpected-type": func(t *testing.T) test {
			ch := &Challenge{
				Status: StatusPending,
				Type:   "foo",
			}
			return test{
				ch:  ch,
				err: NewErrorISE("unexpected challenge type 'foo'"),
			}
		},
		"fail/http-01": func(t *testing.T) test {
			ch := &Challenge{
				ID:     "chID",
				Status: StatusPending,
				Type:   "http-01",
				Token:  "token",
				Value:  "zap.internal",
			}

			return test{
				ch: ch,
				vc: &mockClient{
					get: func(url string) (*http.Response, error) {
						return nil, errors.New("force")
					},
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Type, ch.Type)
						assert.Equals(t, updch.Status, ch.Status)
						assert.Equals(t, updch.Value, ch.Value)

						err := NewError(ErrorConnectionType, "error doing http GET for url http://zap.internal/.well-known/acme-challenge/%s: force", ch.Token)
						assert.HasPrefix(t, updch.Error.Err.Error(), err.Err.Error())
						assert.Equals(t, updch.Error.Type, err.Type)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						assert.Equals(t, updch.Error.Status, err.Status)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						return errors.New("force")
					},
				},
				err: NewErrorISE("failure saving error to acme challenge: force"),
			}
		},
		"ok/http-01": func(t *testing.T) test {
			ch := &Challenge{
				ID:     "chID",
				Status: StatusPending,
				Type:   "http-01",
				Token:  "token",
				Value:  "zap.internal",
			}

			return test{
				ch: ch,
				vc: &mockClient{
					get: func(url string) (*http.Response, error) {
						return nil, errors.New("force")
					},
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Type, ch.Type)
						assert.Equals(t, updch.Status, ch.Status)
						assert.Equals(t, updch.Value, ch.Value)

						err := NewError(ErrorConnectionType, "error doing http GET for url http://zap.internal/.well-known/acme-challenge/%s: force", ch.Token)
						assert.HasPrefix(t, updch.Error.Err.Error(), err.Err.Error())
						assert.Equals(t, updch.Error.Type, err.Type)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						assert.Equals(t, updch.Error.Status, err.Status)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						return nil
					},
				},
			}
		},
		"fail/dns-01": func(t *testing.T) test {
			ch := &Challenge{
				ID:     "chID",
				Type:   "dns-01",
				Status: StatusPending,
				Token:  "token",
				Value:  "zap.internal",
			}

			return test{
				ch: ch,
				vc: &mockClient{
					lookupTxt: func(url string) ([]string, error) {
						return nil, errors.New("force")
					},
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Type, ch.Type)
						assert.Equals(t, updch.Status, ch.Status)
						assert.Equals(t, updch.Value, ch.Value)

						err := NewError(ErrorDNSType, "error looking up TXT records for domain %s: force", ch.Value)

						assert.HasPrefix(t, updch.Error.Err.Error(), err.Err.Error())
						assert.Equals(t, updch.Error.Type, err.Type)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						assert.Equals(t, updch.Error.Status, err.Status)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						return errors.New("force")
					},
				},
				err: NewErrorISE("failure saving error to acme challenge: force"),
			}
		},
		"ok/dns-01": func(t *testing.T) test {
			ch := &Challenge{
				ID:     "chID",
				Type:   "dns-01",
				Status: StatusPending,
				Token:  "token",
				Value:  "zap.internal",
			}

			return test{
				ch: ch,
				vc: &mockClient{
					lookupTxt: func(url string) ([]string, error) {
						return nil, errors.New("force")
					},
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Type, ch.Type)
						assert.Equals(t, updch.Status, ch.Status)
						assert.Equals(t, updch.Value, ch.Value)

						err := NewError(ErrorDNSType, "error looking up TXT records for domain %s: force", ch.Value)

						assert.HasPrefix(t, updch.Error.Err.Error(), err.Err.Error())
						assert.Equals(t, updch.Error.Type, err.Type)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						assert.Equals(t, updch.Error.Status, err.Status)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						return nil
					},
				},
			}
		},
		"fail/tls-alpn-01": func(t *testing.T) test {
			ch := &Challenge{
				ID:     "chID",
				Token:  "token",
				Type:   "tls-alpn-01",
				Status: StatusPending,
				Value:  "zap.internal",
			}
			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: func(network, addr string, config *tls.Config) (*tls.Conn, error) {
						return nil, errors.New("force")
					},
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Status, ch.Status)
						assert.Equals(t, updch.Type, ch.Type)
						assert.Equals(t, updch.Value, ch.Value)

						err := NewError(ErrorConnectionType, "error doing TLS dial for %v:443: force", ch.Value)

						assert.HasPrefix(t, updch.Error.Err.Error(), err.Err.Error())
						assert.Equals(t, updch.Error.Type, err.Type)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						assert.Equals(t, updch.Error.Status, err.Status)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						return errors.New("force")
					},
				},
				err: NewErrorISE("failure saving error to acme challenge: force"),
			}
		},
		"ok/tls-alpn-01": func(t *testing.T) test {
			ch := &Challenge{
				ID:     "chID",
				Token:  "token",
				Type:   "tls-alpn-01",
				Status: StatusPending,
				Value:  "zap.internal",
			}

			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			assert.FatalError(t, err)
			expKeyAuthHash := sha256.Sum256([]byte(expKeyAuth))

			cert, err := newTLSALPNValidationCert(expKeyAuthHash[:], false, true, ch.Value)
			assert.FatalError(t, err)

			srv, tlsDial := newTestTLSALPNServer(cert)
			srv.Start()

			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: tlsDial,
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Status, ch.Status)
						assert.Equals(t, updch.Type, ch.Type)
						assert.Equals(t, updch.Value, ch.Value)
						assert.Equals(t, updch.Error, nil)
						return nil
					},
				},
				srv: srv,
				jwk: jwk,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)

			if tc.srv != nil {
				defer tc.srv.Close()
			}

			ctx := NewClientContext(context.Background(), tc.vc)
			if err := tc.ch.Validate(ctx, tc.db, tc.jwk); err != nil {
				if assert.NotNil(t, tc.err) {
					switch k := err.(type) {
					case *Error:
						assert.Equals(t, k.Type, tc.err.Type)
						assert.Equals(t, k.Detail, tc.err.Detail)
						assert.Equals(t, k.Status, tc.err.Status)
						assert.Equals(t, k.Err.Error(), tc.err.Err.Error())
						assert.Equals(t, k.Detail, tc.err.Detail)
					default:
						assert.FatalError(t, errors.New("unexpected error type"))
					}
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

type errReader int

func (errReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("force")
}
func (errReader) Close() error {
	return nil
}

func TestHTTP01Validate(t *testing.T) {
	type test struct {
		vc  Client
		ch  *Challenge
		jwk *jose.JSONWebKey
		db  DB
		err *Error
	}
	tests := map[string]func(t *testing.T) test{
		"fail/http-get-error-store-error": func(t *testing.T) test {
			ch := &Challenge{
				ID:     "chID",
				Token:  "token",
				Value:  "zap.internal",
				Status: StatusPending,
			}

			return test{
				ch: ch,
				vc: &mockClient{
					get: func(url string) (*http.Response, error) {
						return nil, errors.New("force")
					},
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Value, ch.Value)
						assert.Equals(t, updch.Status, StatusPending)

						err := NewError(ErrorConnectionType, "error doing http GET for url http://zap.internal/.well-known/acme-challenge/%s: force", ch.Token)
						assert.HasPrefix(t, updch.Error.Err.Error(), err.Err.Error())
						assert.Equals(t, updch.Error.Type, err.Type)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						assert.Equals(t, updch.Error.Status, err.Status)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						return errors.New("force")
					},
				},
				err: NewErrorISE("failure saving error to acme challenge: force"),
			}
		},
		"ok/http-get-error": func(t *testing.T) test {
			ch := &Challenge{
				ID:     "chID",
				Token:  "token",
				Value:  "zap.internal",
				Status: StatusPending,
			}

			return test{
				ch: ch,
				vc: &mockClient{
					get: func(url string) (*http.Response, error) {
						return nil, errors.New("force")
					},
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Value, ch.Value)
						assert.Equals(t, updch.Status, StatusPending)

						err := NewError(ErrorConnectionType, "error doing http GET for url http://zap.internal/.well-known/acme-challenge/%s: force", ch.Token)
						assert.HasPrefix(t, updch.Error.Err.Error(), err.Err.Error())
						assert.Equals(t, updch.Error.Type, err.Type)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						assert.Equals(t, updch.Error.Status, err.Status)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						return nil
					},
				},
			}
		},
		"fail/http-get->=400-store-error": func(t *testing.T) test {
			ch := &Challenge{
				ID:     "chID",
				Token:  "token",
				Value:  "zap.internal",
				Status: StatusPending,
			}

			return test{
				ch: ch,
				vc: &mockClient{
					get: func(url string) (*http.Response, error) {
						return &http.Response{
							StatusCode: http.StatusBadRequest,
							Body:       errReader(0),
						}, nil
					},
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Value, ch.Value)
						assert.Equals(t, updch.Status, StatusPending)

						err := NewError(ErrorConnectionType, "error doing http GET for url http://zap.internal/.well-known/acme-challenge/%s with status code 400", ch.Token)
						assert.HasPrefix(t, updch.Error.Err.Error(), err.Err.Error())
						assert.Equals(t, updch.Error.Type, err.Type)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						assert.Equals(t, updch.Error.Status, err.Status)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						return errors.New("force")
					},
				},
				err: NewErrorISE("failure saving error to acme challenge: force"),
			}
		},
		"ok/http-get->=400": func(t *testing.T) test {
			ch := &Challenge{
				ID:     "chID",
				Token:  "token",
				Value:  "zap.internal",
				Status: StatusPending,
			}

			return test{
				ch: ch,
				vc: &mockClient{
					get: func(url string) (*http.Response, error) {
						return &http.Response{
							StatusCode: http.StatusBadRequest,
							Body:       errReader(0),
						}, nil
					},
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Value, ch.Value)
						assert.Equals(t, updch.Status, StatusPending)

						err := NewError(ErrorConnectionType, "error doing http GET for url http://zap.internal/.well-known/acme-challenge/%s with status code 400", ch.Token)
						assert.HasPrefix(t, updch.Error.Err.Error(), err.Err.Error())
						assert.Equals(t, updch.Error.Type, err.Type)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						assert.Equals(t, updch.Error.Status, err.Status)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						return nil
					},
				},
			}
		},
		"fail/read-body": func(t *testing.T) test {
			ch := &Challenge{
				ID:     "chID",
				Token:  "token",
				Value:  "zap.internal",
				Status: StatusPending,
			}

			return test{
				ch: ch,
				vc: &mockClient{
					get: func(url string) (*http.Response, error) {
						return &http.Response{
							Body: errReader(0),
						}, nil
					},
				},
				err: NewErrorISE("error reading response body for url http://zap.internal/.well-known/acme-challenge/%s: force", ch.Token),
			}
		},
		"fail/key-auth-gen-error": func(t *testing.T) test {
			ch := &Challenge{
				ID:     "chID",
				Token:  "token",
				Value:  "zap.internal",
				Status: StatusPending,
			}

			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			jwk.Key = "foo"
			return test{
				ch: ch,
				vc: &mockClient{
					get: func(url string) (*http.Response, error) {
						return &http.Response{
							Body: io.NopCloser(bytes.NewBufferString("foo")),
						}, nil
					},
				},
				jwk: jwk,
				err: NewErrorISE("error generating JWK thumbprint: square/go-jose: unknown key type 'string'"),
			}
		},
		"ok/key-auth-mismatch": func(t *testing.T) test {
			ch := &Challenge{
				ID:     "chID",
				Token:  "token",
				Value:  "zap.internal",
				Status: StatusPending,
			}

			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			assert.FatalError(t, err)
			return test{
				ch: ch,
				vc: &mockClient{
					get: func(url string) (*http.Response, error) {
						return &http.Response{
							Body: io.NopCloser(bytes.NewBufferString("foo")),
						}, nil
					},
				},
				jwk: jwk,
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Value, ch.Value)
						assert.Equals(t, updch.Status, StatusInvalid)

						err := NewError(ErrorRejectedIdentifierType,
							"keyAuthorization does not match; expected %s, but got foo", expKeyAuth)
						assert.HasPrefix(t, updch.Error.Err.Error(), err.Err.Error())
						assert.Equals(t, updch.Error.Type, err.Type)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						assert.Equals(t, updch.Error.Status, err.Status)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						return nil
					},
				},
			}
		},
		"fail/key-auth-mismatch-store-error": func(t *testing.T) test {
			ch := &Challenge{
				ID:     "chID",
				Token:  "token",
				Value:  "zap.internal",
				Status: StatusPending,
			}

			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			assert.FatalError(t, err)
			return test{
				ch: ch,
				vc: &mockClient{
					get: func(url string) (*http.Response, error) {
						return &http.Response{
							Body: io.NopCloser(bytes.NewBufferString("foo")),
						}, nil
					},
				},
				jwk: jwk,
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Value, ch.Value)
						assert.Equals(t, updch.Status, StatusInvalid)

						err := NewError(ErrorRejectedIdentifierType,
							"keyAuthorization does not match; expected %s, but got foo", expKeyAuth)
						assert.HasPrefix(t, updch.Error.Err.Error(), err.Err.Error())
						assert.Equals(t, updch.Error.Type, err.Type)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						assert.Equals(t, updch.Error.Status, err.Status)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						return errors.New("force")
					},
				},
				err: NewErrorISE("failure saving error to acme challenge: force"),
			}
		},
		"fail/update-challenge-error": func(t *testing.T) test {
			ch := &Challenge{
				ID:     "chID",
				Token:  "token",
				Value:  "zap.internal",
				Status: StatusPending,
			}

			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			assert.FatalError(t, err)
			return test{
				ch: ch,
				vc: &mockClient{
					get: func(url string) (*http.Response, error) {
						return &http.Response{
							Body: io.NopCloser(bytes.NewBufferString(expKeyAuth)),
						}, nil
					},
				},
				jwk: jwk,
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Value, ch.Value)
						assert.Equals(t, updch.Status, StatusValid)
						assert.Equals(t, updch.Error, nil)
						va, err := time.Parse(time.RFC3339, updch.ValidatedAt)
						assert.FatalError(t, err)
						now := clock.Now()
						assert.True(t, va.Add(-time.Minute).Before(now))
						assert.True(t, va.Add(time.Minute).After(now))

						return errors.New("force")
					},
				},
				err: NewErrorISE("error updating challenge: force"),
			}
		},
		"ok": func(t *testing.T) test {
			ch := &Challenge{
				ID:     "chID",
				Token:  "token",
				Value:  "zap.internal",
				Status: StatusPending,
			}

			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			assert.FatalError(t, err)
			return test{
				ch: ch,
				vc: &mockClient{
					get: func(url string) (*http.Response, error) {
						return &http.Response{
							Body: io.NopCloser(bytes.NewBufferString(expKeyAuth)),
						}, nil
					},
				},
				jwk: jwk,
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Value, ch.Value)

						assert.Equals(t, updch.Status, StatusValid)
						assert.Equals(t, updch.Error, nil)
						va, err := time.Parse(time.RFC3339, updch.ValidatedAt)
						assert.FatalError(t, err)
						now := clock.Now()
						assert.True(t, va.Add(-time.Minute).Before(now))
						assert.True(t, va.Add(time.Minute).After(now))
						return nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			ctx := NewClientContext(context.Background(), tc.vc)
			if err := http01Validate(ctx, tc.ch, tc.db, tc.jwk); err != nil {
				if assert.NotNil(t, tc.err) {
					switch k := err.(type) {
					case *Error:
						assert.Equals(t, k.Type, tc.err.Type)
						assert.Equals(t, k.Detail, tc.err.Detail)
						assert.Equals(t, k.Status, tc.err.Status)
						assert.Equals(t, k.Err.Error(), tc.err.Err.Error())
						assert.Equals(t, k.Detail, tc.err.Detail)
					default:
						assert.FatalError(t, errors.New("unexpected error type"))
					}
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

func TestDNS01Validate(t *testing.T) {
	fulldomain := "*.zap.internal"
	domain := strings.TrimPrefix(fulldomain, "*.")
	type test struct {
		vc  Client
		ch  *Challenge
		jwk *jose.JSONWebKey
		db  DB
		err *Error
	}
	tests := map[string]func(t *testing.T) test{
		"fail/lookupTXT-store-error": func(t *testing.T) test {
			ch := &Challenge{
				ID:     "chID",
				Token:  "token",
				Value:  fulldomain,
				Status: StatusPending,
			}

			return test{
				ch: ch,
				vc: &mockClient{
					lookupTxt: func(url string) ([]string, error) {
						return nil, errors.New("force")
					},
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Value, ch.Value)
						assert.Equals(t, updch.Status, StatusPending)

						err := NewError(ErrorDNSType, "error looking up TXT records for domain %s: force", domain)

						assert.HasPrefix(t, updch.Error.Err.Error(), err.Err.Error())
						assert.Equals(t, updch.Error.Type, err.Type)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						assert.Equals(t, updch.Error.Status, err.Status)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						return errors.New("force")
					},
				},
				err: NewErrorISE("failure saving error to acme challenge: force"),
			}
		},
		"ok/lookupTXT-error": func(t *testing.T) test {
			ch := &Challenge{
				ID:     "chID",
				Token:  "token",
				Value:  fulldomain,
				Status: StatusPending,
			}

			return test{
				ch: ch,
				vc: &mockClient{
					lookupTxt: func(url string) ([]string, error) {
						return nil, errors.New("force")
					},
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Value, ch.Value)
						assert.Equals(t, updch.Status, StatusPending)

						err := NewError(ErrorDNSType, "error looking up TXT records for domain %s: force", domain)

						assert.HasPrefix(t, updch.Error.Err.Error(), err.Err.Error())
						assert.Equals(t, updch.Error.Type, err.Type)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						assert.Equals(t, updch.Error.Status, err.Status)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						return nil
					},
				},
			}
		},
		"fail/key-auth-gen-error": func(t *testing.T) test {
			ch := &Challenge{
				ID:     "chID",
				Token:  "token",
				Value:  fulldomain,
				Status: StatusPending,
			}

			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			jwk.Key = "foo"

			return test{
				ch: ch,
				vc: &mockClient{
					lookupTxt: func(url string) ([]string, error) {
						return []string{"foo"}, nil
					},
				},
				jwk: jwk,
				err: NewErrorISE("error generating JWK thumbprint: square/go-jose: unknown key type 'string'"),
			}
		},
		"fail/key-auth-mismatch-store-error": func(t *testing.T) test {
			ch := &Challenge{
				ID:     "chID",
				Token:  "token",
				Value:  fulldomain,
				Status: StatusPending,
			}

			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			assert.FatalError(t, err)

			return test{
				ch: ch,
				vc: &mockClient{
					lookupTxt: func(url string) ([]string, error) {
						return []string{"foo", "bar"}, nil
					},
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Value, ch.Value)
						assert.Equals(t, updch.Status, StatusPending)

						err := NewError(ErrorRejectedIdentifierType, "keyAuthorization does not match; expected %s, but got %s", expKeyAuth, []string{"foo", "bar"})

						assert.HasPrefix(t, updch.Error.Err.Error(), err.Err.Error())
						assert.Equals(t, updch.Error.Type, err.Type)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						assert.Equals(t, updch.Error.Status, err.Status)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						return errors.New("force")
					},
				},
				jwk: jwk,
				err: NewErrorISE("failure saving error to acme challenge: force"),
			}
		},
		"ok/key-auth-mismatch-store-error": func(t *testing.T) test {
			ch := &Challenge{
				ID:     "chID",
				Token:  "token",
				Value:  fulldomain,
				Status: StatusPending,
			}

			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			assert.FatalError(t, err)

			return test{
				ch: ch,
				vc: &mockClient{
					lookupTxt: func(url string) ([]string, error) {
						return []string{"foo", "bar"}, nil
					},
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Value, ch.Value)
						assert.Equals(t, updch.Status, StatusPending)

						err := NewError(ErrorRejectedIdentifierType, "keyAuthorization does not match; expected %s, but got %s", expKeyAuth, []string{"foo", "bar"})

						assert.HasPrefix(t, updch.Error.Err.Error(), err.Err.Error())
						assert.Equals(t, updch.Error.Type, err.Type)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						assert.Equals(t, updch.Error.Status, err.Status)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						return nil
					},
				},
				jwk: jwk,
			}
		},
		"fail/update-challenge-error": func(t *testing.T) test {
			ch := &Challenge{
				ID:     "chID",
				Token:  "token",
				Value:  fulldomain,
				Status: StatusPending,
			}

			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			assert.FatalError(t, err)
			h := sha256.Sum256([]byte(expKeyAuth))
			expected := base64.RawURLEncoding.EncodeToString(h[:])

			return test{
				ch: ch,
				vc: &mockClient{
					lookupTxt: func(url string) ([]string, error) {
						return []string{"foo", expected}, nil
					},
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Value, ch.Value)
						assert.Equals(t, updch.Status, StatusValid)

						assert.Equals(t, updch.Status, StatusValid)
						assert.Equals(t, updch.Error, nil)
						va, err := time.Parse(time.RFC3339, updch.ValidatedAt)
						assert.FatalError(t, err)
						now := clock.Now()
						assert.True(t, va.Add(-time.Minute).Before(now))
						assert.True(t, va.Add(time.Minute).After(now))

						return errors.New("force")
					},
				},
				jwk: jwk,
				err: NewErrorISE("error updating challenge: force"),
			}
		},
		"ok": func(t *testing.T) test {
			ch := &Challenge{
				ID:     "chID",
				Token:  "token",
				Value:  fulldomain,
				Status: StatusPending,
			}

			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			assert.FatalError(t, err)
			h := sha256.Sum256([]byte(expKeyAuth))
			expected := base64.RawURLEncoding.EncodeToString(h[:])

			return test{
				ch: ch,
				vc: &mockClient{
					lookupTxt: func(url string) ([]string, error) {
						return []string{"foo", expected}, nil
					},
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Value, ch.Value)
						assert.Equals(t, updch.Status, StatusValid)

						assert.Equals(t, updch.Status, StatusValid)
						assert.Equals(t, updch.Error, nil)
						va, err := time.Parse(time.RFC3339, updch.ValidatedAt)
						assert.FatalError(t, err)
						now := clock.Now()
						assert.True(t, va.Add(-time.Minute).Before(now))
						assert.True(t, va.Add(time.Minute).After(now))

						return nil
					},
				},
				jwk: jwk,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			ctx := NewClientContext(context.Background(), tc.vc)
			if err := dns01Validate(ctx, tc.ch, tc.db, tc.jwk); err != nil {
				if assert.NotNil(t, tc.err) {
					switch k := err.(type) {
					case *Error:
						assert.Equals(t, k.Type, tc.err.Type)
						assert.Equals(t, k.Detail, tc.err.Detail)
						assert.Equals(t, k.Status, tc.err.Status)
						assert.Equals(t, k.Err.Error(), tc.err.Err.Error())
						assert.Equals(t, k.Detail, tc.err.Detail)
					default:
						assert.FatalError(t, errors.New("unexpected error type"))
					}
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

type tlsDialer func(network, addr string, config *tls.Config) (conn *tls.Conn, err error)

func newTestTLSALPNServer(validationCert *tls.Certificate) (*httptest.Server, tlsDialer) {
	srv := httptest.NewUnstartedServer(http.NewServeMux())

	srv.Config.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){
		"acme-tls/1": func(_ *http.Server, conn *tls.Conn, _ http.Handler) {
			// no-op
		},
		"http/1.1": func(_ *http.Server, conn *tls.Conn, _ http.Handler) {
			panic("unexpected http/1.1 next proto")
		},
	}

	srv.TLS = &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if len(hello.SupportedProtos) == 1 && hello.SupportedProtos[0] == "acme-tls/1" {
				return validationCert, nil
			}
			return nil, nil
		},
		NextProtos: []string{
			"acme-tls/1",
			"http/1.1",
		},
	}

	srv.Listener = tls.NewListener(srv.Listener, srv.TLS)
	//srv.Config.ErrorLog = log.New(ioutil.Discard, "", 0) // hush

	return srv, func(network, addr string, config *tls.Config) (conn *tls.Conn, err error) {
		return tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", srv.Listener.Addr().String(), config)
	}
}

// noopConn is a mock net.Conn that does nothing.
type noopConn struct{}

func (c *noopConn) Read(_ []byte) (n int, err error)   { return 0, io.EOF }
func (c *noopConn) Write(_ []byte) (n int, err error)  { return 0, io.EOF }
func (c *noopConn) Close() error                       { return nil }
func (c *noopConn) LocalAddr() net.Addr                { return &net.IPAddr{IP: net.IPv4zero, Zone: ""} }
func (c *noopConn) RemoteAddr() net.Addr               { return &net.IPAddr{IP: net.IPv4zero, Zone: ""} }
func (c *noopConn) SetDeadline(t time.Time) error      { return nil }
func (c *noopConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *noopConn) SetWriteDeadline(t time.Time) error { return nil }

func newTLSALPNValidationCert(keyAuthHash []byte, obsoleteOID, critical bool, names ...string) (*tls.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1337),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, 1),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              names,
	}

	if keyAuthHash != nil {
		oid := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}
		if obsoleteOID {
			oid = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 30, 1}
		}

		keyAuthHashEnc, _ := asn1.Marshal(keyAuthHash)

		certTemplate.ExtraExtensions = []pkix.Extension{
			{
				Id:       oid,
				Critical: critical,
				Value:    keyAuthHashEnc,
			},
		}
	}

	cert, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, privateKey.Public(), privateKey)
	if err != nil {
		return nil, err
	}

	return &tls.Certificate{
		PrivateKey:  privateKey,
		Certificate: [][]byte{cert},
	}, nil
}

func TestTLSALPN01Validate(t *testing.T) {
	makeTLSCh := func() *Challenge {
		return &Challenge{
			ID:     "chID",
			Token:  "token",
			Type:   "tls-alpn-01",
			Status: StatusPending,
			Value:  "zap.internal",
		}
	}
	type test struct {
		vc  Client
		ch  *Challenge
		jwk *jose.JSONWebKey
		db  DB
		srv *httptest.Server
		err *Error
	}
	tests := map[string]func(t *testing.T) test{
		"fail/tlsDial-store-error": func(t *testing.T) test {
			ch := makeTLSCh()
			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: func(network, addr string, config *tls.Config) (*tls.Conn, error) {
						return nil, errors.New("force")
					},
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Status, ch.Status)
						assert.Equals(t, updch.Type, ch.Type)
						assert.Equals(t, updch.Value, ch.Value)

						err := NewError(ErrorConnectionType, "error doing TLS dial for %v:443: force", ch.Value)

						assert.HasPrefix(t, updch.Error.Err.Error(), err.Err.Error())
						assert.Equals(t, updch.Error.Type, err.Type)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						assert.Equals(t, updch.Error.Status, err.Status)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						return errors.New("force")
					},
				},
				err: NewErrorISE("failure saving error to acme challenge: force"),
			}
		},
		"ok/tlsDial-error": func(t *testing.T) test {
			ch := makeTLSCh()
			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: func(network, addr string, config *tls.Config) (*tls.Conn, error) {
						return nil, errors.New("force")
					},
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Status, ch.Status)
						assert.Equals(t, updch.Type, ch.Type)
						assert.Equals(t, updch.Value, ch.Value)

						err := NewError(ErrorConnectionType, "error doing TLS dial for %v:443: force", ch.Value)

						assert.HasPrefix(t, updch.Error.Err.Error(), err.Err.Error())
						assert.Equals(t, updch.Error.Type, err.Type)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						assert.Equals(t, updch.Error.Status, err.Status)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						return nil
					},
				},
			}
		},
		"ok/tlsDial-timeout": func(t *testing.T) test {
			ch := makeTLSCh()

			srv, tlsDial := newTestTLSALPNServer(nil)
			// srv.Start() - do not start server to cause timeout

			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: tlsDial,
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Status, ch.Status)
						assert.Equals(t, updch.Type, ch.Type)
						assert.Equals(t, updch.Value, ch.Value)

						err := NewError(ErrorConnectionType, "error doing TLS dial for %v:443:", ch.Value)

						assert.HasPrefix(t, updch.Error.Err.Error(), err.Err.Error())
						assert.Equals(t, updch.Error.Type, err.Type)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						assert.Equals(t, updch.Error.Status, err.Status)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						return nil
					},
				},
				srv: srv,
			}
		},
		"ok/no-certificates-error": func(t *testing.T) test {
			ch := makeTLSCh()

			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: func(network, addr string, config *tls.Config) (*tls.Conn, error) {
						return tls.Client(&noopConn{}, config), nil
					},
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Status, StatusInvalid)
						assert.Equals(t, updch.Type, ch.Type)
						assert.Equals(t, updch.Value, ch.Value)

						err := NewError(ErrorRejectedIdentifierType, "tls-alpn-01 challenge for %v resulted in no certificates", ch.Value)

						assert.HasPrefix(t, updch.Error.Err.Error(), err.Err.Error())
						assert.Equals(t, updch.Error.Type, err.Type)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						assert.Equals(t, updch.Error.Status, err.Status)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						return nil
					},
				},
			}
		},
		"fail/no-certificates-store-error": func(t *testing.T) test {
			ch := makeTLSCh()

			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: func(network, addr string, config *tls.Config) (*tls.Conn, error) {
						return tls.Client(&noopConn{}, config), nil
					},
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Status, StatusInvalid)
						assert.Equals(t, updch.Type, ch.Type)
						assert.Equals(t, updch.Value, ch.Value)

						err := NewError(ErrorRejectedIdentifierType, "tls-alpn-01 challenge for %v resulted in no certificates", ch.Value)

						assert.HasPrefix(t, updch.Error.Err.Error(), err.Err.Error())
						assert.Equals(t, updch.Error.Type, err.Type)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						assert.Equals(t, updch.Error.Status, err.Status)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						return errors.New("force")
					},
				},
				err: NewErrorISE("failure saving error to acme challenge: force"),
			}
		},
		"ok/error-no-protocol": func(t *testing.T) test {
			ch := makeTLSCh()

			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)

			srv := httptest.NewTLSServer(nil)

			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: func(network, addr string, config *tls.Config) (*tls.Conn, error) {
						return tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", srv.Listener.Addr().String(), config)
					},
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Status, StatusInvalid)
						assert.Equals(t, updch.Type, ch.Type)
						assert.Equals(t, updch.Value, ch.Value)

						err := NewError(ErrorRejectedIdentifierType, "cannot negotiate ALPN acme-tls/1 protocol for tls-alpn-01 challenge")

						assert.HasPrefix(t, updch.Error.Err.Error(), err.Err.Error())
						assert.Equals(t, updch.Error.Type, err.Type)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						assert.Equals(t, updch.Error.Status, err.Status)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						return nil
					},
				},
				srv: srv,
				jwk: jwk,
			}
		},
		"fail/no-protocol-store-error": func(t *testing.T) test {
			ch := makeTLSCh()

			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)

			srv := httptest.NewTLSServer(nil)

			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: func(network, addr string, config *tls.Config) (*tls.Conn, error) {
						return tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", srv.Listener.Addr().String(), config)
					},
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Status, StatusInvalid)
						assert.Equals(t, updch.Type, ch.Type)
						assert.Equals(t, updch.Value, ch.Value)

						err := NewError(ErrorRejectedIdentifierType, "cannot negotiate ALPN acme-tls/1 protocol for tls-alpn-01 challenge")

						assert.HasPrefix(t, updch.Error.Err.Error(), err.Err.Error())
						assert.Equals(t, updch.Error.Type, err.Type)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						assert.Equals(t, updch.Error.Status, err.Status)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						return errors.New("force")
					},
				},
				srv: srv,
				jwk: jwk,
				err: NewErrorISE("failure saving error to acme challenge: force"),
			}
		},
		"ok/no-names-nor-ips-error": func(t *testing.T) test {
			ch := makeTLSCh()

			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			assert.FatalError(t, err)
			expKeyAuthHash := sha256.Sum256([]byte(expKeyAuth))

			cert, err := newTLSALPNValidationCert(expKeyAuthHash[:], false, true)
			assert.FatalError(t, err)

			srv, tlsDial := newTestTLSALPNServer(cert)
			srv.Start()

			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: tlsDial,
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Status, StatusInvalid)
						assert.Equals(t, updch.Type, ch.Type)
						assert.Equals(t, updch.Value, ch.Value)

						err := NewError(ErrorRejectedIdentifierType, "incorrect certificate for tls-alpn-01 challenge: leaf certificate must contain a single IP address or DNS name, %v", ch.Value)

						assert.HasPrefix(t, updch.Error.Err.Error(), err.Err.Error())
						assert.Equals(t, updch.Error.Type, err.Type)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						assert.Equals(t, updch.Error.Status, err.Status)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						return nil
					},
				},
				srv: srv,
				jwk: jwk,
			}
		},
		"fail/no-names-store-error": func(t *testing.T) test {
			ch := makeTLSCh()

			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			assert.FatalError(t, err)
			expKeyAuthHash := sha256.Sum256([]byte(expKeyAuth))

			cert, err := newTLSALPNValidationCert(expKeyAuthHash[:], false, true)
			assert.FatalError(t, err)

			srv, tlsDial := newTestTLSALPNServer(cert)
			srv.Start()

			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: tlsDial,
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Status, StatusInvalid)
						assert.Equals(t, updch.Type, ch.Type)
						assert.Equals(t, updch.Value, ch.Value)

						err := NewError(ErrorRejectedIdentifierType, "incorrect certificate for tls-alpn-01 challenge: leaf certificate must contain a single IP address or DNS name, %v", ch.Value)

						assert.HasPrefix(t, updch.Error.Err.Error(), err.Err.Error())
						assert.Equals(t, updch.Error.Type, err.Type)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						assert.Equals(t, updch.Error.Status, err.Status)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						return errors.New("force")
					},
				},
				srv: srv,
				jwk: jwk,
				err: NewErrorISE("failure saving error to acme challenge: force"),
			}
		},
		"ok/too-many-names-error": func(t *testing.T) test {
			ch := makeTLSCh()

			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			assert.FatalError(t, err)
			expKeyAuthHash := sha256.Sum256([]byte(expKeyAuth))

			cert, err := newTLSALPNValidationCert(expKeyAuthHash[:], false, true, ch.Value, "other.internal")
			assert.FatalError(t, err)

			srv, tlsDial := newTestTLSALPNServer(cert)
			srv.Start()

			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: tlsDial,
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Status, StatusInvalid)
						assert.Equals(t, updch.Type, ch.Type)
						assert.Equals(t, updch.Value, ch.Value)

						err := NewError(ErrorRejectedIdentifierType, "incorrect certificate for tls-alpn-01 challenge: leaf certificate must contain a single IP address or DNS name, %v", ch.Value)

						assert.HasPrefix(t, updch.Error.Err.Error(), err.Err.Error())
						assert.Equals(t, updch.Error.Type, err.Type)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						assert.Equals(t, updch.Error.Status, err.Status)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						return nil
					},
				},
				srv: srv,
				jwk: jwk,
			}
		},
		"ok/wrong-name": func(t *testing.T) test {
			ch := makeTLSCh()

			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			assert.FatalError(t, err)
			expKeyAuthHash := sha256.Sum256([]byte(expKeyAuth))

			cert, err := newTLSALPNValidationCert(expKeyAuthHash[:], false, true, "other.internal")
			assert.FatalError(t, err)

			srv, tlsDial := newTestTLSALPNServer(cert)
			srv.Start()

			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: tlsDial,
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Status, StatusInvalid)
						assert.Equals(t, updch.Type, ch.Type)
						assert.Equals(t, updch.Value, ch.Value)

						err := NewError(ErrorRejectedIdentifierType, "incorrect certificate for tls-alpn-01 challenge: leaf certificate must contain a single IP address or DNS name, %v", ch.Value)

						assert.HasPrefix(t, updch.Error.Err.Error(), err.Err.Error())
						assert.Equals(t, updch.Error.Type, err.Type)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						assert.Equals(t, updch.Error.Status, err.Status)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						return nil
					},
				},
				srv: srv,
				jwk: jwk,
			}
		},
		"fail/key-auth-gen-error": func(t *testing.T) test {
			ch := makeTLSCh()

			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			assert.FatalError(t, err)
			expKeyAuthHash := sha256.Sum256([]byte(expKeyAuth))
			jwk.Key = "foo"

			cert, err := newTLSALPNValidationCert(expKeyAuthHash[:], false, true, ch.Value)
			assert.FatalError(t, err)

			srv, tlsDial := newTestTLSALPNServer(cert)
			srv.Start()

			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: tlsDial,
				},
				srv: srv,
				jwk: jwk,
				err: NewErrorISE("error generating JWK thumbprint: square/go-jose: unknown key type 'string'"),
			}
		},
		"ok/error-no-extension": func(t *testing.T) test {
			ch := makeTLSCh()

			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)

			cert, err := newTLSALPNValidationCert(nil, false, true, ch.Value)
			assert.FatalError(t, err)

			srv, tlsDial := newTestTLSALPNServer(cert)
			srv.Start()

			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: tlsDial,
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Status, StatusInvalid)
						assert.Equals(t, updch.Type, ch.Type)
						assert.Equals(t, updch.Value, ch.Value)

						err := NewError(ErrorRejectedIdentifierType, "incorrect certificate for tls-alpn-01 challenge: missing acmeValidationV1 extension")

						assert.HasPrefix(t, updch.Error.Err.Error(), err.Err.Error())
						assert.Equals(t, updch.Error.Type, err.Type)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						assert.Equals(t, updch.Error.Status, err.Status)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						return nil
					},
				},
				srv: srv,
				jwk: jwk,
			}
		},
		"fail/no-extension-store-error": func(t *testing.T) test {
			ch := makeTLSCh()

			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)

			cert, err := newTLSALPNValidationCert(nil, false, true, ch.Value)
			assert.FatalError(t, err)

			srv, tlsDial := newTestTLSALPNServer(cert)
			srv.Start()

			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: tlsDial,
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Status, StatusInvalid)
						assert.Equals(t, updch.Type, ch.Type)
						assert.Equals(t, updch.Value, ch.Value)

						err := NewError(ErrorRejectedIdentifierType, "incorrect certificate for tls-alpn-01 challenge: missing acmeValidationV1 extension")

						assert.HasPrefix(t, updch.Error.Err.Error(), err.Err.Error())
						assert.Equals(t, updch.Error.Type, err.Type)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						assert.Equals(t, updch.Error.Status, err.Status)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						return errors.New("force")
					},
				},
				srv: srv,
				jwk: jwk,
				err: NewErrorISE("failure saving error to acme challenge: force"),
			}
		},
		"ok/error-extension-not-critical": func(t *testing.T) test {
			ch := makeTLSCh()

			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			assert.FatalError(t, err)
			expKeyAuthHash := sha256.Sum256([]byte(expKeyAuth))

			cert, err := newTLSALPNValidationCert(expKeyAuthHash[:], false, false, ch.Value)
			assert.FatalError(t, err)

			srv, tlsDial := newTestTLSALPNServer(cert)
			srv.Start()

			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: tlsDial,
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Status, StatusInvalid)
						assert.Equals(t, updch.Type, ch.Type)
						assert.Equals(t, updch.Value, ch.Value)

						err := NewError(ErrorRejectedIdentifierType, "incorrect certificate for tls-alpn-01 challenge: acmeValidationV1 extension not critical")

						assert.HasPrefix(t, updch.Error.Err.Error(), err.Err.Error())
						assert.Equals(t, updch.Error.Type, err.Type)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						assert.Equals(t, updch.Error.Status, err.Status)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						return nil
					},
				},
				srv: srv,
				jwk: jwk,
			}
		},
		"fail/extension-not-critical-store-error": func(t *testing.T) test {
			ch := makeTLSCh()

			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			assert.FatalError(t, err)
			expKeyAuthHash := sha256.Sum256([]byte(expKeyAuth))

			cert, err := newTLSALPNValidationCert(expKeyAuthHash[:], false, false, ch.Value)
			assert.FatalError(t, err)

			srv, tlsDial := newTestTLSALPNServer(cert)
			srv.Start()

			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: tlsDial,
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Status, StatusInvalid)
						assert.Equals(t, updch.Type, ch.Type)
						assert.Equals(t, updch.Value, ch.Value)

						err := NewError(ErrorRejectedIdentifierType, "incorrect certificate for tls-alpn-01 challenge: acmeValidationV1 extension not critical")

						assert.HasPrefix(t, updch.Error.Err.Error(), err.Err.Error())
						assert.Equals(t, updch.Error.Type, err.Type)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						assert.Equals(t, updch.Error.Status, err.Status)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						return errors.New("force")
					},
				},
				srv: srv,
				jwk: jwk,
				err: NewErrorISE("failure saving error to acme challenge: force"),
			}
		},
		"ok/error-malformed-extension": func(t *testing.T) test {
			ch := makeTLSCh()

			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)

			cert, err := newTLSALPNValidationCert([]byte{1, 2, 3}, false, true, ch.Value)
			assert.FatalError(t, err)

			srv, tlsDial := newTestTLSALPNServer(cert)
			srv.Start()

			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: tlsDial,
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Status, StatusInvalid)
						assert.Equals(t, updch.Type, ch.Type)
						assert.Equals(t, updch.Value, ch.Value)

						err := NewError(ErrorRejectedIdentifierType, "incorrect certificate for tls-alpn-01 challenge: malformed acmeValidationV1 extension value")

						assert.HasPrefix(t, updch.Error.Err.Error(), err.Err.Error())
						assert.Equals(t, updch.Error.Type, err.Type)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						assert.Equals(t, updch.Error.Status, err.Status)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						return nil
					},
				},
				srv: srv,
				jwk: jwk,
			}
		},
		"fail/malformed-extension-store-error": func(t *testing.T) test {
			ch := makeTLSCh()

			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)

			cert, err := newTLSALPNValidationCert([]byte{1, 2, 3}, false, true, ch.Value)
			assert.FatalError(t, err)

			srv, tlsDial := newTestTLSALPNServer(cert)
			srv.Start()

			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: tlsDial,
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Status, StatusInvalid)
						assert.Equals(t, updch.Type, ch.Type)
						assert.Equals(t, updch.Value, ch.Value)

						err := NewError(ErrorRejectedIdentifierType, "incorrect certificate for tls-alpn-01 challenge: malformed acmeValidationV1 extension value")

						assert.HasPrefix(t, updch.Error.Err.Error(), err.Err.Error())
						assert.Equals(t, updch.Error.Type, err.Type)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						assert.Equals(t, updch.Error.Status, err.Status)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						return errors.New("force")
					},
				},
				srv: srv,
				jwk: jwk,
				err: NewErrorISE("failure saving error to acme challenge: force"),
			}
		},
		"ok/error-keyauth-mismatch": func(t *testing.T) test {
			ch := makeTLSCh()

			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			assert.FatalError(t, err)
			expKeyAuthHash := sha256.Sum256([]byte(expKeyAuth))
			incorrectTokenHash := sha256.Sum256([]byte("mismatched"))

			cert, err := newTLSALPNValidationCert(incorrectTokenHash[:], false, true, ch.Value)
			assert.FatalError(t, err)

			srv, tlsDial := newTestTLSALPNServer(cert)
			srv.Start()

			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: tlsDial,
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Status, StatusInvalid)
						assert.Equals(t, updch.Type, ch.Type)
						assert.Equals(t, updch.Value, ch.Value)

						err := NewError(ErrorRejectedIdentifierType, "incorrect certificate for tls-alpn-01 challenge: "+
							"expected acmeValidationV1 extension value %s for this challenge but got %s",
							hex.EncodeToString(expKeyAuthHash[:]), hex.EncodeToString(incorrectTokenHash[:]))

						assert.HasPrefix(t, updch.Error.Err.Error(), err.Err.Error())
						assert.Equals(t, updch.Error.Type, err.Type)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						assert.Equals(t, updch.Error.Status, err.Status)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						return nil
					},
				},
				srv: srv,
				jwk: jwk,
			}
		},
		"fail/keyauth-mismatch-store-error": func(t *testing.T) test {
			ch := makeTLSCh()

			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			assert.FatalError(t, err)
			expKeyAuthHash := sha256.Sum256([]byte(expKeyAuth))
			incorrectTokenHash := sha256.Sum256([]byte("mismatched"))

			cert, err := newTLSALPNValidationCert(incorrectTokenHash[:], false, true, ch.Value)
			assert.FatalError(t, err)

			srv, tlsDial := newTestTLSALPNServer(cert)
			srv.Start()

			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: tlsDial,
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Status, StatusInvalid)
						assert.Equals(t, updch.Type, ch.Type)
						assert.Equals(t, updch.Value, ch.Value)

						err := NewError(ErrorRejectedIdentifierType, "incorrect certificate for tls-alpn-01 challenge: "+
							"expected acmeValidationV1 extension value %s for this challenge but got %s",
							hex.EncodeToString(expKeyAuthHash[:]), hex.EncodeToString(incorrectTokenHash[:]))

						assert.HasPrefix(t, updch.Error.Err.Error(), err.Err.Error())
						assert.Equals(t, updch.Error.Type, err.Type)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						assert.Equals(t, updch.Error.Status, err.Status)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						return errors.New("force")
					},
				},
				srv: srv,
				jwk: jwk,
				err: NewErrorISE("failure saving error to acme challenge: force"),
			}
		},
		"ok/error-obsolete-oid": func(t *testing.T) test {
			ch := makeTLSCh()

			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			assert.FatalError(t, err)
			expKeyAuthHash := sha256.Sum256([]byte(expKeyAuth))

			cert, err := newTLSALPNValidationCert(expKeyAuthHash[:], true, true, ch.Value)
			assert.FatalError(t, err)

			srv, tlsDial := newTestTLSALPNServer(cert)
			srv.Start()

			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: tlsDial,
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Status, StatusInvalid)
						assert.Equals(t, updch.Type, ch.Type)
						assert.Equals(t, updch.Value, ch.Value)

						err := NewError(ErrorRejectedIdentifierType, "incorrect certificate for tls-alpn-01 challenge: "+
							"obsolete id-pe-acmeIdentifier in acmeValidationV1 extension")

						assert.HasPrefix(t, updch.Error.Err.Error(), err.Err.Error())
						assert.Equals(t, updch.Error.Type, err.Type)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						assert.Equals(t, updch.Error.Status, err.Status)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						return nil
					},
				},
				srv: srv,
				jwk: jwk,
			}
		},
		"fail/obsolete-oid-store-error": func(t *testing.T) test {
			ch := makeTLSCh()

			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			assert.FatalError(t, err)
			expKeyAuthHash := sha256.Sum256([]byte(expKeyAuth))

			cert, err := newTLSALPNValidationCert(expKeyAuthHash[:], true, true, ch.Value)
			assert.FatalError(t, err)

			srv, tlsDial := newTestTLSALPNServer(cert)
			srv.Start()

			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: tlsDial,
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Status, StatusInvalid)
						assert.Equals(t, updch.Type, ch.Type)
						assert.Equals(t, updch.Value, ch.Value)

						err := NewError(ErrorRejectedIdentifierType, "incorrect certificate for tls-alpn-01 challenge: "+
							"obsolete id-pe-acmeIdentifier in acmeValidationV1 extension")

						assert.HasPrefix(t, updch.Error.Err.Error(), err.Err.Error())
						assert.Equals(t, updch.Error.Type, err.Type)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						assert.Equals(t, updch.Error.Status, err.Status)
						assert.Equals(t, updch.Error.Detail, err.Detail)
						return errors.New("force")
					},
				},
				srv: srv,
				jwk: jwk,
				err: NewErrorISE("failure saving error to acme challenge: force"),
			}
		},
		"ok": func(t *testing.T) test {
			ch := makeTLSCh()

			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			assert.FatalError(t, err)
			expKeyAuthHash := sha256.Sum256([]byte(expKeyAuth))

			cert, err := newTLSALPNValidationCert(expKeyAuthHash[:], false, true, ch.Value)
			assert.FatalError(t, err)

			srv, tlsDial := newTestTLSALPNServer(cert)
			srv.Start()

			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: tlsDial,
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Status, StatusValid)
						assert.Equals(t, updch.Type, ch.Type)
						assert.Equals(t, updch.Value, ch.Value)
						assert.Equals(t, updch.Error, nil)
						return nil
					},
				},
				srv: srv,
				jwk: jwk,
			}
		},
		"ok/ip": func(t *testing.T) test {
			ch := makeTLSCh()
			ch.Value = "127.0.0.1"

			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			assert.FatalError(t, err)
			expKeyAuthHash := sha256.Sum256([]byte(expKeyAuth))

			cert, err := newTLSALPNValidationCert(expKeyAuthHash[:], false, true, ch.Value)
			assert.FatalError(t, err)

			srv, tlsDial := newTestTLSALPNServer(cert)
			srv.Start()

			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: tlsDial,
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equals(t, updch.ID, ch.ID)
						assert.Equals(t, updch.Token, ch.Token)
						assert.Equals(t, updch.Status, StatusValid)
						assert.Equals(t, updch.Type, ch.Type)
						assert.Equals(t, updch.Value, ch.Value)
						assert.Equals(t, updch.Error, nil)
						return nil
					},
				},
				srv: srv,
				jwk: jwk,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)

			if tc.srv != nil {
				defer tc.srv.Close()
			}

			ctx := NewClientContext(context.Background(), tc.vc)
			if err := tlsalpn01Validate(ctx, tc.ch, tc.db, tc.jwk); err != nil {
				if assert.NotNil(t, tc.err) {
					switch k := err.(type) {
					case *Error:
						assert.Equals(t, k.Type, tc.err.Type)
						assert.Equals(t, k.Detail, tc.err.Detail)
						assert.Equals(t, k.Status, tc.err.Status)
						assert.Equals(t, k.Err.Error(), tc.err.Err.Error())
						assert.Equals(t, k.Detail, tc.err.Detail)
					default:
						assert.FatalError(t, errors.New("unexpected error type"))
					}
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

func Test_reverseAddr(t *testing.T) {
	type args struct {
		ip net.IP
	}
	tests := []struct {
		name     string
		args     args
		wantArpa string
	}{
		{
			name: "ok/ipv4",
			args: args{
				ip: net.ParseIP("127.0.0.1"),
			},
			wantArpa: "1.0.0.127.in-addr.arpa.",
		},
		{
			name: "ok/ipv6",
			args: args{
				ip: net.ParseIP("2001:db8::567:89ab"),
			},
			wantArpa: "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotArpa := reverseAddr(tt.args.ip); gotArpa != tt.wantArpa {
				t.Errorf("reverseAddr() = %v, want %v", gotArpa, tt.wantArpa)
			}
		})
	}
}

func Test_serverName(t *testing.T) {
	type args struct {
		ch *Challenge
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "ok/dns",
			args: args{
				ch: &Challenge{
					Value: "example.com",
				},
			},
			want: "example.com",
		},
		{
			name: "ok/ipv4",
			args: args{
				ch: &Challenge{
					Value: "127.0.0.1",
				},
			},
			want: "1.0.0.127.in-addr.arpa.",
		},
		{
			name: "ok/ipv6",
			args: args{
				ch: &Challenge{
					Value: "2001:db8::567:89ab",
				},
			},
			want: "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := serverName(tt.args.ch); got != tt.want {
				t.Errorf("serverName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_http01ChallengeHost(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{
			name:  "dns",
			value: "www.example.com",
			want:  "www.example.com",
		},
		{
			name:  "ipv4",
			value: "127.0.0.1",
			want:  "127.0.0.1",
		},
		{
			name:  "ipv6",
			value: "::1",
			want:  "[::1]",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := http01ChallengeHost(tt.value); got != tt.want {
				t.Errorf("http01ChallengeHost() = %v, want %v", got, tt.want)
			}
		})
	}
}
