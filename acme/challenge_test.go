package acme

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/minica"

	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/provisioner"
)

type mockClient struct {
	get       func(url string) (*http.Response, error)
	lookupTxt func(name string) ([]string, error)
	tlsDial   func(network, addr string, config *tls.Config) (*tls.Conn, error)
}

func (m *mockClient) Get(url string) (*http.Response, error)  { return m.get(url) }
func (m *mockClient) LookupTxt(name string) ([]string, error) { return m.lookupTxt(name) }
func (m *mockClient) TLSDial(network, addr string, tlsConfig *tls.Config) (*tls.Conn, error) {
	return m.tlsDial(network, addr, tlsConfig)
}

func mustNonAttestationProvisioner(t *testing.T) Provisioner {
	t.Helper()

	prov := &provisioner.ACME{
		Type:       "ACME",
		Name:       "acme",
		Challenges: []provisioner.ACMEChallenge{provisioner.HTTP_01},
	}
	if err := prov.Init(provisioner.Config{
		Claims: config.GlobalProvisionerClaims,
	}); err != nil {
		t.Fatal(err)
	}
	prov.AttestationFormats = []provisioner.ACMEAttestationFormat{"bogus-format"} // results in no attestation formats enabled
	return prov
}

func mustAttestationProvisioner(t *testing.T, roots []byte) Provisioner {
	t.Helper()

	prov := &provisioner.ACME{
		Type:             "ACME",
		Name:             "acme",
		Challenges:       []provisioner.ACMEChallenge{provisioner.DEVICE_ATTEST_01},
		AttestationRoots: roots,
	}
	if err := prov.Init(provisioner.Config{
		Claims: config.GlobalProvisionerClaims,
	}); err != nil {
		t.Fatal(err)
	}
	return prov
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
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, "zap.internal", updch.Value)
						assert.Equal(t, StatusValid, updch.Status)

						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)
						assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

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
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, "zap.internal", updch.Value)
						assert.Equal(t, StatusValid, updch.Status)

						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)
						assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

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
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, "zap.internal", updch.Value)
						assert.Equal(t, StatusValid, updch.Status)

						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)
						assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

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
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, "zap.internal", updch.Value)
						assert.Equal(t, StatusInvalid, updch.Status)

						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)
						assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

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
				if assert.Error(t, tc.err) {
					var k *Error
					if errors.As(err, &k) {
						assert.Equal(t, tc.err.Type, k.Type)
						assert.Equal(t, tc.err.Detail, k.Detail)
						assert.Equal(t, tc.err.Status, k.Status)
						assert.Equal(t, tc.err.Err.Error(), k.Err.Error())
					} else {
						assert.Fail(t, "unexpected error type")
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
			require.NoError(t, err)
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
			require.NoError(t, err)
			thumbprint, err := jwk.Thumbprint(crypto.SHA256)
			require.NoError(t, err)
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
				if assert.Error(t, tc.err) {
					var k *Error
					if errors.As(err, &k) {
						assert.Equal(t, tc.err.Type, k.Type)
						assert.Equal(t, tc.err.Detail, k.Detail)
						assert.Equal(t, tc.err.Status, k.Status)
						assert.Equal(t, tc.err.Err.Error(), k.Err.Error())
					} else {
						assert.Fail(t, "unexpected error type")
					}
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equal(t, tc.exp, ka)
				}
			}
		})
	}
}

func TestChallenge_Validate(t *testing.T) {
	type test struct {
		ch      *Challenge
		vc      Client
		jwk     *jose.JSONWebKey
		db      DB
		srv     *httptest.Server
		payload []byte
		ctx     context.Context
		err     *Error
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
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, ChallengeType("http-01"), updch.Type)
						assert.Equal(t, "zap.internal", updch.Value)
						assert.Equal(t, StatusPending, updch.Status)

						err := NewError(ErrorConnectionType, "error doing http GET for url http://zap.internal/.well-known/acme-challenge/%s: force", ch.Token)
						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)
						assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

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
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, ChallengeType("http-01"), updch.Type)
						assert.Equal(t, "zap.internal", updch.Value)
						assert.Equal(t, StatusPending, updch.Status)

						err := NewError(ErrorConnectionType, "error doing http GET for url http://zap.internal/.well-known/acme-challenge/%s: force", ch.Token)
						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)
						assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

						return nil
					},
				},
			}
		},
		"ok/http-01-insecure": func(t *testing.T) test {
			t.Cleanup(func() {
				InsecurePortHTTP01 = 0
			})

			ch := &Challenge{
				ID:     "chID",
				Status: StatusPending,
				Type:   "http-01",
				Token:  "token",
				Value:  "zap.internal",
			}

			InsecurePortHTTP01 = 8080

			return test{
				ch: ch,
				vc: &mockClient{
					get: func(url string) (*http.Response, error) {
						return nil, errors.New("force")
					},
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, ChallengeType("http-01"), updch.Type)
						assert.Equal(t, "zap.internal", updch.Value)
						assert.Equal(t, StatusPending, updch.Status)

						err := NewError(ErrorConnectionType, "error doing http GET for url http://zap.internal:8080/.well-known/acme-challenge/%s: force", ch.Token)
						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)
						assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

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
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, ChallengeType("dns-01"), updch.Type)
						assert.Equal(t, "zap.internal", updch.Value)
						assert.Equal(t, StatusPending, updch.Status)

						err := NewError(ErrorDNSType, "error looking up TXT records for domain %s: force", ch.Value)

						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)
						assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

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
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, ChallengeType("dns-01"), updch.Type)
						assert.Equal(t, "zap.internal", updch.Value)
						assert.Equal(t, StatusPending, updch.Status)

						err := NewError(ErrorDNSType, "error looking up TXT records for domain %s: force", ch.Value)

						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)
						assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

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
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, ChallengeType("tls-alpn-01"), updch.Type)
						assert.Equal(t, "zap.internal", updch.Value)
						assert.Equal(t, StatusPending, updch.Status)

						err := NewError(ErrorConnectionType, "error doing TLS dial for %v:443: force", ch.Value)

						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)
						assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

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
			require.NoError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			require.NoError(t, err)
			expKeyAuthHash := sha256.Sum256([]byte(expKeyAuth))

			cert, err := newTLSALPNValidationCert(expKeyAuthHash[:], false, true, ch.Value)
			require.NoError(t, err)

			srv, tlsDial := newTestTLSALPNServer(cert)
			srv.Start()

			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: tlsDial,
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, ChallengeType("tls-alpn-01"), updch.Type)
						assert.Equal(t, "zap.internal", updch.Value)
						assert.Equal(t, StatusValid, updch.Status)
						assert.Nil(t, updch.Error)
						return nil
					},
				},
				srv: srv,
				jwk: jwk,
			}
		},
		"ok/tls-alpn-01-insecure": func(t *testing.T) test {
			t.Cleanup(func() {
				InsecurePortTLSALPN01 = 0
			})

			ch := &Challenge{
				ID:     "chID",
				Token:  "token",
				Type:   "tls-alpn-01",
				Status: StatusPending,
				Value:  "zap.internal",
			}

			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			require.NoError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			require.NoError(t, err)
			expKeyAuthHash := sha256.Sum256([]byte(expKeyAuth))

			cert, err := newTLSALPNValidationCert(expKeyAuthHash[:], false, true, ch.Value)
			require.NoError(t, err)

			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				if l, err = net.Listen("tcp6", "[::1]:0"); err != nil {
					t.Fatalf("failed to listen on a port: %v", err)
				}
			}
			_, port, err := net.SplitHostPort(l.Addr().String())
			if err != nil {
				t.Fatalf("failed to split host port: %v", err)
			}

			// Use an insecure port
			InsecurePortTLSALPN01, err = strconv.Atoi(port)
			if err != nil {
				t.Fatalf("failed to convert port to int: %v", err)
			}

			srv, tlsDial := newTestTLSALPNServer(cert, func(srv *httptest.Server) {
				srv.Listener.Close()
				srv.Listener = l
			})
			srv.Start()

			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: tlsDial,
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, ChallengeType("tls-alpn-01"), updch.Type)
						assert.Equal(t, "zap.internal", updch.Value)
						assert.Equal(t, StatusValid, updch.Status)
						assert.Nil(t, updch.Error)
						return nil
					},
				},
				srv: srv,
				jwk: jwk,
			}
		},
		"fail/device-attest-01": func(t *testing.T) test {
			ch := &Challenge{
				ID:     "chID",
				Token:  "token",
				Type:   "device-attest-01",
				Status: StatusPending,
				Value:  "12345678",
			}
			payload, err := json.Marshal(struct {
				Error string `json:"error"`
			}{
				Error: "an error",
			})
			assert.NoError(t, err)
			return test{
				ch:      ch,
				payload: payload,
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, StatusInvalid, updch.Status)
						assert.Equal(t, ChallengeType("device-attest-01"), updch.Type)
						assert.Equal(t, "12345678", updch.Value)

						err := NewError(ErrorRejectedIdentifierType, "payload contained error: an error")

						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)

						return errors.New("force")
					},
				},
				err: NewError(ErrorServerInternalType, "failure saving error to acme challenge: force"),
			}
		},
		"ok/device-attest-01": func(t *testing.T) test {
			ctx := context.Background()
			ca, err := minica.New()
			assert.NoError(t, err)
			caRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Root.Raw})
			ctx = NewProvisionerContext(ctx, mustAttestationProvisioner(t, caRoot))
			makeLeaf := func(signer crypto.Signer, serialNumber []byte) *x509.Certificate {
				leaf, err := ca.Sign(&x509.Certificate{
					Subject:   pkix.Name{CommonName: "attestation cert"},
					PublicKey: signer.Public(),
					ExtraExtensions: []pkix.Extension{
						{Id: oidYubicoSerialNumber, Value: serialNumber},
					},
				})
				if err != nil {
					t.Fatal(err)
				}
				return leaf
			}

			signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			assert.NoError(t, err)
			serialNumber, err := asn1.Marshal(1234)
			assert.NoError(t, err)
			leaf := makeLeaf(signer, serialNumber)

			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.NoError(t, err)
			token := "token"
			keyAuth, err := KeyAuthorization(token, jwk)
			assert.NoError(t, err)
			keyAuthSum := sha256.Sum256([]byte(keyAuth))
			sig, err := signer.Sign(rand.Reader, keyAuthSum[:], crypto.SHA256)
			assert.NoError(t, err)
			cborSig, err := cbor.Marshal(sig)
			assert.NoError(t, err)

			ch := &Challenge{
				ID:     "chID",
				Token:  token,
				Type:   "device-attest-01",
				Status: StatusPending,
				Value:  "1234",
			}
			attObj, err := cbor.Marshal(struct {
				Format       string                 `json:"fmt"`
				AttStatement map[string]interface{} `json:"attStmt,omitempty"`
			}{
				Format: "step",
				AttStatement: map[string]interface{}{
					"x5c": []interface{}{leaf.Raw, ca.Intermediate.Raw},
					"alg": -7,
					"sig": cborSig,
				},
			})
			assert.NoError(t, err)
			payload, err := json.Marshal(struct {
				AttObj string `json:"attObj"`
			}{
				AttObj: base64.RawURLEncoding.EncodeToString(attObj),
			})
			assert.NoError(t, err)
			return test{
				ch:      ch,
				payload: payload,
				ctx:     ctx,
				jwk:     jwk,
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, token, updch.Token)
						assert.Equal(t, StatusValid, updch.Status)
						assert.Equal(t, ChallengeType("device-attest-01"), updch.Type)
						assert.Equal(t, "1234", updch.Value)

						return nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)

			if tc.srv != nil {
				defer tc.srv.Close()
			}

			ctx := tc.ctx
			if ctx == nil {
				ctx = context.Background()
			}
			ctx = NewClientContext(ctx, tc.vc)
			if err := tc.ch.Validate(ctx, tc.db, tc.jwk, tc.payload); err != nil {
				if assert.Error(t, tc.err) {
					var k *Error
					if errors.As(err, &k) {
						assert.Equal(t, tc.err.Type, k.Type)
						assert.Equal(t, tc.err.Detail, k.Detail)
						assert.Equal(t, tc.err.Status, k.Status)
						assert.Equal(t, tc.err.Err.Error(), k.Err.Error())
					} else {
						assert.Fail(t, "unexpected error type")
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
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, "zap.internal", updch.Value)
						assert.Equal(t, StatusPending, updch.Status)

						err := NewError(ErrorConnectionType, "error doing http GET for url http://zap.internal/.well-known/acme-challenge/%s: force", ch.Token)
						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)
						assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

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
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, "zap.internal", updch.Value)
						assert.Equal(t, StatusPending, updch.Status)

						err := NewError(ErrorConnectionType, "error doing http GET for url http://zap.internal/.well-known/acme-challenge/%s: force", ch.Token)
						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)
						assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

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
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, "zap.internal", updch.Value)
						assert.Equal(t, StatusPending, updch.Status)

						err := NewError(ErrorConnectionType, "error doing http GET for url http://zap.internal/.well-known/acme-challenge/%s with status code 400", ch.Token)
						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)
						assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

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
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, "zap.internal", updch.Value)
						assert.Equal(t, StatusPending, updch.Status)

						err := NewError(ErrorConnectionType, "error doing http GET for url http://zap.internal/.well-known/acme-challenge/%s with status code 400", ch.Token)
						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)
						assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

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
			require.NoError(t, err)
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
			require.NoError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			require.NoError(t, err)
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
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, "zap.internal", updch.Value)
						assert.Equal(t, StatusInvalid, updch.Status)

						err := NewError(ErrorRejectedIdentifierType,
							"keyAuthorization does not match; expected %s, but got foo", expKeyAuth)
						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)
						assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

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
			require.NoError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			require.NoError(t, err)
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
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, "zap.internal", updch.Value)
						assert.Equal(t, StatusInvalid, updch.Status)

						err := NewError(ErrorRejectedIdentifierType,
							"keyAuthorization does not match; expected %s, but got foo", expKeyAuth)
						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)
						assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

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
			require.NoError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			require.NoError(t, err)
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
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, "zap.internal", updch.Value)
						assert.Equal(t, StatusValid, updch.Status)
						assert.Nil(t, updch.Error)

						va, err := time.Parse(time.RFC3339, updch.ValidatedAt)
						require.NoError(t, err)
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
			require.NoError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			require.NoError(t, err)
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
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, "zap.internal", updch.Value)
						assert.Equal(t, StatusValid, updch.Status)
						assert.Nil(t, updch.Error)

						va, err := time.Parse(time.RFC3339, updch.ValidatedAt)
						require.NoError(t, err)
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
				if assert.Error(t, tc.err) {
					var k *Error
					if errors.As(err, &k) {
						assert.Equal(t, tc.err.Type, k.Type)
						assert.Equal(t, tc.err.Detail, k.Detail)
						assert.Equal(t, tc.err.Status, k.Status)
						assert.Equal(t, tc.err.Err.Error(), k.Err.Error())
					} else {
						assert.Fail(t, "unexpected error type")
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
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, fulldomain, updch.Value)
						assert.Equal(t, StatusPending, updch.Status)

						err := NewError(ErrorDNSType, "error looking up TXT records for domain %s: force", domain)

						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)
						assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

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
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, fulldomain, updch.Value)
						assert.Equal(t, StatusPending, updch.Status)

						err := NewError(ErrorDNSType, "error looking up TXT records for domain %s: force", domain)

						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)
						assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

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
			require.NoError(t, err)
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
			require.NoError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			require.NoError(t, err)

			return test{
				ch: ch,
				vc: &mockClient{
					lookupTxt: func(url string) ([]string, error) {
						return []string{"foo", "bar"}, nil
					},
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, fulldomain, updch.Value)
						assert.Equal(t, StatusPending, updch.Status)

						err := NewError(ErrorRejectedIdentifierType, "keyAuthorization does not match; expected %s, but got %s", expKeyAuth, []string{"foo", "bar"})

						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)
						assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

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
			require.NoError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			require.NoError(t, err)

			return test{
				ch: ch,
				vc: &mockClient{
					lookupTxt: func(url string) ([]string, error) {
						return []string{"foo", "bar"}, nil
					},
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, fulldomain, updch.Value)
						assert.Equal(t, StatusPending, updch.Status)

						err := NewError(ErrorRejectedIdentifierType, "keyAuthorization does not match; expected %s, but got %s", expKeyAuth, []string{"foo", "bar"})

						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)
						assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

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
			require.NoError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			require.NoError(t, err)
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
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, fulldomain, ch.Value)
						assert.Equal(t, StatusValid, updch.Status)
						assert.Nil(t, updch.Error)

						va, err := time.Parse(time.RFC3339, updch.ValidatedAt)
						require.NoError(t, err)
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
			require.NoError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			require.NoError(t, err)
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
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, fulldomain, updch.Value)
						assert.Equal(t, StatusValid, updch.Status)
						assert.Nil(t, updch.Error)

						va, err := time.Parse(time.RFC3339, updch.ValidatedAt)
						require.NoError(t, err)
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
				if assert.Error(t, tc.err) {
					var k *Error
					if errors.As(err, &k) {
						assert.Equal(t, tc.err.Type, k.Type)
						assert.Equal(t, tc.err.Detail, k.Detail)
						assert.Equal(t, tc.err.Status, k.Status)
						assert.Equal(t, tc.err.Err.Error(), k.Err.Error())
					} else {
						assert.Fail(t, "unexpected error type")
					}
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

type tlsDialer func(network, addr string, config *tls.Config) (conn *tls.Conn, err error)

func newTestTLSALPNServer(validationCert *tls.Certificate, opts ...func(*httptest.Server)) (*httptest.Server, tlsDialer) {
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

	// Apply options
	for _, fn := range opts {
		fn(srv)
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
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, StatusPending, updch.Status)
						assert.Equal(t, ChallengeType("tls-alpn-01"), updch.Type)
						assert.Equal(t, "zap.internal", updch.Value)

						err := NewError(ErrorConnectionType, "error doing TLS dial for %v:443: force", ch.Value)

						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)
						assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

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
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, StatusPending, updch.Status)
						assert.Equal(t, ChallengeType("tls-alpn-01"), updch.Type)
						assert.Equal(t, "zap.internal", updch.Value)

						err := NewError(ErrorConnectionType, "error doing TLS dial for %v:443: force", ch.Value)

						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)
						assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

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
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, StatusPending, updch.Status)
						assert.Equal(t, ChallengeType("tls-alpn-01"), updch.Type)
						assert.Equal(t, "zap.internal", updch.Value)

						err := NewError(ErrorConnectionType, "error doing TLS dial for %v:443: context deadline exceeded", ch.Value)

						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)
						assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

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
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, StatusInvalid, updch.Status)
						assert.Equal(t, ChallengeType("tls-alpn-01"), updch.Type)
						assert.Equal(t, "zap.internal", updch.Value)

						err := NewError(ErrorRejectedIdentifierType, "tls-alpn-01 challenge for %v resulted in no certificates", ch.Value)

						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)
						assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

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
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, StatusInvalid, updch.Status)
						assert.Equal(t, ChallengeType("tls-alpn-01"), updch.Type)
						assert.Equal(t, "zap.internal", updch.Value)

						err := NewError(ErrorRejectedIdentifierType, "tls-alpn-01 challenge for %v resulted in no certificates", ch.Value)

						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)
						assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

						return errors.New("force")
					},
				},
				err: NewErrorISE("failure saving error to acme challenge: force"),
			}
		},
		"ok/error-no-protocol": func(t *testing.T) test {
			ch := makeTLSCh()

			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			require.NoError(t, err)

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
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, StatusInvalid, updch.Status)
						assert.Equal(t, ChallengeType("tls-alpn-01"), updch.Type)
						assert.Equal(t, "zap.internal", updch.Value)

						err := NewError(ErrorRejectedIdentifierType, "cannot negotiate ALPN acme-tls/1 protocol for tls-alpn-01 challenge")

						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)
						assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

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
			require.NoError(t, err)

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
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, StatusInvalid, updch.Status)
						assert.Equal(t, ChallengeType("tls-alpn-01"), updch.Type)
						assert.Equal(t, "zap.internal", updch.Value)

						err := NewError(ErrorRejectedIdentifierType, "cannot negotiate ALPN acme-tls/1 protocol for tls-alpn-01 challenge")

						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)
						assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

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
			require.NoError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			require.NoError(t, err)
			expKeyAuthHash := sha256.Sum256([]byte(expKeyAuth))

			cert, err := newTLSALPNValidationCert(expKeyAuthHash[:], false, true)
			require.NoError(t, err)

			srv, tlsDial := newTestTLSALPNServer(cert)
			srv.Start()

			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: tlsDial,
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, StatusInvalid, updch.Status)
						assert.Equal(t, ChallengeType("tls-alpn-01"), updch.Type)
						assert.Equal(t, "zap.internal", updch.Value)

						err := NewError(ErrorRejectedIdentifierType, "incorrect certificate for tls-alpn-01 challenge: leaf certificate must contain a single IP address or DNS name, %v", ch.Value)

						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)
						assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

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
			require.NoError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			require.NoError(t, err)
			expKeyAuthHash := sha256.Sum256([]byte(expKeyAuth))

			cert, err := newTLSALPNValidationCert(expKeyAuthHash[:], false, true)
			require.NoError(t, err)

			srv, tlsDial := newTestTLSALPNServer(cert)
			srv.Start()

			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: tlsDial,
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, StatusInvalid, updch.Status)
						assert.Equal(t, ChallengeType("tls-alpn-01"), updch.Type)
						assert.Equal(t, "zap.internal", updch.Value)

						err := NewError(ErrorRejectedIdentifierType, "incorrect certificate for tls-alpn-01 challenge: leaf certificate must contain a single IP address or DNS name, %v", ch.Value)

						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)
						assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

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
			require.NoError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			require.NoError(t, err)
			expKeyAuthHash := sha256.Sum256([]byte(expKeyAuth))

			cert, err := newTLSALPNValidationCert(expKeyAuthHash[:], false, true, ch.Value, "other.internal")
			require.NoError(t, err)

			srv, tlsDial := newTestTLSALPNServer(cert)
			srv.Start()

			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: tlsDial,
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, StatusInvalid, updch.Status)
						assert.Equal(t, ChallengeType("tls-alpn-01"), updch.Type)
						assert.Equal(t, "zap.internal", updch.Value)

						err := NewError(ErrorRejectedIdentifierType, "incorrect certificate for tls-alpn-01 challenge: leaf certificate must contain a single IP address or DNS name, %v", ch.Value)

						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)
						assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

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
			require.NoError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			require.NoError(t, err)
			expKeyAuthHash := sha256.Sum256([]byte(expKeyAuth))

			cert, err := newTLSALPNValidationCert(expKeyAuthHash[:], false, true, "other.internal")
			require.NoError(t, err)

			srv, tlsDial := newTestTLSALPNServer(cert)
			srv.Start()

			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: tlsDial,
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, StatusInvalid, updch.Status)
						assert.Equal(t, ChallengeType("tls-alpn-01"), updch.Type)
						assert.Equal(t, "zap.internal", updch.Value)

						err := NewError(ErrorRejectedIdentifierType, "incorrect certificate for tls-alpn-01 challenge: leaf certificate must contain a single IP address or DNS name, %v", ch.Value)

						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)
						assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

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
			require.NoError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			require.NoError(t, err)
			expKeyAuthHash := sha256.Sum256([]byte(expKeyAuth))
			jwk.Key = "foo"

			cert, err := newTLSALPNValidationCert(expKeyAuthHash[:], false, true, ch.Value)
			require.NoError(t, err)

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
			require.NoError(t, err)

			cert, err := newTLSALPNValidationCert(nil, false, true, ch.Value)
			require.NoError(t, err)

			srv, tlsDial := newTestTLSALPNServer(cert)
			srv.Start()

			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: tlsDial,
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, StatusInvalid, updch.Status)
						assert.Equal(t, ChallengeType("tls-alpn-01"), updch.Type)
						assert.Equal(t, "zap.internal", updch.Value)

						err := NewError(ErrorRejectedIdentifierType, "incorrect certificate for tls-alpn-01 challenge: missing acmeValidationV1 extension")

						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)
						assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

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
			require.NoError(t, err)

			cert, err := newTLSALPNValidationCert(nil, false, true, ch.Value)
			require.NoError(t, err)

			srv, tlsDial := newTestTLSALPNServer(cert)
			srv.Start()

			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: tlsDial,
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, StatusInvalid, updch.Status)
						assert.Equal(t, ChallengeType("tls-alpn-01"), updch.Type)
						assert.Equal(t, "zap.internal", updch.Value)

						err := NewError(ErrorRejectedIdentifierType, "incorrect certificate for tls-alpn-01 challenge: missing acmeValidationV1 extension")

						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)
						assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

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
			require.NoError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			require.NoError(t, err)
			expKeyAuthHash := sha256.Sum256([]byte(expKeyAuth))

			cert, err := newTLSALPNValidationCert(expKeyAuthHash[:], false, false, ch.Value)
			require.NoError(t, err)

			srv, tlsDial := newTestTLSALPNServer(cert)
			srv.Start()

			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: tlsDial,
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, StatusInvalid, updch.Status)
						assert.Equal(t, ChallengeType("tls-alpn-01"), updch.Type)
						assert.Equal(t, "zap.internal", updch.Value)

						err := NewError(ErrorRejectedIdentifierType, "incorrect certificate for tls-alpn-01 challenge: acmeValidationV1 extension not critical")

						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)
						assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

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
			require.NoError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			require.NoError(t, err)
			expKeyAuthHash := sha256.Sum256([]byte(expKeyAuth))

			cert, err := newTLSALPNValidationCert(expKeyAuthHash[:], false, false, ch.Value)
			require.NoError(t, err)

			srv, tlsDial := newTestTLSALPNServer(cert)
			srv.Start()

			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: tlsDial,
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, StatusInvalid, updch.Status)
						assert.Equal(t, ChallengeType("tls-alpn-01"), updch.Type)
						assert.Equal(t, "zap.internal", updch.Value)

						err := NewError(ErrorRejectedIdentifierType, "incorrect certificate for tls-alpn-01 challenge: acmeValidationV1 extension not critical")

						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)
						assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

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
			require.NoError(t, err)

			cert, err := newTLSALPNValidationCert([]byte{1, 2, 3}, false, true, ch.Value)
			require.NoError(t, err)

			srv, tlsDial := newTestTLSALPNServer(cert)
			srv.Start()

			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: tlsDial,
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, StatusInvalid, updch.Status)
						assert.Equal(t, ChallengeType("tls-alpn-01"), updch.Type)
						assert.Equal(t, "zap.internal", updch.Value)

						err := NewError(ErrorRejectedIdentifierType, "incorrect certificate for tls-alpn-01 challenge: malformed acmeValidationV1 extension value")

						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)
						assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

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
			require.NoError(t, err)

			cert, err := newTLSALPNValidationCert([]byte{1, 2, 3}, false, true, ch.Value)
			require.NoError(t, err)

			srv, tlsDial := newTestTLSALPNServer(cert)
			srv.Start()

			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: tlsDial,
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, StatusInvalid, updch.Status)
						assert.Equal(t, ChallengeType("tls-alpn-01"), updch.Type)
						assert.Equal(t, "zap.internal", updch.Value)

						err := NewError(ErrorRejectedIdentifierType, "incorrect certificate for tls-alpn-01 challenge: malformed acmeValidationV1 extension value")

						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)
						assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

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
			require.NoError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			require.NoError(t, err)
			expKeyAuthHash := sha256.Sum256([]byte(expKeyAuth))
			incorrectTokenHash := sha256.Sum256([]byte("mismatched"))

			cert, err := newTLSALPNValidationCert(incorrectTokenHash[:], false, true, ch.Value)
			require.NoError(t, err)

			srv, tlsDial := newTestTLSALPNServer(cert)
			srv.Start()

			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: tlsDial,
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, StatusInvalid, updch.Status)
						assert.Equal(t, ChallengeType("tls-alpn-01"), updch.Type)
						assert.Equal(t, "zap.internal", updch.Value)

						err := NewError(ErrorRejectedIdentifierType, "incorrect certificate for tls-alpn-01 challenge: "+
							"expected acmeValidationV1 extension value %s for this challenge but got %s",
							hex.EncodeToString(expKeyAuthHash[:]), hex.EncodeToString(incorrectTokenHash[:]))

						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)
						assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

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
			require.NoError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			require.NoError(t, err)
			expKeyAuthHash := sha256.Sum256([]byte(expKeyAuth))
			incorrectTokenHash := sha256.Sum256([]byte("mismatched"))

			cert, err := newTLSALPNValidationCert(incorrectTokenHash[:], false, true, ch.Value)
			require.NoError(t, err)

			srv, tlsDial := newTestTLSALPNServer(cert)
			srv.Start()

			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: tlsDial,
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, StatusInvalid, updch.Status)
						assert.Equal(t, ChallengeType("tls-alpn-01"), updch.Type)
						assert.Equal(t, "zap.internal", updch.Value)

						err := NewError(ErrorRejectedIdentifierType, "incorrect certificate for tls-alpn-01 challenge: "+
							"expected acmeValidationV1 extension value %s for this challenge but got %s",
							hex.EncodeToString(expKeyAuthHash[:]), hex.EncodeToString(incorrectTokenHash[:]))

						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)
						assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

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
			require.NoError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			require.NoError(t, err)
			expKeyAuthHash := sha256.Sum256([]byte(expKeyAuth))

			cert, err := newTLSALPNValidationCert(expKeyAuthHash[:], true, true, ch.Value)
			require.NoError(t, err)

			srv, tlsDial := newTestTLSALPNServer(cert)
			srv.Start()

			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: tlsDial,
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, StatusInvalid, updch.Status)
						assert.Equal(t, ChallengeType("tls-alpn-01"), updch.Type)
						assert.Equal(t, "zap.internal", updch.Value)

						err := NewError(ErrorRejectedIdentifierType, "incorrect certificate for tls-alpn-01 challenge: "+
							"obsolete id-pe-acmeIdentifier in acmeValidationV1 extension")

						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)
						assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

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
			require.NoError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			require.NoError(t, err)
			expKeyAuthHash := sha256.Sum256([]byte(expKeyAuth))

			cert, err := newTLSALPNValidationCert(expKeyAuthHash[:], true, true, ch.Value)
			require.NoError(t, err)

			srv, tlsDial := newTestTLSALPNServer(cert)
			srv.Start()

			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: tlsDial,
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, StatusInvalid, updch.Status)
						assert.Equal(t, ChallengeType("tls-alpn-01"), updch.Type)
						assert.Equal(t, "zap.internal", updch.Value)

						err := NewError(ErrorRejectedIdentifierType, "incorrect certificate for tls-alpn-01 challenge: "+
							"obsolete id-pe-acmeIdentifier in acmeValidationV1 extension")

						assert.EqualError(t, updch.Error.Err, err.Err.Error())
						assert.Equal(t, err.Type, updch.Error.Type)
						assert.Equal(t, err.Detail, updch.Error.Detail)
						assert.Equal(t, err.Status, updch.Error.Status)
						assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

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
			require.NoError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			require.NoError(t, err)
			expKeyAuthHash := sha256.Sum256([]byte(expKeyAuth))

			cert, err := newTLSALPNValidationCert(expKeyAuthHash[:], false, true, ch.Value)
			require.NoError(t, err)

			srv, tlsDial := newTestTLSALPNServer(cert)
			srv.Start()

			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: tlsDial,
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, StatusValid, updch.Status)
						assert.Equal(t, ChallengeType("tls-alpn-01"), updch.Type)
						assert.Equal(t, "zap.internal", updch.Value)
						assert.Nil(t, updch.Error)

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
			require.NoError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.Token, jwk)
			require.NoError(t, err)
			expKeyAuthHash := sha256.Sum256([]byte(expKeyAuth))

			cert, err := newTLSALPNValidationCert(expKeyAuthHash[:], false, true, ch.Value)
			require.NoError(t, err)

			srv, tlsDial := newTestTLSALPNServer(cert)
			srv.Start()

			return test{
				ch: ch,
				vc: &mockClient{
					tlsDial: tlsDial,
				},
				db: &MockDB{
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, StatusValid, updch.Status)
						assert.Equal(t, ChallengeType("tls-alpn-01"), updch.Type)
						assert.Equal(t, "127.0.0.1", updch.Value)
						assert.Nil(t, updch.Error)

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
				if assert.Error(t, tc.err) {
					var k *Error
					if errors.As(err, &k) {
						assert.Equal(t, tc.err.Type, k.Type)
						assert.Equal(t, tc.err.Detail, k.Detail)
						assert.Equal(t, tc.err.Status, k.Status)
						assert.Equal(t, tc.err.Err.Error(), k.Err.Error())
						assert.Equal(t, tc.err.Subproblems, k.Subproblems)
					} else {
						assert.Fail(t, "unexpected error type")
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

func Test_doAppleAttestationFormat(t *testing.T) {
	ctx := context.Background()
	ca, err := minica.New()
	if err != nil {
		t.Fatal(err)
	}
	caRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Root.Raw})
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.Sign(&x509.Certificate{
		Subject:   pkix.Name{CommonName: "attestation cert"},
		PublicKey: signer.Public(),
		ExtraExtensions: []pkix.Extension{
			{Id: oidAppleSerialNumber, Value: []byte("serial-number")},
			{Id: oidAppleUniqueDeviceIdentifier, Value: []byte("udid")},
			{Id: oidAppleSecureEnclaveProcessorOSVersion, Value: []byte("16.0")},
			{Id: oidAppleNonce, Value: []byte("nonce")},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		ctx  context.Context
		prov Provisioner
		ch   *Challenge
		att  *attestationObject
	}
	tests := []struct {
		name    string
		args    args
		want    *appleAttestationData
		wantErr bool
	}{
		{"ok", args{ctx, mustAttestationProvisioner(t, caRoot), &Challenge{}, &attestationObject{
			Format: "apple",
			AttStatement: map[string]interface{}{
				"x5c": []interface{}{leaf.Raw, ca.Intermediate.Raw},
			},
		}}, &appleAttestationData{
			Nonce:        []byte("nonce"),
			SerialNumber: "serial-number",
			UDID:         "udid",
			SEPVersion:   "16.0",
			Certificate:  leaf,
		}, false},
		{"fail apple issuer", args{ctx, mustAttestationProvisioner(t, nil), &Challenge{}, &attestationObject{
			Format: "apple",
			AttStatement: map[string]interface{}{
				"x5c": []interface{}{leaf.Raw, ca.Intermediate.Raw},
			},
		}}, nil, true},
		{"fail missing x5c", args{ctx, mustAttestationProvisioner(t, caRoot), &Challenge{}, &attestationObject{
			Format: "apple",
			AttStatement: map[string]interface{}{
				"foo": "bar",
			},
		}}, nil, true},
		{"fail empty issuer", args{ctx, mustAttestationProvisioner(t, caRoot), &Challenge{}, &attestationObject{
			Format: "apple",
			AttStatement: map[string]interface{}{
				"x5c": []interface{}{},
			},
		}}, nil, true},
		{"fail leaf type", args{ctx, mustAttestationProvisioner(t, caRoot), &Challenge{}, &attestationObject{
			Format: "apple",
			AttStatement: map[string]interface{}{
				"x5c": []interface{}{"leaf", ca.Intermediate.Raw},
			},
		}}, nil, true},
		{"fail leaf parse", args{ctx, mustAttestationProvisioner(t, caRoot), &Challenge{}, &attestationObject{
			Format: "apple",
			AttStatement: map[string]interface{}{
				"x5c": []interface{}{leaf.Raw[:100], ca.Intermediate.Raw},
			},
		}}, nil, true},
		{"fail intermediate type", args{ctx, mustAttestationProvisioner(t, caRoot), &Challenge{}, &attestationObject{
			Format: "apple",
			AttStatement: map[string]interface{}{
				"x5c": []interface{}{leaf.Raw, "intermediate"},
			},
		}}, nil, true},
		{"fail intermediate parse", args{ctx, mustAttestationProvisioner(t, caRoot), &Challenge{}, &attestationObject{
			Format: "apple",
			AttStatement: map[string]interface{}{
				"x5c": []interface{}{leaf.Raw, ca.Intermediate.Raw[:100]},
			},
		}}, nil, true},
		{"fail verify", args{ctx, mustAttestationProvisioner(t, caRoot), &Challenge{}, &attestationObject{
			Format: "apple",
			AttStatement: map[string]interface{}{
				"x5c": []interface{}{leaf.Raw},
			},
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := doAppleAttestationFormat(tt.args.ctx, tt.args.prov, tt.args.ch, tt.args.att)
			if (err != nil) != tt.wantErr {
				t.Errorf("doAppleAttestationFormat() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("doAppleAttestationFormat() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_doStepAttestationFormat(t *testing.T) {
	ctx := context.Background()
	ca, err := minica.New()
	if err != nil {
		t.Fatal(err)
	}
	caRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Root.Raw})

	makeLeaf := func(signer crypto.Signer, serialNumber []byte) *x509.Certificate {
		leaf, err := ca.Sign(&x509.Certificate{
			Subject:   pkix.Name{CommonName: "attestation cert"},
			PublicKey: signer.Public(),
			ExtraExtensions: []pkix.Extension{
				{Id: oidYubicoSerialNumber, Value: serialNumber},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return leaf
	}
	mustSigner := func(kty, crv string, size int) crypto.Signer {
		s, err := keyutil.GenerateSigner(kty, crv, size)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serialNumber, err := asn1.Marshal(1234)
	if err != nil {
		t.Fatal(err)
	}
	leaf := makeLeaf(signer, serialNumber)

	jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	keyAuth, err := KeyAuthorization("token", jwk)
	if err != nil {
		t.Fatal(err)
	}
	keyAuthSum := sha256.Sum256([]byte(keyAuth))
	sig, err := signer.Sign(rand.Reader, keyAuthSum[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	cborSig, err := cbor.Marshal(sig)
	if err != nil {
		t.Fatal(err)
	}

	otherSigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherSig, err := otherSigner.Sign(rand.Reader, keyAuthSum[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	otherCBORSig, err := cbor.Marshal(otherSig)
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		ctx  context.Context
		prov Provisioner
		ch   *Challenge
		jwk  *jose.JSONWebKey
		att  *attestationObject
	}
	tests := []struct {
		name    string
		args    args
		want    *stepAttestationData
		wantErr bool
	}{
		{"ok", args{ctx, mustAttestationProvisioner(t, caRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "step",
			AttStatement: map[string]interface{}{
				"x5c": []interface{}{leaf.Raw, ca.Intermediate.Raw},
				"alg": -7,
				"sig": cborSig,
			},
		}}, &stepAttestationData{
			SerialNumber: "1234",
			Certificate:  leaf,
		}, false},
		{"fail yubico issuer", args{ctx, mustAttestationProvisioner(t, nil), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "step",
			AttStatement: map[string]interface{}{
				"x5c": []interface{}{leaf.Raw, ca.Intermediate.Raw},
				"alg": -7,
				"sig": cborSig,
			},
		}}, nil, true},
		{"fail x5c type", args{ctx, mustAttestationProvisioner(t, caRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "step",
			AttStatement: map[string]interface{}{
				"x5c": [][]byte{leaf.Raw, ca.Intermediate.Raw},
				"alg": -7,
				"sig": cborSig,
			},
		}}, nil, true},
		{"fail x5c empty", args{ctx, mustAttestationProvisioner(t, caRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "step",
			AttStatement: map[string]interface{}{
				"x5c": []interface{}{},
				"alg": -7,
				"sig": cborSig,
			},
		}}, nil, true},
		{"fail leaf type", args{ctx, mustAttestationProvisioner(t, caRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "step",
			AttStatement: map[string]interface{}{
				"x5c": []interface{}{"leaf", ca.Intermediate.Raw},
				"alg": -7,
				"sig": cborSig,
			},
		}}, nil, true},
		{"fail leaf parse", args{ctx, mustAttestationProvisioner(t, caRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "step",
			AttStatement: map[string]interface{}{
				"x5c": []interface{}{leaf.Raw[:100], ca.Intermediate.Raw},
				"alg": -7,
				"sig": cborSig,
			},
		}}, nil, true},
		{"fail intermediate type", args{ctx, mustAttestationProvisioner(t, caRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "step",
			AttStatement: map[string]interface{}{
				"x5c": []interface{}{leaf.Raw, "intermediate"},
				"alg": -7,
				"sig": cborSig,
			},
		}}, nil, true},
		{"fail intermediate parse", args{ctx, mustAttestationProvisioner(t, caRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "step",
			AttStatement: map[string]interface{}{
				"x5c": []interface{}{leaf.Raw, ca.Intermediate.Raw[:100]},
				"alg": -7,
				"sig": cborSig,
			},
		}}, nil, true},
		{"fail verify", args{ctx, mustAttestationProvisioner(t, caRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "step",
			AttStatement: map[string]interface{}{
				"x5c": []interface{}{leaf.Raw},
				"alg": -7,
				"sig": cborSig,
			},
		}}, nil, true},
		{"fail sig type", args{ctx, mustAttestationProvisioner(t, caRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "step",
			AttStatement: map[string]interface{}{
				"x5c": []interface{}{leaf.Raw, ca.Intermediate.Raw},
				"alg": -7,
				"sig": string(cborSig),
			},
		}}, nil, true},
		{"fail sig unmarshal", args{ctx, mustAttestationProvisioner(t, caRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "step",
			AttStatement: map[string]interface{}{
				"x5c": []interface{}{leaf.Raw, ca.Intermediate.Raw},
				"alg": -7,
				"sig": []byte("bad-sig"),
			},
		}}, nil, true},
		{"fail keyAuthorization", args{ctx, mustAttestationProvisioner(t, caRoot), &Challenge{Token: "token"}, &jose.JSONWebKey{Key: []byte("not an asymmetric key")}, &attestationObject{
			Format: "step",
			AttStatement: map[string]interface{}{
				"x5c": []interface{}{leaf.Raw, ca.Intermediate.Raw},
				"alg": -7,
				"sig": cborSig,
			},
		}}, nil, true},
		{"fail sig verify P-256", args{ctx, mustAttestationProvisioner(t, caRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "step",
			AttStatement: map[string]interface{}{
				"x5c": []interface{}{leaf.Raw, ca.Intermediate.Raw},
				"alg": -7,
				"sig": otherCBORSig,
			},
		}}, nil, true},
		{"fail sig verify P-384", args{ctx, mustAttestationProvisioner(t, caRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "step",
			AttStatement: map[string]interface{}{
				"x5c": []interface{}{makeLeaf(mustSigner("EC", "P-384", 0), serialNumber).Raw, ca.Intermediate.Raw},
				"alg": -7,
				"sig": cborSig,
			},
		}}, nil, true},
		{"fail sig verify RSA", args{ctx, mustAttestationProvisioner(t, caRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "step",
			AttStatement: map[string]interface{}{
				"x5c": []interface{}{makeLeaf(mustSigner("RSA", "", 2048), serialNumber).Raw, ca.Intermediate.Raw},
				"alg": -7,
				"sig": cborSig,
			},
		}}, nil, true},
		{"fail sig verify Ed25519", args{ctx, mustAttestationProvisioner(t, caRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "step",
			AttStatement: map[string]interface{}{
				"x5c": []interface{}{makeLeaf(mustSigner("OKP", "Ed25519", 0), serialNumber).Raw, ca.Intermediate.Raw},
				"alg": -7,
				"sig": cborSig,
			},
		}}, nil, true},
		{"fail unmarshal serial number", args{ctx, mustAttestationProvisioner(t, caRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "step",
			AttStatement: map[string]interface{}{
				"x5c": []interface{}{makeLeaf(signer, []byte("bad-serial")).Raw, ca.Intermediate.Raw},
				"alg": -7,
				"sig": cborSig,
			},
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := doStepAttestationFormat(tt.args.ctx, tt.args.prov, tt.args.ch, tt.args.jwk, tt.args.att)
			if (err != nil) != tt.wantErr {
				t.Errorf("doStepAttestationFormat() error = %#v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("doStepAttestationFormat() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_doStepAttestationFormat_noCAIntermediate(t *testing.T) {
	ctx := context.Background()

	// This CA simulates a YubiKey v5.2.4, where the attestation intermediate in
	// the CA does not have the basic constraint extension. With the current
	// validation of the certificate the test case below returns an error. If
	// we change the validation to support this use case, the test case below
	// should change.
	//
	// See https://github.com/Yubico/yubikey-manager/issues/522
	ca, err := minica.New(minica.WithIntermediateTemplate(`{"subject": {{ toJson .Subject }}}`))
	if err != nil {
		t.Fatal(err)
	}
	caRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Root.Raw})

	makeLeaf := func(signer crypto.Signer, serialNumber []byte) *x509.Certificate {
		leaf, err := ca.Sign(&x509.Certificate{
			Subject:   pkix.Name{CommonName: "attestation cert"},
			PublicKey: signer.Public(),
			ExtraExtensions: []pkix.Extension{
				{Id: oidYubicoSerialNumber, Value: serialNumber},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return leaf
	}

	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serialNumber, err := asn1.Marshal(1234)
	if err != nil {
		t.Fatal(err)
	}
	leaf := makeLeaf(signer, serialNumber)

	jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	keyAuth, err := KeyAuthorization("token", jwk)
	if err != nil {
		t.Fatal(err)
	}
	keyAuthSum := sha256.Sum256([]byte(keyAuth))
	sig, err := signer.Sign(rand.Reader, keyAuthSum[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	cborSig, err := cbor.Marshal(sig)
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		ctx  context.Context
		prov Provisioner
		ch   *Challenge
		jwk  *jose.JSONWebKey
		att  *attestationObject
	}
	tests := []struct {
		name    string
		args    args
		want    *stepAttestationData
		wantErr bool
	}{
		{"fail no intermediate", args{ctx, mustAttestationProvisioner(t, caRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "step",
			AttStatement: map[string]interface{}{
				"x5c": []interface{}{leaf.Raw, ca.Intermediate.Raw},
				"alg": -7,
				"sig": cborSig,
			},
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := doStepAttestationFormat(tt.args.ctx, tt.args.prov, tt.args.ch, tt.args.jwk, tt.args.att)
			if (err != nil) != tt.wantErr {
				t.Errorf("doStepAttestationFormat() error = %#v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("doStepAttestationFormat() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_deviceAttest01Validate(t *testing.T) {
	invalidPayload := "!?"
	errorPayload, err := json.Marshal(struct {
		Error string `json:"error"`
	}{
		Error: "an error",
	})
	require.NoError(t, err)
	errorBase64Payload, err := json.Marshal(struct {
		AttObj string `json:"attObj"`
	}{
		AttObj: "?!",
	})
	require.NoError(t, err)
	errorCBORPayload, err := json.Marshal(struct {
		AttObj string `json:"attObj"`
	}{
		AttObj: "AAAA",
	})
	require.NoError(t, err)
	type args struct {
		ctx     context.Context
		ch      *Challenge
		db      DB
		jwk     *jose.JSONWebKey
		payload []byte
	}
	type test struct {
		args    args
		wantErr *Error
	}
	tests := map[string]func(t *testing.T) test{
		"fail/json.Unmarshal": func(t *testing.T) test {
			return test{
				args: args{
					ch: &Challenge{
						ID:     "chID",
						Token:  "token",
						Type:   "device-attest-01",
						Status: StatusPending,
						Value:  "12345678",
					},
					payload: []byte(invalidPayload),
				},
				wantErr: NewErrorISE("error unmarshalling JSON: invalid character '!' looking for beginning of value"),
			}

		},
		"fail/storeError": func(t *testing.T) test {
			return test{
				args: args{
					ch: &Challenge{
						ID:     "chID",
						Token:  "token",
						Type:   "device-attest-01",
						Status: StatusPending,
						Value:  "12345678",
					},
					payload: errorPayload,
					db: &MockDB{
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusInvalid, updch.Status)
							assert.Equal(t, ChallengeType("device-attest-01"), updch.Type)
							assert.Equal(t, "12345678", updch.Value)

							err := NewError(ErrorRejectedIdentifierType, "payload contained error: an error")

							assert.EqualError(t, updch.Error.Err, err.Err.Error())
							assert.Equal(t, err.Type, updch.Error.Type)
							assert.Equal(t, err.Detail, updch.Error.Detail)
							assert.Equal(t, err.Status, updch.Error.Status)
							assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

							return errors.New("force")
						},
					},
				},
				wantErr: NewErrorISE("failure saving error to acme challenge: force"),
			}
		},
		"ok/storeError-return-nil": func(t *testing.T) test {
			return test{
				args: args{
					ch: &Challenge{
						ID:     "chID",
						Token:  "token",
						Type:   "device-attest-01",
						Status: StatusPending,
						Value:  "12345678",
					},
					payload: errorPayload,
					db: &MockDB{
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusInvalid, updch.Status)
							assert.Equal(t, ChallengeType("device-attest-01"), updch.Type)
							assert.Equal(t, "12345678", updch.Value)

							err := NewError(ErrorRejectedIdentifierType, "payload contained error: an error")

							assert.EqualError(t, updch.Error.Err, err.Err.Error())
							assert.Equal(t, err.Type, updch.Error.Type)
							assert.Equal(t, err.Detail, updch.Error.Detail)
							assert.Equal(t, err.Status, updch.Error.Status)
							assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

							return nil
						},
					},
				},
				wantErr: nil,
			}
		},
		"fail/base64-decode": func(t *testing.T) test {
			return test{
				args: args{
					ch: &Challenge{
						ID:     "chID",
						Token:  "token",
						Type:   "device-attest-01",
						Status: StatusPending,
						Value:  "12345678",
					},
					payload: errorBase64Payload,
				},
				wantErr: NewErrorISE("error base64 decoding attObj: illegal base64 data at input byte 0"),
			}
		},
		"fail/cbor.Unmarshal": func(t *testing.T) test {
			return test{
				args: args{
					ch: &Challenge{
						ID:     "chID",
						Token:  "token",
						Type:   "device-attest-01",
						Status: StatusPending,
						Value:  "12345678",
					},
					payload: errorCBORPayload,
				},
				wantErr: NewErrorISE("error unmarshalling CBOR: cbor: cannot unmarshal positive integer into Go value of type acme.attestationObject"),
			}
		},
		"ok/prov.IsAttestationFormatEnabled": func(t *testing.T) test {
			ca, err := minica.New()
			require.NoError(t, err)
			makeLeaf := func(signer crypto.Signer, serialNumber []byte) *x509.Certificate {
				leaf, err := ca.Sign(&x509.Certificate{
					Subject:   pkix.Name{CommonName: "attestation cert"},
					PublicKey: signer.Public(),
					ExtraExtensions: []pkix.Extension{
						{Id: oidYubicoSerialNumber, Value: serialNumber},
					},
				})
				if err != nil {
					t.Fatal(err)
				}
				return leaf
			}
			signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			serialNumber, err := asn1.Marshal(1234)
			require.NoError(t, err)
			leaf := makeLeaf(signer, serialNumber)
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			require.NoError(t, err)
			token := "token"
			keyAuth, err := KeyAuthorization(token, jwk)
			require.NoError(t, err)
			keyAuthSum := sha256.Sum256([]byte(keyAuth))
			sig, err := signer.Sign(rand.Reader, keyAuthSum[:], crypto.SHA256)
			require.NoError(t, err)
			cborSig, err := cbor.Marshal(sig)
			require.NoError(t, err)
			ctx := NewProvisionerContext(context.Background(), mustNonAttestationProvisioner(t))
			attObj, err := cbor.Marshal(struct {
				Format       string                 `json:"fmt"`
				AttStatement map[string]interface{} `json:"attStmt,omitempty"`
			}{
				Format: "step",
				AttStatement: map[string]interface{}{
					"x5c": []interface{}{leaf.Raw, ca.Intermediate.Raw},
					"alg": -7,
					"sig": cborSig,
				},
			})
			require.NoError(t, err)
			payload, err := json.Marshal(struct {
				AttObj string `json:"attObj"`
			}{
				AttObj: base64.RawURLEncoding.EncodeToString(attObj),
			})
			require.NoError(t, err)
			return test{
				args: args{
					ctx: ctx,
					ch: &Challenge{
						ID:     "chID",
						Token:  "token",
						Type:   "device-attest-01",
						Status: StatusPending,
						Value:  "12345678",
					},
					payload: payload,
					db: &MockDB{
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusInvalid, updch.Status)
							assert.Equal(t, ChallengeType("device-attest-01"), updch.Type)
							assert.Equal(t, "12345678", updch.Value)

							err := NewError(ErrorBadAttestationStatementType, "attestation format %q is not enabled", "step")

							assert.EqualError(t, updch.Error.Err, err.Err.Error())
							assert.Equal(t, err.Type, updch.Error.Type)
							assert.Equal(t, err.Detail, updch.Error.Detail)
							assert.Equal(t, err.Status, updch.Error.Status)
							assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

							return nil
						},
					},
				},
				wantErr: nil,
			}
		},
		"ok/doAppleAttestationFormat-storeError": func(t *testing.T) test {
			ctx := NewProvisionerContext(context.Background(), mustAttestationProvisioner(t, nil))
			attObj, err := cbor.Marshal(struct {
				Format       string                 `json:"fmt"`
				AttStatement map[string]interface{} `json:"attStmt,omitempty"`
			}{
				Format:       "apple",
				AttStatement: map[string]interface{}{},
			})
			require.NoError(t, err)
			payload, err := json.Marshal(struct {
				AttObj string `json:"attObj"`
			}{
				AttObj: base64.RawURLEncoding.EncodeToString(attObj),
			})
			require.NoError(t, err)
			return test{
				args: args{
					ctx: ctx,
					ch: &Challenge{
						ID:     "chID",
						Token:  "token",
						Type:   "device-attest-01",
						Status: StatusPending,
						Value:  "12345678",
					},
					payload: payload,
					db: &MockDB{
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusInvalid, updch.Status)
							assert.Equal(t, ChallengeType("device-attest-01"), updch.Type)
							assert.Equal(t, "12345678", updch.Value)

							err := NewError(ErrorBadAttestationStatementType, "x5c not present")

							assert.EqualError(t, updch.Error.Err, err.Err.Error())
							assert.Equal(t, err.Type, updch.Error.Type)
							assert.Equal(t, err.Detail, updch.Error.Detail)
							assert.Equal(t, err.Status, updch.Error.Status)
							assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

							return nil
						},
					},
				},
				wantErr: nil,
			}
		},
		"ok/doAppleAttestationFormat-non-matching-nonce": func(t *testing.T) test {
			ca, err := minica.New()
			require.NoError(t, err)
			signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			caRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Root.Raw})
			leaf, err := ca.Sign(&x509.Certificate{
				Subject:   pkix.Name{CommonName: "attestation cert"},
				PublicKey: signer.Public(),
				ExtraExtensions: []pkix.Extension{
					{Id: oidAppleSerialNumber, Value: []byte("serial-number")},
					{Id: oidAppleUniqueDeviceIdentifier, Value: []byte("udid")},
					{Id: oidAppleSecureEnclaveProcessorOSVersion, Value: []byte("16.0")},
					{Id: oidAppleNonce, Value: []byte("nonce")},
				},
			})
			require.NoError(t, err)
			ctx := NewProvisionerContext(context.Background(), mustAttestationProvisioner(t, caRoot))
			attObj, err := cbor.Marshal(struct {
				Format       string                 `json:"fmt"`
				AttStatement map[string]interface{} `json:"attStmt,omitempty"`
			}{
				Format: "apple",
				AttStatement: map[string]interface{}{
					"x5c": []interface{}{leaf.Raw, ca.Intermediate.Raw},
				},
			})
			require.NoError(t, err)
			payload, err := json.Marshal(struct {
				AttObj string `json:"attObj"`
			}{
				AttObj: base64.RawURLEncoding.EncodeToString(attObj),
			})
			require.NoError(t, err)
			return test{
				args: args{
					ctx: ctx,
					ch: &Challenge{
						ID:     "chID",
						Token:  "token",
						Type:   "device-attest-01",
						Status: StatusPending,
						Value:  "12345678",
					},
					payload: payload,
					db: &MockDB{
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusInvalid, updch.Status)
							assert.Equal(t, ChallengeType("device-attest-01"), updch.Type)
							assert.Equal(t, "12345678", updch.Value)

							err := NewError(ErrorBadAttestationStatementType, "challenge token does not match")

							assert.EqualError(t, updch.Error.Err, err.Err.Error())
							assert.Equal(t, err.Type, updch.Error.Type)
							assert.Equal(t, err.Detail, updch.Error.Detail)
							assert.Equal(t, err.Status, updch.Error.Status)
							assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

							return nil
						},
					},
				},
				wantErr: nil,
			}
		},
		"ok/doAppleAttestationFormat-non-matching-challenge-value": func(t *testing.T) test {
			ca, err := minica.New()
			require.NoError(t, err)
			signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			caRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Root.Raw})
			nonce := sha256.Sum256([]byte("nonce"))
			leaf, err := ca.Sign(&x509.Certificate{
				Subject:   pkix.Name{CommonName: "attestation cert"},
				PublicKey: signer.Public(),
				ExtraExtensions: []pkix.Extension{
					{Id: oidAppleSerialNumber, Value: []byte("serial-number")},
					{Id: oidAppleUniqueDeviceIdentifier, Value: []byte("udid")},
					{Id: oidAppleSecureEnclaveProcessorOSVersion, Value: []byte("16.0")},
					{Id: oidAppleNonce, Value: nonce[:]},
				},
			})
			require.NoError(t, err)
			ctx := NewProvisionerContext(context.Background(), mustAttestationProvisioner(t, caRoot))
			attObj, err := cbor.Marshal(struct {
				Format       string                 `json:"fmt"`
				AttStatement map[string]interface{} `json:"attStmt,omitempty"`
			}{
				Format: "apple",
				AttStatement: map[string]interface{}{
					"x5c": []interface{}{leaf.Raw, ca.Intermediate.Raw},
				},
			})
			require.NoError(t, err)
			payload, err := json.Marshal(struct {
				AttObj string `json:"attObj"`
			}{
				AttObj: base64.RawURLEncoding.EncodeToString(attObj),
			})
			require.NoError(t, err)
			return test{
				args: args{
					ctx: ctx,
					ch: &Challenge{
						ID:     "chID",
						Token:  "nonce",
						Type:   "device-attest-01",
						Status: StatusPending,
						Value:  "non-matching-value",
					},
					payload: payload,
					db: &MockDB{
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "nonce", updch.Token)
							assert.Equal(t, StatusInvalid, updch.Status)
							assert.Equal(t, ChallengeType("device-attest-01"), updch.Type)
							assert.Equal(t, "non-matching-value", updch.Value)

							err := NewError(ErrorBadAttestationStatementType, "permanent identifier does not match")

							assert.EqualError(t, updch.Error.Err, err.Err.Error())
							assert.Equal(t, err.Type, updch.Error.Type)
							assert.Equal(t, err.Detail, updch.Error.Detail)
							assert.Equal(t, err.Status, updch.Error.Status)
							assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

							return nil
						},
					},
				},
				wantErr: nil,
			}
		},
		"ok/doStepAttestationFormat-storeError": func(t *testing.T) test {
			ca, err := minica.New()
			require.NoError(t, err)
			caRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Root.Raw})
			signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			require.NoError(t, err)
			token := "token"
			keyAuth, err := KeyAuthorization(token, jwk)
			require.NoError(t, err)
			keyAuthSum := sha256.Sum256([]byte(keyAuth))
			sig, err := signer.Sign(rand.Reader, keyAuthSum[:], crypto.SHA256)
			require.NoError(t, err)
			cborSig, err := cbor.Marshal(sig)
			require.NoError(t, err)
			ctx := NewProvisionerContext(context.Background(), mustAttestationProvisioner(t, caRoot))
			attObj, err := cbor.Marshal(struct {
				Format       string                 `json:"fmt"`
				AttStatement map[string]interface{} `json:"attStmt,omitempty"`
			}{
				Format: "step",
				AttStatement: map[string]interface{}{
					"alg": -7,
					"sig": cborSig,
				},
			})
			require.NoError(t, err)
			payload, err := json.Marshal(struct {
				AttObj string `json:"attObj"`
			}{
				AttObj: base64.RawURLEncoding.EncodeToString(attObj),
			})
			require.NoError(t, err)
			return test{
				args: args{
					ctx: ctx,
					ch: &Challenge{
						ID:     "chID",
						Token:  "token",
						Type:   "device-attest-01",
						Status: StatusPending,
						Value:  "12345678",
					},
					payload: payload,
					db: &MockDB{
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusInvalid, updch.Status)
							assert.Equal(t, ChallengeType("device-attest-01"), updch.Type)
							assert.Equal(t, "12345678", updch.Value)

							err := NewError(ErrorBadAttestationStatementType, "x5c not present")

							assert.EqualError(t, updch.Error.Err, err.Err.Error())
							assert.Equal(t, err.Type, updch.Error.Type)
							assert.Equal(t, err.Detail, updch.Error.Detail)
							assert.Equal(t, err.Status, updch.Error.Status)
							assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

							return nil
						},
					},
				},
				wantErr: nil,
			}
		},
		"ok/doStepAttestationFormat-non-matching-identifier": func(t *testing.T) test {
			ca, err := minica.New()
			require.NoError(t, err)
			caRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Root.Raw})
			signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			require.NoError(t, err)
			token := "token"
			keyAuth, err := KeyAuthorization(token, jwk)
			require.NoError(t, err)
			keyAuthSum := sha256.Sum256([]byte(keyAuth))
			sig, err := signer.Sign(rand.Reader, keyAuthSum[:], crypto.SHA256)
			require.NoError(t, err)
			cborSig, err := cbor.Marshal(sig)
			require.NoError(t, err)
			ctx := NewProvisionerContext(context.Background(), mustAttestationProvisioner(t, caRoot))
			makeLeaf := func(signer crypto.Signer, serialNumber []byte) *x509.Certificate {
				leaf, err := ca.Sign(&x509.Certificate{
					Subject:   pkix.Name{CommonName: "attestation cert"},
					PublicKey: signer.Public(),
					ExtraExtensions: []pkix.Extension{
						{Id: oidYubicoSerialNumber, Value: serialNumber},
					},
				})
				if err != nil {
					t.Fatal(err)
				}
				return leaf
			}
			require.NoError(t, err)
			serialNumber, err := asn1.Marshal(87654321)
			require.NoError(t, err)
			leaf := makeLeaf(signer, serialNumber)
			attObj, err := cbor.Marshal(struct {
				Format       string                 `json:"fmt"`
				AttStatement map[string]interface{} `json:"attStmt,omitempty"`
			}{
				Format: "step",
				AttStatement: map[string]interface{}{
					"x5c": []interface{}{leaf.Raw, ca.Intermediate.Raw},
					"alg": -7,
					"sig": cborSig,
				},
			})
			require.NoError(t, err)
			payload, err := json.Marshal(struct {
				AttObj string `json:"attObj"`
			}{
				AttObj: base64.RawURLEncoding.EncodeToString(attObj),
			})
			require.NoError(t, err)
			return test{
				args: args{
					ctx: ctx,
					ch: &Challenge{
						ID:     "chID",
						Token:  "token",
						Type:   "device-attest-01",
						Status: StatusPending,
						Value:  "12345678",
					},
					payload: payload,
					db: &MockDB{
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusInvalid, updch.Status)
							assert.Equal(t, ChallengeType("device-attest-01"), updch.Type)
							assert.Equal(t, "12345678", updch.Value)

							err := NewError(ErrorBadAttestationStatementType, "permanent identifier does not match").
								AddSubproblems(NewSubproblemWithIdentifier(
									ErrorMalformedType,
									Identifier{Type: "permanent-identifier", Value: "12345678"},
									"challenge identifier \"12345678\" doesn't match the attested hardware identifier \"87654321\"",
								))

							assert.EqualError(t, updch.Error.Err, err.Err.Error())
							assert.Equal(t, err.Type, updch.Error.Type)
							assert.Equal(t, err.Detail, updch.Error.Detail)
							assert.Equal(t, err.Status, updch.Error.Status)
							assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

							return nil
						},
					},
					jwk: jwk,
				},
				wantErr: nil,
			}
		},
		"ok/unknown-attestation-format": func(t *testing.T) test {
			ca, err := minica.New()
			require.NoError(t, err)
			signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			require.NoError(t, err)
			token := "token"
			keyAuth, err := KeyAuthorization(token, jwk)
			require.NoError(t, err)
			keyAuthSum := sha256.Sum256([]byte(keyAuth))
			sig, err := signer.Sign(rand.Reader, keyAuthSum[:], crypto.SHA256)
			require.NoError(t, err)
			cborSig, err := cbor.Marshal(sig)
			require.NoError(t, err)
			ctx := NewProvisionerContext(context.Background(), mustNonAttestationProvisioner(t))
			makeLeaf := func(signer crypto.Signer, serialNumber []byte) *x509.Certificate {
				leaf, err := ca.Sign(&x509.Certificate{
					Subject:   pkix.Name{CommonName: "attestation cert"},
					PublicKey: signer.Public(),
					ExtraExtensions: []pkix.Extension{
						{Id: oidYubicoSerialNumber, Value: serialNumber},
					},
				})
				if err != nil {
					t.Fatal(err)
				}
				return leaf
			}
			require.NoError(t, err)
			serialNumber, err := asn1.Marshal(87654321)
			require.NoError(t, err)
			leaf := makeLeaf(signer, serialNumber)
			attObj, err := cbor.Marshal(struct {
				Format       string                 `json:"fmt"`
				AttStatement map[string]interface{} `json:"attStmt,omitempty"`
			}{
				Format: "bogus-format",
				AttStatement: map[string]interface{}{
					"x5c": []interface{}{leaf.Raw, ca.Intermediate.Raw},
					"alg": -7,
					"sig": cborSig,
				},
			})
			require.NoError(t, err)
			payload, err := json.Marshal(struct {
				AttObj string `json:"attObj"`
			}{
				AttObj: base64.RawURLEncoding.EncodeToString(attObj),
			})
			require.NoError(t, err)
			return test{
				args: args{
					ctx: ctx,
					ch: &Challenge{
						ID:     "chID",
						Token:  "token",
						Type:   "device-attest-01",
						Status: StatusPending,
						Value:  "12345678",
					},
					payload: payload,
					db: &MockDB{
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusInvalid, updch.Status)
							assert.Equal(t, ChallengeType("device-attest-01"), updch.Type)
							assert.Equal(t, "12345678", updch.Value)

							err := NewError(ErrorBadAttestationStatementType, "unexpected attestation object format")

							assert.EqualError(t, updch.Error.Err, err.Err.Error())
							assert.Equal(t, err.Type, updch.Error.Type)
							assert.Equal(t, err.Detail, updch.Error.Detail)
							assert.Equal(t, err.Status, updch.Error.Status)
							assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

							return nil
						},
					},
					jwk: jwk,
				},
				wantErr: nil,
			}
		},
		"fail/db.UpdateChallenge": func(t *testing.T) test {
			ca, err := minica.New()
			require.NoError(t, err)
			caRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Root.Raw})
			signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			require.NoError(t, err)
			token := "token"
			keyAuth, err := KeyAuthorization(token, jwk)
			require.NoError(t, err)
			keyAuthSum := sha256.Sum256([]byte(keyAuth))
			sig, err := signer.Sign(rand.Reader, keyAuthSum[:], crypto.SHA256)
			require.NoError(t, err)
			cborSig, err := cbor.Marshal(sig)
			require.NoError(t, err)
			ctx := NewProvisionerContext(context.Background(), mustAttestationProvisioner(t, caRoot))
			makeLeaf := func(signer crypto.Signer, serialNumber []byte) *x509.Certificate {
				leaf, err := ca.Sign(&x509.Certificate{
					Subject:   pkix.Name{CommonName: "attestation cert"},
					PublicKey: signer.Public(),
					ExtraExtensions: []pkix.Extension{
						{Id: oidYubicoSerialNumber, Value: serialNumber},
					},
				})
				if err != nil {
					t.Fatal(err)
				}
				return leaf
			}
			require.NoError(t, err)
			serialNumber, err := asn1.Marshal(12345678)
			require.NoError(t, err)
			leaf := makeLeaf(signer, serialNumber)
			attObj, err := cbor.Marshal(struct {
				Format       string                 `json:"fmt"`
				AttStatement map[string]interface{} `json:"attStmt,omitempty"`
			}{
				Format: "step",
				AttStatement: map[string]interface{}{
					"x5c": []interface{}{leaf.Raw, ca.Intermediate.Raw},
					"alg": -7,
					"sig": cborSig,
				},
			})
			require.NoError(t, err)
			payload, err := json.Marshal(struct {
				AttObj string `json:"attObj"`
			}{
				AttObj: base64.RawURLEncoding.EncodeToString(attObj),
			})
			require.NoError(t, err)
			return test{
				args: args{
					ctx: ctx,
					ch: &Challenge{
						ID:     "chID",
						Token:  "token",
						Type:   "device-attest-01",
						Status: StatusPending,
						Value:  "12345678",
					},
					payload: payload,
					db: &MockDB{
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusValid, updch.Status)
							assert.Equal(t, ChallengeType("device-attest-01"), updch.Type)
							assert.Equal(t, "12345678", updch.Value)

							return errors.New("force")
						},
					},
					jwk: jwk,
				},
				wantErr: NewError(ErrorServerInternalType, "error updating challenge: force"),
			}
		},
		"ok": func(t *testing.T) test {
			ca, err := minica.New()
			require.NoError(t, err)
			caRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Root.Raw})
			signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			require.NoError(t, err)
			token := "token"
			keyAuth, err := KeyAuthorization(token, jwk)
			require.NoError(t, err)
			keyAuthSum := sha256.Sum256([]byte(keyAuth))
			sig, err := signer.Sign(rand.Reader, keyAuthSum[:], crypto.SHA256)
			require.NoError(t, err)
			cborSig, err := cbor.Marshal(sig)
			require.NoError(t, err)
			ctx := NewProvisionerContext(context.Background(), mustAttestationProvisioner(t, caRoot))
			makeLeaf := func(signer crypto.Signer, serialNumber []byte) *x509.Certificate {
				leaf, err := ca.Sign(&x509.Certificate{
					Subject:   pkix.Name{CommonName: "attestation cert"},
					PublicKey: signer.Public(),
					ExtraExtensions: []pkix.Extension{
						{Id: oidYubicoSerialNumber, Value: serialNumber},
					},
				})
				if err != nil {
					t.Fatal(err)
				}
				return leaf
			}
			require.NoError(t, err)
			serialNumber, err := asn1.Marshal(12345678)
			require.NoError(t, err)
			leaf := makeLeaf(signer, serialNumber)
			attObj, err := cbor.Marshal(struct {
				Format       string                 `json:"fmt"`
				AttStatement map[string]interface{} `json:"attStmt,omitempty"`
			}{
				Format: "step",
				AttStatement: map[string]interface{}{
					"x5c": []interface{}{leaf.Raw, ca.Intermediate.Raw},
					"alg": -7,
					"sig": cborSig,
				},
			})
			require.NoError(t, err)
			payload, err := json.Marshal(struct {
				AttObj string `json:"attObj"`
			}{
				AttObj: base64.RawURLEncoding.EncodeToString(attObj),
			})
			require.NoError(t, err)
			return test{
				args: args{
					ctx: ctx,
					ch: &Challenge{
						ID:     "chID",
						Token:  "token",
						Type:   "device-attest-01",
						Status: StatusPending,
						Value:  "12345678",
					},
					payload: payload,
					db: &MockDB{
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusValid, updch.Status)
							assert.Equal(t, ChallengeType("device-attest-01"), updch.Type)
							assert.Equal(t, "12345678", updch.Value)

							return nil
						},
					},
					jwk: jwk,
				},
				wantErr: nil,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)

			if err := deviceAttest01Validate(tc.args.ctx, tc.args.ch, tc.args.db, tc.args.jwk, tc.args.payload); err != nil {
				assert.Error(t, tc.wantErr)
				assert.EqualError(t, err, tc.wantErr.Error())
				return
			}

			assert.Nil(t, tc.wantErr)
		})
	}
}
