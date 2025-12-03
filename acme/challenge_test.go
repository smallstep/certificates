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
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/x509util"

	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/provisioner"
	wireprovisioner "github.com/smallstep/certificates/authority/provisioner/wire"
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

func fatalError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
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

func mustAccountAndKeyAuthorization(t *testing.T, token string) (*jose.JSONWebKey, string) {
	t.Helper()

	jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
	fatalError(t, err)

	keyAuth, err := KeyAuthorization(token, jwk)
	fatalError(t, err)
	return jwk, keyAuth
}

func mustAttestApple(t *testing.T, nonce string) ([]byte, *x509.Certificate, *x509.Certificate) {
	t.Helper()

	ca, err := minica.New()
	fatalError(t, err)

	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fatalError(t, err)

	nonceSum := sha256.Sum256([]byte(nonce))
	leaf, err := ca.Sign(&x509.Certificate{
		Subject:   pkix.Name{CommonName: "attestation cert"},
		PublicKey: signer.Public(),
		ExtraExtensions: []pkix.Extension{
			{Id: oidAppleSerialNumber, Value: []byte("serial-number")},
			{Id: oidAppleUniqueDeviceIdentifier, Value: []byte("udid")},
			{Id: oidAppleSecureEnclaveProcessorOSVersion, Value: []byte("16.0")},
			{Id: oidAppleNonce, Value: nonceSum[:]},
		},
	})
	fatalError(t, err)

	attObj, err := cbor.Marshal(struct {
		Format       string                 `json:"fmt"`
		AttStatement map[string]interface{} `json:"attStmt,omitempty"`
	}{
		Format: "apple",
		AttStatement: map[string]interface{}{
			"x5c": []interface{}{leaf.Raw, ca.Intermediate.Raw},
		},
	})
	fatalError(t, err)

	payload, err := json.Marshal(struct {
		AttObj string `json:"attObj"`
	}{
		AttObj: base64.RawURLEncoding.EncodeToString(attObj),
	})
	fatalError(t, err)

	return payload, leaf, ca.Root
}

func mustAttestYubikey(t *testing.T, _, keyAuthorization string, serial int) ([]byte, *x509.Certificate, *x509.Certificate) {
	t.Helper()

	ca, err := minica.New()
	fatalError(t, err)

	keyAuthSum := sha256.Sum256([]byte(keyAuthorization))

	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fatalError(t, err)
	sig, err := signer.Sign(rand.Reader, keyAuthSum[:], crypto.SHA256)
	fatalError(t, err)
	cborSig, err := cbor.Marshal(sig)
	fatalError(t, err)

	serialNumber, err := asn1.Marshal(serial)
	fatalError(t, err)

	leaf, err := ca.Sign(&x509.Certificate{
		Subject:   pkix.Name{CommonName: "attestation cert"},
		PublicKey: signer.Public(),
		ExtraExtensions: []pkix.Extension{
			{Id: oidYubicoSerialNumber, Value: serialNumber},
		},
	})
	fatalError(t, err)

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
	fatalError(t, err)

	payload, err := json.Marshal(struct {
		AttObj string `json:"attObj"`
	}{
		AttObj: base64.RawURLEncoding.EncodeToString(attObj),
	})
	fatalError(t, err)

	return payload, leaf, ca.Root
}

type stepManagedDevice struct {
	DeviceID string
}

func mustAttestStepManagedDeviceID(t *testing.T, _, keyAuthorization, serialNumber string) ([]byte, *x509.Certificate, *x509.Certificate) {
	t.Helper()

	ca, err := minica.New()
	require.NoError(t, err)

	keyAuthSum := sha256.Sum256([]byte(keyAuthorization))

	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	sig, err := signer.Sign(rand.Reader, keyAuthSum[:], crypto.SHA256)
	require.NoError(t, err)
	cborSig, err := cbor.Marshal(sig)
	require.NoError(t, err)

	v, err := asn1.Marshal(stepManagedDevice{DeviceID: serialNumber})
	require.NoError(t, err)

	leaf, err := ca.Sign(&x509.Certificate{
		Subject:   pkix.Name{CommonName: "attestation cert"},
		PublicKey: signer.Public(),
		ExtraExtensions: []pkix.Extension{
			{Id: oidStepManagedDevice, Value: v},
		},
	})
	require.NoError(t, err)

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

	return payload, leaf, ca.Root
}

func newWireProvisionerWithOptions(t *testing.T, options *provisioner.Options) *provisioner.ACME {
	t.Helper()
	prov := &provisioner.ACME{
		Type:    "ACME",
		Name:    "wire",
		Options: options,
		Challenges: []provisioner.ACMEChallenge{
			provisioner.WIREOIDC_01,
			provisioner.WIREDPOP_01,
		},
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
				err:   NewErrorISE("error generating JWK thumbprint: go-jose/go-jose: unknown key type 'string'"),
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
	fakeKey := `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA5c+4NKZSNQcR1T8qN6SjwgdPZQ0Ge12Ylx/YeGAJ35k=
-----END PUBLIC KEY-----`
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
				err: NewErrorISE(`unexpected challenge type "foo"`),
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

						err := NewError(ErrorConnectionType, "error doing TLS dial for %v: force", ch.Value)

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
			payload, err := json.Marshal(struct {
				Error string `json:"error"`
			}{
				Error: "an error",
			})
			assert.NoError(t, err)
			return test{
				ch: &Challenge{
					ID:              "chID",
					AuthorizationID: "azID",
					Token:           "token",
					Type:            "device-attest-01",
					Status:          StatusPending,
					Value:           "12345678",
				},
				payload: payload,
				db: &MockDB{
					MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
						assert.Equal(t, "azID", id)
						return &Authorization{ID: "azID"}, nil
					},
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, StatusInvalid, updch.Status)
						assert.Equal(t, ChallengeType("device-attest-01"), updch.Type)
						assert.Equal(t, "12345678", updch.Value)
						assert.Equal(t, payload, updch.Payload)
						assert.Empty(t, updch.PayloadFormat)

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
			jwk, keyAuth := mustAccountAndKeyAuthorization(t, "token")
			payload, leaf, root := mustAttestYubikey(t, "nonce", keyAuth, 1234)

			caRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})
			ctx := NewProvisionerContext(context.Background(), mustAttestationProvisioner(t, caRoot))

			return test{
				ch: &Challenge{
					ID:              "chID",
					AuthorizationID: "azID",
					Token:           "token",
					Type:            "device-attest-01",
					Status:          StatusPending,
					Value:           "1234",
				},
				payload: payload,
				ctx:     ctx,
				jwk:     jwk,
				db: &MockDB{
					MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
						assert.Equal(t, "azID", id)
						return &Authorization{ID: "azID"}, nil
					},
					MockUpdateAuthorization: func(ctx context.Context, az *Authorization) error {
						fingerprint, err := keyutil.Fingerprint(leaf.PublicKey)
						assert.NoError(t, err)
						assert.Equal(t, "azID", az.ID)
						assert.Equal(t, fingerprint, az.Fingerprint)
						return nil
					},
					MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
						assert.Equal(t, "chID", updch.ID)
						assert.Equal(t, "token", updch.Token)
						assert.Equal(t, StatusValid, updch.Status)
						assert.Equal(t, ChallengeType("device-attest-01"), updch.Type)
						assert.Equal(t, "1234", updch.Value)
						assert.Equal(t, payload, updch.Payload)
						assert.Equal(t, "step", updch.PayloadFormat)

						return nil
					},
				},
			}
		},
		"ok/wire-oidc-01": func(t *testing.T) test {
			jwk, keyAuth := mustAccountAndKeyAuthorization(t, "token")
			signerJWK, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			require.NoError(t, err)
			signer, err := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.SignatureAlgorithm(signerJWK.Algorithm),
				Key:       signerJWK,
			}, new(jose.SignerOptions))
			require.NoError(t, err)
			srv := mustJWKServer(t, signerJWK.Public())
			tokenBytes, err := json.Marshal(struct {
				jose.Claims
				Name              string `json:"name,omitempty"`
				PreferredUsername string `json:"preferred_username,omitempty"`
				KeyAuth           string `json:"keyauth"`
				ACMEAudience      string `json:"acme_aud"`
			}{
				Claims: jose.Claims{
					Issuer:   srv.URL,
					Audience: []string{"test"},
					Expiry:   jose.NewNumericDate(time.Now().Add(1 * time.Minute)),
				},
				Name:              "Alice Smith",
				PreferredUsername: "wireapp://%40alice_wire@wire.com",
				KeyAuth:           keyAuth,
				ACMEAudience:      "https://ca.example.com/acme/wire/challenge/azID/chID",
			})
			require.NoError(t, err)
			signed, err := signer.Sign(tokenBytes)
			require.NoError(t, err)
			idToken, err := signed.CompactSerialize()
			require.NoError(t, err)
			payload, err := json.Marshal(struct {
				IDToken string `json:"id_token"`
			}{
				IDToken: idToken,
			})
			require.NoError(t, err)
			valueBytes, err := json.Marshal(struct {
				Name     string `json:"name,omitempty"`
				Domain   string `json:"domain,omitempty"`
				ClientID string `json:"client-id,omitempty"`
				Handle   string `json:"handle,omitempty"`
			}{
				Name:     "Alice Smith",
				Domain:   "wire.com",
				ClientID: "wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com",
				Handle:   "wireapp://%40alice_wire@wire.com",
			})
			require.NoError(t, err)
			ctx := NewProvisionerContext(context.Background(), newWireProvisionerWithOptions(t, &provisioner.Options{
				Wire: &wireprovisioner.Options{
					OIDC: &wireprovisioner.OIDCOptions{
						Provider: &wireprovisioner.Provider{
							IssuerURL:  srv.URL,
							JWKSURL:    srv.URL + "/keys",
							Algorithms: []string{"ES256"},
						},
						Config: &wireprovisioner.Config{
							ClientID:            "test",
							SignatureAlgorithms: []string{"ES256"},
							Now:                 time.Now,
						},
						TransformTemplate: "",
					},
					DPOP: &wireprovisioner.DPOPOptions{
						SigningKey: []byte(fakeKey),
					},
				},
			}))
			ctx = NewLinkerContext(ctx, NewLinker("ca.example.com", "acme"))
			return test{
				ch: &Challenge{
					ID:              "chID",
					AuthorizationID: "azID",
					AccountID:       "accID",
					Token:           "token",
					Type:            "wire-oidc-01",
					Status:          StatusPending,
					Value:           string(valueBytes),
				},
				srv:     srv,
				payload: payload,
				ctx:     ctx,
				jwk:     jwk,
				db: &MockWireDB{
					MockDB: MockDB{
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusValid, updch.Status)
							assert.Equal(t, ChallengeType("wire-oidc-01"), updch.Type)
							assert.Equal(t, string(valueBytes), updch.Value)
							return nil
						},
					},
					MockGetAllOrdersByAccountID: func(ctx context.Context, accountID string) ([]string, error) {
						assert.Equal(t, "accID", accountID)
						return []string{"orderID"}, nil
					},
					MockCreateOidcToken: func(ctx context.Context, orderID string, idToken map[string]interface{}) error {
						assert.Equal(t, "orderID", orderID)
						assert.Equal(t, "Alice Smith", idToken["name"].(string))
						assert.Equal(t, "wireapp://%40alice_wire@wire.com", idToken["preferred_username"].(string))
						return nil
					},
				},
			}
		},
		"fail/wire-oidc-01-no-wire-db": func(t *testing.T) test {
			jwk, keyAuth := mustAccountAndKeyAuthorization(t, "token")
			signerJWK, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			require.NoError(t, err)
			signer, err := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.SignatureAlgorithm(signerJWK.Algorithm),
				Key:       signerJWK,
			}, new(jose.SignerOptions))
			require.NoError(t, err)
			srv := mustJWKServer(t, signerJWK.Public())
			tokenBytes, err := json.Marshal(struct {
				jose.Claims
				Name              string `json:"name,omitempty"`
				PreferredUsername string `json:"preferred_username,omitempty"`
				KeyAuth           string `json:"keyauth"`
				ACMEAudience      string `json:"acme_aud"`
			}{
				Claims: jose.Claims{
					Issuer:   srv.URL,
					Audience: []string{"test"},
					Expiry:   jose.NewNumericDate(time.Now().Add(1 * time.Minute)),
				},
				Name:              "Alice Smith",
				PreferredUsername: "wireapp://%40alice_wire@wire.com",
				KeyAuth:           keyAuth,
				ACMEAudience:      "https://ca.example.com/acme/wire/challenge/azID/chID",
			})
			require.NoError(t, err)
			signed, err := signer.Sign(tokenBytes)
			require.NoError(t, err)
			idToken, err := signed.CompactSerialize()
			require.NoError(t, err)
			payload, err := json.Marshal(struct {
				IDToken string `json:"id_token"`
			}{
				IDToken: idToken,
			})
			require.NoError(t, err)
			valueBytes, err := json.Marshal(struct {
				Name     string `json:"name,omitempty"`
				Domain   string `json:"domain,omitempty"`
				ClientID string `json:"client-id,omitempty"`
				Handle   string `json:"handle,omitempty"`
			}{
				Name:     "Alice Smith",
				Domain:   "wire.com",
				ClientID: "wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com",
				Handle:   "wireapp://%40alice_wire@wire.com",
			})
			require.NoError(t, err)
			ctx := NewProvisionerContext(context.Background(), newWireProvisionerWithOptions(t, &provisioner.Options{
				Wire: &wireprovisioner.Options{
					OIDC: &wireprovisioner.OIDCOptions{
						Provider: &wireprovisioner.Provider{
							IssuerURL:  srv.URL,
							JWKSURL:    srv.URL + "/keys",
							Algorithms: []string{"ES256"},
						},
						Config: &wireprovisioner.Config{
							ClientID:            "test",
							SignatureAlgorithms: []string{"ES256"},
							Now:                 time.Now,
						},
						TransformTemplate: "",
					},
					DPOP: &wireprovisioner.DPOPOptions{
						SigningKey: []byte(fakeKey),
					},
				},
			}))
			ctx = NewLinkerContext(ctx, NewLinker("ca.example.com", "acme"))
			return test{
				ch: &Challenge{
					ID:              "chID",
					AuthorizationID: "azID",
					AccountID:       "accID",
					Token:           "token",
					Type:            "wire-oidc-01",
					Status:          StatusPending,
					Value:           string(valueBytes),
				},
				srv:     srv,
				payload: payload,
				ctx:     ctx,
				jwk:     jwk,
				db:      &MockDB{},
				err: &Error{
					Type:   "urn:ietf:params:acme:error:serverInternal",
					Detail: "The server experienced an internal error",
					Status: 500,
					Err:    errors.New("db *acme.MockDB is not a WireDB"),
				},
			}
		},
		"ok/wire-dpop-01": func(t *testing.T) test {
			jwk, keyAuth := mustAccountAndKeyAuthorization(t, "token")
			_ = keyAuth // TODO(hs): keyAuth (not) required for DPoP? Or needs to be added to validation?
			dpopSigner, err := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.SignatureAlgorithm(jwk.Algorithm),
				Key:       jwk,
			}, new(jose.SignerOptions))
			require.NoError(t, err)
			signerJWK, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			require.NoError(t, err)
			signer, err := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.SignatureAlgorithm(signerJWK.Algorithm),
				Key:       signerJWK,
			}, new(jose.SignerOptions))
			require.NoError(t, err)
			signerPEMBlock, err := pemutil.Serialize(signerJWK.Public().Key)
			require.NoError(t, err)
			signerPEMBytes := pem.EncodeToMemory(signerPEMBlock)
			dpopBytes, err := json.Marshal(struct {
				jose.Claims
				Challenge string `json:"chal,omitempty"`
				Handle    string `json:"handle,omitempty"`
				Nonce     string `json:"nonce,omitempty"`
				HTU       string `json:"htu,omitempty"`
				Name      string `json:"name,omitempty"`
			}{
				Claims: jose.Claims{
					Subject:  "wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com",
					Audience: jose.Audience{"https://ca.example.com/acme/wire/challenge/azID/chID"},
				},
				Challenge: "token",
				Handle:    "wireapp://%40alice_wire@wire.com",
				Nonce:     "nonce",
				HTU:       "http://issuer.example.com",
				Name:      "Alice Smith",
			})
			require.NoError(t, err)
			dpop, err := dpopSigner.Sign(dpopBytes)
			require.NoError(t, err)
			proof, err := dpop.CompactSerialize()
			require.NoError(t, err)
			tokenBytes, err := json.Marshal(struct {
				jose.Claims
				Challenge string `json:"chal,omitempty"`
				Nonce     string `json:"nonce,omitempty"`
				Cnf       struct {
					Kid string `json:"kid,omitempty"`
				} `json:"cnf"`
				Proof      string `json:"proof,omitempty"`
				ClientID   string `json:"client_id"`
				APIVersion int    `json:"api_version"`
				Scope      string `json:"scope"`
			}{
				Claims: jose.Claims{
					Issuer:   "http://issuer.example.com",
					Audience: jose.Audience{"https://ca.example.com/acme/wire/challenge/azID/chID"},
					Expiry:   jose.NewNumericDate(time.Now().Add(1 * time.Minute)),
				},
				Challenge: "token",
				Nonce:     "nonce",
				Cnf: struct {
					Kid string `json:"kid,omitempty"`
				}{
					Kid: jwk.KeyID,
				},
				Proof:      proof,
				ClientID:   "wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com",
				APIVersion: 5,
				Scope:      "wire_client_id",
			})
			require.NoError(t, err)
			signed, err := signer.Sign(tokenBytes)
			require.NoError(t, err)
			accessToken, err := signed.CompactSerialize()
			require.NoError(t, err)
			payload, err := json.Marshal(struct {
				AccessToken string `json:"access_token"`
			}{
				AccessToken: accessToken,
			})
			require.NoError(t, err)
			valueBytes, err := json.Marshal(struct {
				Name     string `json:"name,omitempty"`
				Domain   string `json:"domain,omitempty"`
				ClientID string `json:"client-id,omitempty"`
				Handle   string `json:"handle,omitempty"`
			}{
				Name:     "Alice Smith",
				Domain:   "wire.com",
				ClientID: "wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com",
				Handle:   "wireapp://%40alice_wire@wire.com",
			})
			require.NoError(t, err)
			ctx := NewProvisionerContext(context.Background(), newWireProvisionerWithOptions(t, &provisioner.Options{
				Wire: &wireprovisioner.Options{
					OIDC: &wireprovisioner.OIDCOptions{
						Provider: &wireprovisioner.Provider{
							IssuerURL:  "http://issuerexample.com",
							Algorithms: []string{"ES256"},
						},
						Config: &wireprovisioner.Config{
							ClientID:            "test",
							SignatureAlgorithms: []string{"ES256"},
							Now:                 time.Now,
						},
						TransformTemplate: "",
					},
					DPOP: &wireprovisioner.DPOPOptions{
						Target:     "http://issuer.example.com",
						SigningKey: signerPEMBytes,
					},
				},
			}))
			ctx = NewLinkerContext(ctx, NewLinker("ca.example.com", "acme"))
			return test{
				ch: &Challenge{
					ID:              "chID",
					AuthorizationID: "azID",
					AccountID:       "accID",
					Token:           "token",
					Type:            "wire-dpop-01",
					Status:          StatusPending,
					Value:           string(valueBytes),
				},
				payload: payload,
				ctx:     ctx,
				jwk:     jwk,
				db: &MockWireDB{
					MockDB: MockDB{
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusValid, updch.Status)
							assert.Equal(t, ChallengeType("wire-dpop-01"), updch.Type)
							assert.Equal(t, string(valueBytes), updch.Value)
							return nil
						},
					},
					MockGetAllOrdersByAccountID: func(ctx context.Context, accountID string) ([]string, error) {
						assert.Equal(t, "accID", accountID)
						return []string{"orderID"}, nil
					},
					MockCreateDpopToken: func(ctx context.Context, orderID string, dpop map[string]interface{}) error {
						assert.Equal(t, "orderID", orderID)
						assert.Equal(t, "token", dpop["chal"].(string))
						assert.Equal(t, "wireapp://%40alice_wire@wire.com", dpop["handle"].(string))
						assert.Equal(t, "wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com", dpop["sub"].(string))
						return nil
					},
				},
			}
		},
		"fail/wire-dpop-01-no-wire-db": func(t *testing.T) test {
			jwk, _ := mustAccountAndKeyAuthorization(t, "token")
			dpopSigner, err := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.SignatureAlgorithm(jwk.Algorithm),
				Key:       jwk,
			}, new(jose.SignerOptions))
			require.NoError(t, err)
			signerJWK, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			require.NoError(t, err)
			signer, err := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.SignatureAlgorithm(signerJWK.Algorithm),
				Key:       signerJWK,
			}, new(jose.SignerOptions))
			require.NoError(t, err)
			signerPEMBlock, err := pemutil.Serialize(signerJWK.Public().Key)
			require.NoError(t, err)
			signerPEMBytes := pem.EncodeToMemory(signerPEMBlock)
			dpopBytes, err := json.Marshal(struct {
				jose.Claims
				Challenge string `json:"chal,omitempty"`
				Handle    string `json:"handle,omitempty"`
				Nonce     string `json:"nonce,omitempty"`
				HTU       string `json:"htu,omitempty"`
				Name      string `json:"name,omitempty"`
			}{
				Claims: jose.Claims{
					Subject:  "wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com",
					Audience: jose.Audience{"https://ca.example.com/acme/wire/challenge/azID/chID"},
				},
				Challenge: "token",
				Handle:    "wireapp://%40alice_wire@wire.com",
				Nonce:     "nonce",
				HTU:       "http://issuer.example.com",
				Name:      "Alice Smith",
			})
			require.NoError(t, err)
			dpop, err := dpopSigner.Sign(dpopBytes)
			require.NoError(t, err)
			proof, err := dpop.CompactSerialize()
			require.NoError(t, err)
			tokenBytes, err := json.Marshal(struct {
				jose.Claims
				Challenge string `json:"chal,omitempty"`
				Nonce     string `json:"nonce,omitempty"`
				Cnf       struct {
					Kid string `json:"kid,omitempty"`
				} `json:"cnf"`
				Proof      string `json:"proof,omitempty"`
				ClientID   string `json:"client_id"`
				APIVersion int    `json:"api_version"`
				Scope      string `json:"scope"`
			}{
				Claims: jose.Claims{
					Issuer:   "http://issuer.example.com",
					Audience: jose.Audience{"https://ca.example.com/acme/wire/challenge/azID/chID"},
					Expiry:   jose.NewNumericDate(time.Now().Add(1 * time.Minute)),
				},
				Challenge: "token",
				Nonce:     "nonce",
				Cnf: struct {
					Kid string `json:"kid,omitempty"`
				}{
					Kid: jwk.KeyID,
				},
				Proof:      proof,
				ClientID:   "wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com",
				APIVersion: 5,
				Scope:      "wire_client_id",
			})
			require.NoError(t, err)
			signed, err := signer.Sign(tokenBytes)
			require.NoError(t, err)
			accessToken, err := signed.CompactSerialize()
			require.NoError(t, err)
			payload, err := json.Marshal(struct {
				AccessToken string `json:"access_token"`
			}{
				AccessToken: accessToken,
			})
			require.NoError(t, err)
			valueBytes, err := json.Marshal(struct {
				Name     string `json:"name,omitempty"`
				Domain   string `json:"domain,omitempty"`
				ClientID string `json:"client-id,omitempty"`
				Handle   string `json:"handle,omitempty"`
			}{
				Name:     "Alice Smith",
				Domain:   "wire.com",
				ClientID: "wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com",
				Handle:   "wireapp://%40alice_wire@wire.com",
			})
			require.NoError(t, err)
			ctx := NewProvisionerContext(context.Background(), newWireProvisionerWithOptions(t, &provisioner.Options{
				Wire: &wireprovisioner.Options{
					OIDC: &wireprovisioner.OIDCOptions{
						Provider: &wireprovisioner.Provider{
							IssuerURL:  "http://issuerexample.com",
							Algorithms: []string{"ES256"},
						},
						Config: &wireprovisioner.Config{
							ClientID:            "test",
							SignatureAlgorithms: []string{"ES256"},
							Now:                 time.Now,
						},
						TransformTemplate: "",
					},
					DPOP: &wireprovisioner.DPOPOptions{
						Target:     "http://issuer.example.com",
						SigningKey: signerPEMBytes,
					},
				},
			}))
			ctx = NewLinkerContext(ctx, NewLinker("ca.example.com", "acme"))
			return test{
				ch: &Challenge{
					ID:              "chID",
					AuthorizationID: "azID",
					AccountID:       "accID",
					Token:           "token",
					Type:            "wire-dpop-01",
					Status:          StatusPending,
					Value:           string(valueBytes),
				},
				payload: payload,
				ctx:     ctx,
				jwk:     jwk,
				db:      &MockDB{},
				err: &Error{
					Type:   "urn:ietf:params:acme:error:serverInternal",
					Detail: "The server experienced an internal error",
					Status: 500,
					Err:    errors.New("db *acme.MockDB is not a WireDB"),
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
			err := tc.ch.Validate(ctx, tc.db, tc.jwk, tc.payload)
			if tc.err != nil {
				var k *Error
				if errors.As(err, &k) {
					assert.Equal(t, tc.err.Type, k.Type)
					assert.Equal(t, tc.err.Detail, k.Detail)
					assert.Equal(t, tc.err.Status, k.Status)
					assert.Equal(t, tc.err.Err.Error(), k.Err.Error())
				} else {
					assert.Fail(t, "unexpected error type")
				}
				return
			}

			assert.NoError(t, err)
		})
	}
}

func mustJWKServer(t *testing.T, pub jose.JSONWebKey) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	b, err := json.Marshal(struct {
		Keys []jose.JSONWebKey `json:"keys,omitempty"`
	}{
		Keys: []jose.JSONWebKey{pub},
	})
	require.NoError(t, err)
	jwks := string(b)

	wellKnown := fmt.Sprintf(`{
		"issuer": "%[1]s",
		"authorization_endpoint": "%[1]s/auth",
		"token_endpoint": "%[1]s/token",
		"jwks_uri": "%[1]s/keys",
		"userinfo_endpoint": "%[1]s/userinfo",
		"id_token_signing_alg_values_supported": ["ES256"]
	}`, server.URL)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, req *http.Request) {
		_, err := io.WriteString(w, wellKnown)
		if err != nil {
			w.WriteHeader(500)
		}
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, req *http.Request) {
		_, err := io.WriteString(w, jwks)
		if err != nil {
			w.WriteHeader(500)
		}
	})

	t.Cleanup(server.Close)
	return server
}

type errReader int

func (errReader) Read([]byte) (int, error) {
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
				err: NewErrorISE("error generating JWK thumbprint: go-jose/go-jose: unknown key type 'string'"),
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
				err: NewErrorISE("error generating JWK thumbprint: go-jose/go-jose: unknown key type 'string'"),
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

func (c *noopConn) Read(_ []byte) (n int, err error)  { return 0, io.EOF }
func (c *noopConn) Write(_ []byte) (n int, err error) { return 0, io.EOF }
func (c *noopConn) Close() error                      { return nil }
func (c *noopConn) LocalAddr() net.Addr               { return &net.IPAddr{IP: net.IPv4zero, Zone: ""} }
func (c *noopConn) RemoteAddr() net.Addr              { return &net.IPAddr{IP: net.IPv4zero, Zone: ""} }
func (c *noopConn) SetDeadline(time.Time) error       { return nil }
func (c *noopConn) SetReadDeadline(time.Time) error   { return nil }
func (c *noopConn) SetWriteDeadline(time.Time) error  { return nil }

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

						err := NewError(ErrorConnectionType, "error doing TLS dial for %v: force", ch.Value)

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

						err := NewError(ErrorConnectionType, "error doing TLS dial for %v: force", ch.Value)

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

						err := NewError(ErrorConnectionType, "error doing TLS dial for %v: context deadline exceeded", ch.Value)

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
				err: NewErrorISE("error generating JWK thumbprint: go-jose/go-jose: unknown key type 'string'"),
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
		name       string
		strictFQDN bool
		value      string
		want       string
	}{
		{
			name:       "dns",
			strictFQDN: false,
			value:      "www.example.com",
			want:       "www.example.com",
		},
		{
			name:       "dns strict",
			strictFQDN: true,
			value:      "www.example.com",
			want:       "www.example.com.",
		},
		{
			name:       "rooted dns",
			strictFQDN: false,
			value:      "www.example.com.",
			want:       "www.example.com.",
		},
		{
			name:       "rooted dns strict",
			strictFQDN: true,
			value:      "www.example.com.",
			want:       "www.example.com.",
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
			tmp := StrictFQDN
			t.Cleanup(func() {
				StrictFQDN = tmp
			})
			StrictFQDN = tt.strictFQDN
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
	fingerprint, err := keyutil.Fingerprint(signer.Public())
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
			Fingerprint:  fingerprint,
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
	require.NoError(t, err)

	caRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Root.Raw})

	makeLeaf := func(signer crypto.Signer, serialNumber []byte) *x509.Certificate {
		leaf, err := ca.Sign(&x509.Certificate{
			Subject:   pkix.Name{CommonName: "attestation cert"},
			PublicKey: signer.Public(),
			ExtraExtensions: []pkix.Extension{
				{Id: oidYubicoSerialNumber, Value: serialNumber},
			},
		})
		require.NoError(t, err)
		return leaf
	}

	makeLeafWithStepManagedDeviceID := func(signer crypto.Signer, serialNumber string) *x509.Certificate {
		v, err := asn1.Marshal(stepManagedDevice{DeviceID: serialNumber})
		require.NoError(t, err)
		leaf, err := ca.Sign(&x509.Certificate{
			Subject:   pkix.Name{CommonName: "attestation cert"},
			PublicKey: signer.Public(),
			ExtraExtensions: []pkix.Extension{
				{Id: oidStepManagedDevice, Value: v},
			},
		})
		require.NoError(t, err)
		return leaf
	}

	mustSigner := func(kty, crv string, size int) crypto.Signer {
		s, err := keyutil.GenerateSigner(kty, crv, size)
		require.NoError(t, err)
		return s
	}

	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	fingerprint, err := keyutil.Fingerprint(signer.Public())
	require.NoError(t, err)

	serialNumber, err := asn1.Marshal(1234)
	require.NoError(t, err)

	leaf := makeLeaf(signer, serialNumber)
	leafWithStepManagedDeviceID := makeLeafWithStepManagedDeviceID(signer, "1234")

	jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
	require.NoError(t, err)

	keyAuth, err := KeyAuthorization("token", jwk)
	require.NoError(t, err)

	keyAuthSum := sha256.Sum256([]byte(keyAuth))
	sig, err := signer.Sign(rand.Reader, keyAuthSum[:], crypto.SHA256)
	require.NoError(t, err)

	cborSig, err := cbor.Marshal(sig)
	require.NoError(t, err)

	otherSigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	otherSig, err := otherSigner.Sign(rand.Reader, keyAuthSum[:], crypto.SHA256)
	require.NoError(t, err)

	otherCBORSig, err := cbor.Marshal(otherSig)
	require.NoError(t, err)

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
			Fingerprint:  fingerprint,
		}, false},
		{"ok/step-managed-device-id", args{ctx, mustAttestationProvisioner(t, caRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "step",
			AttStatement: map[string]interface{}{
				"x5c": []interface{}{leafWithStepManagedDeviceID.Raw, ca.Intermediate.Raw},
				"alg": -7,
				"sig": cborSig,
			},
		}}, &stepAttestationData{
			SerialNumber: "1234",
			Certificate:  leafWithStepManagedDeviceID,
			Fingerprint:  fingerprint,
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
	emptyPayload, err := json.Marshal(struct {
		AttObj string `json:"attObj"`
	}{
		AttObj: base64.RawURLEncoding.EncodeToString([]byte("")),
	})
	require.NoError(t, err)
	emptyObjectPayload, err := json.Marshal(struct {
		AttObj string `json:"attObj"`
	}{
		AttObj: base64.RawURLEncoding.EncodeToString([]byte("{}")),
	})
	require.NoError(t, err)
	attObj, err := cbor.Marshal(struct {
		Format       string                 `json:"fmt"`
		AttStatement map[string]interface{} `json:"attStmt,omitempty"`
	}{
		Format: "step",
		AttStatement: map[string]interface{}{
			"alg": -7,
			"sig": "",
		},
	})
	require.NoError(t, err)
	errorNonWellformedCBORPayload, err := json.Marshal(struct {
		AttObj string `json:"attObj"`
	}{
		AttObj: base64.RawURLEncoding.EncodeToString(attObj[:len(attObj)-1]), // cut the CBOR encoded data off
	})
	require.NoError(t, err)
	unsupportedFormatAttObj, err := cbor.Marshal(struct {
		Format       string                 `json:"fmt"`
		AttStatement map[string]interface{} `json:"attStmt,omitempty"`
	}{
		Format: "unsupported-format",
		AttStatement: map[string]interface{}{
			"alg": -7,
			"sig": "",
		},
	})
	require.NoError(t, err)
	errorUnsupportedFormat, err := json.Marshal(struct {
		AttObj string `json:"attObj"`
	}{
		AttObj: base64.RawURLEncoding.EncodeToString(unsupportedFormatAttObj),
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
		"fail/getAuthorization": func(t *testing.T) test {
			return test{
				args: args{
					ch: &Challenge{
						ID:              "chID",
						AuthorizationID: "azID",
						Token:           "token",
						Type:            "device-attest-01",
						Status:          StatusPending,
						Value:           "12345678",
					},
					db: &MockDB{
						MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
							return nil, errors.New("not found")
						},
					},
					payload: []byte(invalidPayload),
				},
				wantErr: NewErrorISE("error loading authorization: not found"),
			}
		},
		"fail/json.Unmarshal": func(t *testing.T) test {
			return test{
				args: args{
					ch: &Challenge{
						ID:              "chID",
						AuthorizationID: "azID",
						Token:           "token",
						Type:            "device-attest-01",
						Status:          StatusPending,
						Value:           "12345678",
					},
					db: &MockDB{
						MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
							assert.Equal(t, "azID", id)
							return &Authorization{ID: "azID"}, nil
						},
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
						ID:              "chID",
						AuthorizationID: "azID",
						Token:           "token",
						Type:            "device-attest-01",
						Status:          StatusPending,
						Value:           "12345678",
					},
					payload: errorPayload,
					db: &MockDB{
						MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
							assert.Equal(t, "azID", id)
							return &Authorization{ID: "azID"}, nil
						},
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
						ID:              "chID",
						AuthorizationID: "azID",
						Token:           "token",
						Type:            "device-attest-01",
						Status:          StatusPending,
						Value:           "12345678",
					},
					payload: errorPayload,
					db: &MockDB{
						MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
							assert.Equal(t, "azID", id)
							return &Authorization{ID: "azID"}, nil
						},
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusInvalid, updch.Status)
							assert.Equal(t, ChallengeType("device-attest-01"), updch.Type)
							assert.Equal(t, "12345678", updch.Value)
							assert.Equal(t, errorPayload, updch.Payload)
							assert.Empty(t, updch.PayloadFormat)

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
		"ok/base64-decode": func(t *testing.T) test {
			return test{
				args: args{
					ch: &Challenge{
						ID:              "chID",
						AuthorizationID: "azID",
						Token:           "token",
						Type:            "device-attest-01",
						Status:          StatusPending,
						Value:           "12345678",
					},
					db: &MockDB{
						MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
							assert.Equal(t, "azID", id)
							return &Authorization{ID: "azID"}, nil
						},
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusInvalid, updch.Status)
							assert.Equal(t, ChallengeType("device-attest-01"), updch.Type)
							assert.Equal(t, "12345678", updch.Value)
							assert.Equal(t, errorBase64Payload, updch.Payload)
							assert.Empty(t, updch.PayloadFormat)

							err := NewDetailedError(ErrorBadAttestationStatementType, "failed base64 decoding attObj %q", "?!")

							assert.EqualError(t, updch.Error.Err, err.Err.Error())
							assert.Equal(t, err.Type, updch.Error.Type)
							assert.Equal(t, err.Detail, updch.Error.Detail)
							assert.Equal(t, err.Status, updch.Error.Status)
							assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

							return nil
						},
					},
					payload: errorBase64Payload,
				},
			}
		},
		"ok/empty-attobj": func(t *testing.T) test {
			return test{
				args: args{
					ch: &Challenge{
						ID:              "chID",
						AuthorizationID: "azID",
						Token:           "token",
						Type:            "device-attest-01",
						Status:          StatusPending,
						Value:           "12345678",
					},
					db: &MockDB{
						MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
							assert.Equal(t, "azID", id)
							return &Authorization{ID: "azID"}, nil
						},
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusInvalid, updch.Status)
							assert.Equal(t, ChallengeType("device-attest-01"), updch.Type)
							assert.Equal(t, "12345678", updch.Value)
							assert.Equal(t, emptyPayload, updch.Payload)
							assert.Empty(t, updch.PayloadFormat)

							err := NewDetailedError(ErrorBadAttestationStatementType, "attObj must not be empty")

							assert.EqualError(t, updch.Error.Err, err.Err.Error())
							assert.Equal(t, err.Type, updch.Error.Type)
							assert.Equal(t, err.Detail, updch.Error.Detail)
							assert.Equal(t, err.Status, updch.Error.Status)
							assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

							return nil
						},
					},
					payload: emptyPayload,
				},
			}
		},
		"ok/empty-json-attobj": func(t *testing.T) test {
			return test{
				args: args{
					ch: &Challenge{
						ID:              "chID",
						AuthorizationID: "azID",
						Token:           "token",
						Type:            "device-attest-01",
						Status:          StatusPending,
						Value:           "12345678",
					},
					db: &MockDB{
						MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
							assert.Equal(t, "azID", id)
							return &Authorization{ID: "azID"}, nil
						},
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusInvalid, updch.Status)
							assert.Equal(t, ChallengeType("device-attest-01"), updch.Type)
							assert.Equal(t, "12345678", updch.Value)
							assert.Equal(t, emptyObjectPayload, updch.Payload)
							assert.Empty(t, updch.PayloadFormat)

							err := NewDetailedError(ErrorBadAttestationStatementType, "attObj must not be empty")

							assert.EqualError(t, updch.Error.Err, err.Err.Error())
							assert.Equal(t, err.Type, updch.Error.Type)
							assert.Equal(t, err.Detail, updch.Error.Detail)
							assert.Equal(t, err.Status, updch.Error.Status)
							assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

							return nil
						},
					},
					payload: emptyObjectPayload,
				},
			}
		},
		"ok/cborDecoder.Wellformed": func(t *testing.T) test {
			return test{
				args: args{
					ch: &Challenge{
						ID:              "chID",
						AuthorizationID: "azID",
						Token:           "token",
						Type:            "device-attest-01",
						Status:          StatusPending,
						Value:           "12345678",
					},
					db: &MockDB{
						MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
							assert.Equal(t, "azID", id)
							return &Authorization{ID: "azID"}, nil
						},
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusInvalid, updch.Status)
							assert.Equal(t, ChallengeType("device-attest-01"), updch.Type)
							assert.Equal(t, "12345678", updch.Value)
							assert.Equal(t, errorNonWellformedCBORPayload, updch.Payload)
							assert.Empty(t, updch.PayloadFormat)

							err := NewDetailedError(ErrorBadAttestationStatementType, "attObj is not well formed CBOR: unexpected EOF")

							assert.EqualError(t, updch.Error.Err, err.Err.Error())
							assert.Equal(t, err.Type, updch.Error.Type)
							assert.Equal(t, err.Detail, updch.Error.Detail)
							assert.Equal(t, err.Status, updch.Error.Status)
							assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

							return nil
						},
					},
					payload: errorNonWellformedCBORPayload,
				},
			}
		},
		"ok/unsupported-attestation-format": func(t *testing.T) test {
			ctx := NewProvisionerContext(context.Background(), mustNonAttestationProvisioner(t))
			return test{
				args: args{
					ctx: ctx,
					ch: &Challenge{
						ID:              "chID",
						AuthorizationID: "azID",
						Token:           "token",
						Type:            "device-attest-01",
						Status:          StatusPending,
						Value:           "12345678",
					},
					db: &MockDB{
						MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
							assert.Equal(t, "azID", id)
							return &Authorization{ID: "azID"}, nil
						},
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusInvalid, updch.Status)
							assert.Equal(t, ChallengeType("device-attest-01"), updch.Type)
							assert.Equal(t, "12345678", updch.Value)
							assert.Equal(t, errorUnsupportedFormat, updch.Payload)
							assert.Empty(t, updch.PayloadFormat)

							err := NewDetailedError(ErrorBadAttestationStatementType, "unsupported attestation object format %q", "unsupported-format")

							assert.EqualError(t, updch.Error.Err, err.Err.Error())
							assert.Equal(t, err.Type, updch.Error.Type)
							assert.Equal(t, err.Detail, updch.Error.Detail)
							assert.Equal(t, err.Status, updch.Error.Status)
							assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

							return nil
						},
					},
					payload: errorUnsupportedFormat,
				},
			}
		},
		"ok/prov.IsAttestationFormatEnabled": func(t *testing.T) test {
			jwk, keyAuth := mustAccountAndKeyAuthorization(t, "token")
			payload, _, _ := mustAttestYubikey(t, "nonce", keyAuth, 12345678)
			ctx := NewProvisionerContext(context.Background(), mustNonAttestationProvisioner(t))

			return test{
				args: args{
					ctx: ctx,
					jwk: jwk,
					ch: &Challenge{
						ID:              "chID",
						AuthorizationID: "azID",
						Token:           "token",
						Type:            "device-attest-01",
						Status:          StatusPending,
						Value:           "12345678",
					},
					payload: payload,
					db: &MockDB{
						MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
							assert.Equal(t, "azID", id)
							return &Authorization{ID: "azID"}, nil
						},
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusInvalid, updch.Status)
							assert.Equal(t, ChallengeType("device-attest-01"), updch.Type)
							assert.Equal(t, "12345678", updch.Value)
							assert.Equal(t, payload, updch.Payload)
							assert.Empty(t, updch.PayloadFormat)

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
						ID:              "chID",
						AuthorizationID: "azID",
						Token:           "token",
						Type:            "device-attest-01",
						Status:          StatusPending,
						Value:           "12345678",
					},
					payload: payload,
					db: &MockDB{
						MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
							assert.Equal(t, "azID", id)
							return &Authorization{ID: "azID"}, nil
						},
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusInvalid, updch.Status)
							assert.Equal(t, ChallengeType("device-attest-01"), updch.Type)
							assert.Equal(t, "12345678", updch.Value)
							assert.Equal(t, payload, updch.Payload)
							assert.Empty(t, updch.PayloadFormat)

							err := NewDetailedError(ErrorBadAttestationStatementType, "x5c not present")

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
			jwk, _ := mustAccountAndKeyAuthorization(t, "token")
			payload, _, root := mustAttestApple(t, "bad-nonce")

			caRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})
			ctx := NewProvisionerContext(context.Background(), mustAttestationProvisioner(t, caRoot))

			return test{
				args: args{
					ctx: ctx,
					jwk: jwk,
					ch: &Challenge{
						ID:              "chID",
						AuthorizationID: "azID",
						Token:           "token",
						Type:            "device-attest-01",
						Status:          StatusPending,
						Value:           "serial-number",
					},
					payload: payload,
					db: &MockDB{
						MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
							assert.Equal(t, "azID", id)
							return &Authorization{ID: "azID"}, nil
						},
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusInvalid, updch.Status)
							assert.Equal(t, ChallengeType("device-attest-01"), updch.Type)
							assert.Equal(t, "serial-number", updch.Value)
							assert.Equal(t, payload, updch.Payload)
							assert.Empty(t, updch.PayloadFormat)

							err := NewDetailedError(ErrorBadAttestationStatementType, "challenge token does not match")

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
			jwk, _ := mustAccountAndKeyAuthorization(t, "token")
			payload, _, root := mustAttestApple(t, "nonce")

			caRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})
			ctx := NewProvisionerContext(context.Background(), mustAttestationProvisioner(t, caRoot))
			return test{
				args: args{
					ctx: ctx,
					jwk: jwk,
					ch: &Challenge{
						ID:              "chID",
						AuthorizationID: "azID",
						Token:           "nonce",
						Type:            "device-attest-01",
						Status:          StatusPending,
						Value:           "non-matching-value",
					},
					payload: payload,
					db: &MockDB{
						MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
							assert.Equal(t, "azID", id)
							return &Authorization{ID: "azID"}, nil
						},
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "nonce", updch.Token)
							assert.Equal(t, StatusInvalid, updch.Status)
							assert.Equal(t, ChallengeType("device-attest-01"), updch.Type)
							assert.Equal(t, "non-matching-value", updch.Value)
							assert.Equal(t, payload, updch.Payload)
							assert.Empty(t, updch.PayloadFormat)

							subproblem := NewSubproblemWithIdentifier(
								ErrorRejectedIdentifierType,
								Identifier{Type: "permanent-identifier", Value: "non-matching-value"},
								`challenge identifier "non-matching-value" doesn't match any of the attested hardware identifiers ["udid" "serial-number"]`,
							)
							err := NewDetailedError(ErrorBadAttestationStatementType, "permanent identifier does not match").AddSubproblems(subproblem)

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
						ID:              "chID",
						AuthorizationID: "azID",
						Token:           "token",
						Type:            "device-attest-01",
						Status:          StatusPending,
						Value:           "12345678",
					},
					payload: payload,
					db: &MockDB{
						MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
							assert.Equal(t, "azID", id)
							return &Authorization{ID: "azID"}, nil
						},
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusInvalid, updch.Status)
							assert.Equal(t, ChallengeType("device-attest-01"), updch.Type)
							assert.Equal(t, "12345678", updch.Value)
							assert.Equal(t, payload, updch.Payload)
							assert.Empty(t, updch.PayloadFormat)

							err := NewDetailedError(ErrorBadAttestationStatementType, "x5c not present")

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
			jwk, keyAuth := mustAccountAndKeyAuthorization(t, "token")
			payload, leaf, root := mustAttestYubikey(t, "nonce", keyAuth, 87654321)

			caRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})
			ctx := NewProvisionerContext(context.Background(), mustAttestationProvisioner(t, caRoot))

			return test{
				args: args{
					ctx: ctx,
					jwk: jwk,
					ch: &Challenge{
						ID:              "chID",
						AuthorizationID: "azID",
						Token:           "token",
						Type:            "device-attest-01",
						Status:          StatusPending,
						Value:           "12345678",
					},
					payload: payload,
					db: &MockDB{
						MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
							assert.Equal(t, "azID", id)
							return &Authorization{ID: "azID"}, nil
						},
						MockUpdateAuthorization: func(ctx context.Context, az *Authorization) error {
							fingerprint, err := keyutil.Fingerprint(leaf.PublicKey)
							assert.NoError(t, err)
							assert.Equal(t, "azID", az.ID)
							assert.Equal(t, fingerprint, az.Fingerprint)
							return nil
						},
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusInvalid, updch.Status)
							assert.Equal(t, ChallengeType("device-attest-01"), updch.Type)
							assert.Equal(t, "12345678", updch.Value)
							assert.Equal(t, payload, updch.Payload)
							assert.Empty(t, updch.PayloadFormat)

							err := NewDetailedError(ErrorBadAttestationStatementType, "permanent identifier does not match").
								AddSubproblems(NewSubproblemWithIdentifier(
									ErrorRejectedIdentifierType,
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
						ID:              "chID",
						AuthorizationID: "azID",
						Token:           "token",
						Type:            "device-attest-01",
						Status:          StatusPending,
						Value:           "12345678",
					},
					payload: payload,
					db: &MockDB{
						MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
							assert.Equal(t, "azID", id)
							return &Authorization{ID: "azID"}, nil
						},
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusInvalid, updch.Status)
							assert.Equal(t, ChallengeType("device-attest-01"), updch.Type)
							assert.Equal(t, "12345678", updch.Value)
							assert.Equal(t, payload, updch.Payload)
							assert.Empty(t, updch.PayloadFormat)

							err := NewDetailedError(ErrorBadAttestationStatementType, `unsupported attestation object format "bogus-format"`)

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
		"fail/db.UpdateAuthorization": func(t *testing.T) test {
			jwk, keyAuth := mustAccountAndKeyAuthorization(t, "token")
			payload, leaf, root := mustAttestYubikey(t, "nonce", keyAuth, 12345678)

			caRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})
			ctx := NewProvisionerContext(context.Background(), mustAttestationProvisioner(t, caRoot))

			return test{
				args: args{
					ctx: ctx,
					jwk: jwk,
					ch: &Challenge{
						ID:              "chID",
						AuthorizationID: "azID",
						Token:           "token",
						Type:            "device-attest-01",
						Status:          StatusPending,
						Value:           "12345678",
					},
					payload: payload,
					db: &MockDB{
						MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
							assert.Equal(t, "azID", id)
							return &Authorization{ID: "azID"}, nil
						},
						MockUpdateAuthorization: func(ctx context.Context, az *Authorization) error {
							fingerprint, err := keyutil.Fingerprint(leaf.PublicKey)
							assert.NoError(t, err)
							assert.Equal(t, "azID", az.ID)
							assert.Equal(t, fingerprint, az.Fingerprint)
							return errors.New("force")
						},
					},
				},
				wantErr: NewError(ErrorServerInternalType, "error updating authorization: force"),
			}
		},
		"fail/db.UpdateChallenge": func(t *testing.T) test {
			jwk, keyAuth := mustAccountAndKeyAuthorization(t, "token")
			payload, leaf, root := mustAttestYubikey(t, "nonce", keyAuth, 12345678)

			caRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})
			ctx := NewProvisionerContext(context.Background(), mustAttestationProvisioner(t, caRoot))

			return test{
				args: args{
					ctx: ctx,
					jwk: jwk,
					ch: &Challenge{
						ID:              "chID",
						AuthorizationID: "azID",
						Token:           "token",
						Type:            "device-attest-01",
						Status:          StatusPending,
						Value:           "12345678",
					},
					payload: payload,
					db: &MockDB{
						MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
							assert.Equal(t, "azID", id)
							return &Authorization{ID: "azID"}, nil
						},
						MockUpdateAuthorization: func(ctx context.Context, az *Authorization) error {
							fingerprint, err := keyutil.Fingerprint(leaf.PublicKey)
							assert.NoError(t, err)
							assert.Equal(t, "azID", az.ID)
							assert.Equal(t, fingerprint, az.Fingerprint)
							return nil
						},
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusValid, updch.Status)
							assert.Equal(t, ChallengeType("device-attest-01"), updch.Type)
							assert.Equal(t, "12345678", updch.Value)
							assert.Equal(t, payload, updch.Payload)
							assert.Equal(t, "step", updch.PayloadFormat)

							return errors.New("force")
						},
					},
				},
				wantErr: NewError(ErrorServerInternalType, "error updating challenge: force"),
			}
		},
		"ok": func(t *testing.T) test {
			jwk, keyAuth := mustAccountAndKeyAuthorization(t, "token")
			payload, leaf, root := mustAttestYubikey(t, "nonce", keyAuth, 12345678)

			caRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})
			ctx := NewProvisionerContext(context.Background(), mustAttestationProvisioner(t, caRoot))

			return test{
				args: args{
					ctx: ctx,
					jwk: jwk,
					ch: &Challenge{
						ID:              "chID",
						AuthorizationID: "azID",
						Token:           "token",
						Type:            "device-attest-01",
						Status:          StatusPending,
						Value:           "12345678",
					},
					payload: payload,
					db: &MockDB{
						MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
							assert.Equal(t, "azID", id)
							return &Authorization{ID: "azID"}, nil
						},
						MockUpdateAuthorization: func(ctx context.Context, az *Authorization) error {
							fingerprint, err := keyutil.Fingerprint(leaf.PublicKey)
							assert.NoError(t, err)
							assert.Equal(t, "azID", az.ID)
							assert.Equal(t, fingerprint, az.Fingerprint)
							return nil
						},
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusValid, updch.Status)
							assert.Equal(t, ChallengeType("device-attest-01"), updch.Type)
							assert.Equal(t, "12345678", updch.Value)
							assert.Equal(t, payload, updch.Payload)
							assert.Equal(t, "step", updch.PayloadFormat)

							return nil
						},
					},
				},
				wantErr: nil,
			}
		},
		"ok/step-managed-device-id": func(t *testing.T) test {
			jwk, keyAuth := mustAccountAndKeyAuthorization(t, "token")
			payload, leaf, root := mustAttestStepManagedDeviceID(t, "nonce", keyAuth, "12345678")

			caRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})
			ctx := NewProvisionerContext(context.Background(), mustAttestationProvisioner(t, caRoot))

			return test{
				args: args{
					ctx: ctx,
					jwk: jwk,
					ch: &Challenge{
						ID:              "chID",
						AuthorizationID: "azID",
						Token:           "token",
						Type:            "device-attest-01",
						Status:          StatusPending,
						Value:           "12345678",
					},
					payload: payload,
					db: &MockDB{
						MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
							assert.Equal(t, "azID", id)
							return &Authorization{ID: "azID"}, nil
						},
						MockUpdateAuthorization: func(ctx context.Context, az *Authorization) error {
							fingerprint, err := keyutil.Fingerprint(leaf.PublicKey)
							assert.NoError(t, err)
							assert.Equal(t, "azID", az.ID)
							assert.Equal(t, fingerprint, az.Fingerprint)
							return nil
						},
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusValid, updch.Status)
							assert.Equal(t, ChallengeType("device-attest-01"), updch.Type)
							assert.Equal(t, "12345678", updch.Value)
							assert.Equal(t, payload, updch.Payload)
							assert.Equal(t, "step", updch.PayloadFormat)

							return nil
						},
					},
				},
				wantErr: nil,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)

			if err := deviceAttest01Validate(tc.args.ctx, tc.args.ch, tc.args.db, tc.args.jwk, tc.args.payload); err != nil {
				if assert.Error(t, tc.wantErr) {
					assert.ErrorContains(t, err, tc.wantErr.Error())
				}
				return
			}

			assert.Nil(t, tc.wantErr)
		})
	}
}

var (
	oidTPMManufacturer = asn1.ObjectIdentifier{2, 23, 133, 2, 1}
	oidTPMModel        = asn1.ObjectIdentifier{2, 23, 133, 2, 2}
	oidTPMVersion      = asn1.ObjectIdentifier{2, 23, 133, 2, 3}
)

func generateValidAKCertificate(t *testing.T) *x509.Certificate {
	t.Helper()
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		PublicKey:          signer.Public(),
		Version:            3,
		IsCA:               false,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{oidTCGKpAIKCertificate},
	}
	asn1Value := []byte(fmt.Sprintf(`{"extraNames":[{"type": %q, "value": %q},{"type": %q, "value": %q},{"type": %q, "value": %q}]}`, oidTPMManufacturer, "1414747215", oidTPMModel, "SLB 9670 TPM2.0", oidTPMVersion, "7.55"))
	sans := []x509util.SubjectAlternativeName{
		{Type: x509util.DirectoryNameType,
			ASN1Value: asn1Value},
	}
	ext, err := createSubjectAltNameExtension(nil, nil, nil, nil, sans, true)
	require.NoError(t, err)
	ext.Set(template)
	ca, err := minica.New()
	require.NoError(t, err)
	cert, err := ca.Sign(template)
	require.NoError(t, err)

	return cert
}

func Test_validateAKCertificate(t *testing.T) {
	cert := generateValidAKCertificate(t)
	tests := []struct {
		name   string
		c      *x509.Certificate
		expErr error
	}{
		{
			name:   "ok",
			c:      cert,
			expErr: nil,
		},
		{
			name: "fail/version",
			c: &x509.Certificate{
				Version: 1,
			},
			expErr: errors.New("AK certificate has invalid version 1; only version 3 is allowed"),
		},
		{
			name: "fail/subject",
			c: &x509.Certificate{
				Version: 3,
				Subject: pkix.Name{CommonName: "fail!"},
			},
			expErr: errors.New(`AK certificate subject must be empty; got "CN=fail!"`),
		},
		{
			name: "fail/isCA",
			c: &x509.Certificate{
				Version: 3,
				IsCA:    true,
			},
			expErr: errors.New("AK certificate must not be a CA"),
		},
		{
			name: "fail/extendedKeyUsage",
			c: &x509.Certificate{
				Version: 3,
			},
			expErr: errors.New("AK certificate is missing Extended Key Usage extension"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAKCertificate(tt.c)
			if tt.expErr != nil {
				if assert.Error(t, err) {
					assert.EqualError(t, err, tt.expErr.Error())
				}
				return
			}

			assert.NoError(t, err)
		})
	}
}

func Test_validateAKCertificateSubjectAlternativeNames(t *testing.T) {
	ok := generateValidAKCertificate(t)
	t.Helper()
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	getBase := func() *x509.Certificate {
		return &x509.Certificate{
			PublicKey:          signer.Public(),
			Version:            3,
			IsCA:               false,
			UnknownExtKeyUsage: []asn1.ObjectIdentifier{oidTCGKpAIKCertificate},
		}
	}

	ca, err := minica.New()
	require.NoError(t, err)
	missingManufacturerASN1 := []byte(fmt.Sprintf(`{"extraNames":[{"type": %q, "value": %q},{"type": %q, "value": %q}]}`, oidTPMModel, "SLB 9670 TPM2.0", oidTPMVersion, "7.55"))
	sans := []x509util.SubjectAlternativeName{
		{Type: x509util.DirectoryNameType,
			ASN1Value: missingManufacturerASN1},
	}
	ext, err := createSubjectAltNameExtension(nil, nil, nil, nil, sans, true)
	require.NoError(t, err)
	missingManufacturer := getBase()
	ext.Set(missingManufacturer)

	missingManufacturer, err = ca.Sign(missingManufacturer)
	require.NoError(t, err)

	missingModelASN1 := []byte(fmt.Sprintf(`{"extraNames":[{"type": %q, "value": %q},{"type": %q, "value": %q}]}`, oidTPMManufacturer, "1414747215", oidTPMVersion, "7.55"))
	sans = []x509util.SubjectAlternativeName{
		{Type: x509util.DirectoryNameType,
			ASN1Value: missingModelASN1},
	}
	ext, err = createSubjectAltNameExtension(nil, nil, nil, nil, sans, true)
	require.NoError(t, err)
	missingModel := getBase()
	ext.Set(missingModel)

	missingModel, err = ca.Sign(missingModel)
	require.NoError(t, err)

	missingFirmwareVersionASN1 := []byte(fmt.Sprintf(`{"extraNames":[{"type": %q, "value": %q},{"type": %q, "value": %q}]}`, oidTPMManufacturer, "1414747215", oidTPMModel, "SLB 9670 TPM2.0"))
	sans = []x509util.SubjectAlternativeName{
		{Type: x509util.DirectoryNameType,
			ASN1Value: missingFirmwareVersionASN1},
	}
	ext, err = createSubjectAltNameExtension(nil, nil, nil, nil, sans, true)
	require.NoError(t, err)
	missingFirmwareVersion := getBase()
	ext.Set(missingFirmwareVersion)

	missingFirmwareVersion, err = ca.Sign(missingFirmwareVersion)
	require.NoError(t, err)

	tests := []struct {
		name   string
		c      *x509.Certificate
		expErr error
	}{
		{"ok", ok, nil},
		{"fail/missing-manufacturer", missingManufacturer, errors.New("missing TPM manufacturer")},
		{"fail/missing-model", missingModel, errors.New("missing TPM model")},
		{"fail/missing-firmware-version", missingFirmwareVersion, errors.New("missing TPM version")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAKCertificateSubjectAlternativeNames(tt.c)
			if tt.expErr != nil {
				if assert.Error(t, err) {
					assert.EqualError(t, err, tt.expErr.Error())
				}
				return
			}

			assert.NoError(t, err)
		})
	}
}

func Test_validateAKCertificateExtendedKeyUsage(t *testing.T) {
	ok := generateValidAKCertificate(t)
	missingEKU := &x509.Certificate{}
	t.Helper()
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		PublicKey:   signer.Public(),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	ca, err := minica.New()
	require.NoError(t, err)
	wrongEKU, err := ca.Sign(template)
	require.NoError(t, err)
	tests := []struct {
		name   string
		c      *x509.Certificate
		expErr error
	}{
		{"ok", ok, nil},
		{"fail/wrong-eku", wrongEKU, errors.New("AK certificate is missing Extended Key Usage value tcg-kp-AIKCertificate (2.23.133.8.3)")},
		{"fail/missing-eku", missingEKU, errors.New("AK certificate is missing Extended Key Usage extension")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAKCertificateExtendedKeyUsage(tt.c)
			if tt.expErr != nil {
				if assert.Error(t, err) {
					assert.EqualError(t, err, tt.expErr.Error())
				}
				return
			}

			assert.NoError(t, err)
		})
	}
}

// createSubjectAltNameExtension will construct an Extension containing all
// SubjectAlternativeNames held in a Certificate. It implements more types than
// the golang x509 library, so it is used whenever OtherName or RegisteredID
// type SANs are present in the certificate.
//
// See also https://datatracker.ietf.org/doc/html/rfc5280.html#section-4.2.1.6
//
// TODO(hs): this was copied from go.step.sm/crypto/x509util to make it easier
// to create the SAN extension for testing purposes. Should it be exposed instead?
func createSubjectAltNameExtension(dnsNames, emailAddresses x509util.MultiString, ipAddresses x509util.MultiIP, uris x509util.MultiURL, sans []x509util.SubjectAlternativeName, subjectIsEmpty bool) (x509util.Extension, error) {
	var zero x509util.Extension

	var rawValues []asn1.RawValue
	for _, dnsName := range dnsNames {
		rawValue, err := x509util.SubjectAlternativeName{
			Type: x509util.DNSType, Value: dnsName,
		}.RawValue()
		if err != nil {
			return zero, err
		}

		rawValues = append(rawValues, rawValue)
	}

	for _, emailAddress := range emailAddresses {
		rawValue, err := x509util.SubjectAlternativeName{
			Type: x509util.EmailType, Value: emailAddress,
		}.RawValue()
		if err != nil {
			return zero, err
		}

		rawValues = append(rawValues, rawValue)
	}

	for _, ip := range ipAddresses {
		rawValue, err := x509util.SubjectAlternativeName{
			Type: x509util.IPType, Value: ip.String(),
		}.RawValue()
		if err != nil {
			return zero, err
		}

		rawValues = append(rawValues, rawValue)
	}

	for _, uri := range uris {
		rawValue, err := x509util.SubjectAlternativeName{
			Type: x509util.URIType, Value: uri.String(),
		}.RawValue()
		if err != nil {
			return zero, err
		}

		rawValues = append(rawValues, rawValue)
	}

	for _, san := range sans {
		rawValue, err := san.RawValue()
		if err != nil {
			return zero, err
		}

		rawValues = append(rawValues, rawValue)
	}

	// Now marshal the rawValues into the ASN1 sequence, and create an Extension object to hold the extension
	rawBytes, err := asn1.Marshal(rawValues)
	if err != nil {
		return zero, fmt.Errorf("error marshaling SubjectAlternativeName extension to ASN1: %w", err)
	}

	return x509util.Extension{
		ID:       x509util.ObjectIdentifier(oidSubjectAlternativeName),
		Critical: subjectIsEmpty,
		Value:    rawBytes,
	}, nil
}

func Test_tlsAlpn01ChallengeHost(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name       string
		strictFQDN bool
		args       args
		want       string
	}{
		{"dns", false, args{"smallstep.com"}, "smallstep.com"},
		{"dns strict", true, args{"smallstep.com"}, "smallstep.com."},
		{"rooted dns", false, args{"smallstep.com."}, "smallstep.com."},
		{"rooted dns strict", true, args{"smallstep.com."}, "smallstep.com."},
		{"ipv4", true, args{"1.2.3.4"}, "1.2.3.4"},
		{"ipv6", true, args{"2607:f8b0:4023:1009::71"}, "2607:f8b0:4023:1009::71"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmp := StrictFQDN
			t.Cleanup(func() {
				StrictFQDN = tmp
			})
			StrictFQDN = tt.strictFQDN
			assert.Equal(t, tt.want, tlsAlpn01ChallengeHost(tt.args.name))
		})
	}
}

func Test_dns01ChallengeHost(t *testing.T) {
	type args struct {
		domain string
	}
	tests := []struct {
		name       string
		strictFQDN bool
		args       args
		want       string
	}{
		{"dns", false, args{"smallstep.com"}, "_acme-challenge.smallstep.com"},
		{"dns strict", true, args{"smallstep.com"}, "_acme-challenge.smallstep.com."},
		{"rooted dns", false, args{"smallstep.com."}, "_acme-challenge.smallstep.com."},
		{"rooted dns strict", true, args{"smallstep.com."}, "_acme-challenge.smallstep.com."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmp := StrictFQDN
			t.Cleanup(func() {
				StrictFQDN = tmp
			})
			StrictFQDN = tt.strictFQDN
			assert.Equal(t, tt.want, dns01ChallengeHost(tt.args.domain))
		})
	}
}
