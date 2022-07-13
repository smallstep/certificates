package api

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-chi/chi"
	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ocsp"

	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/x509util"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/provisioner"
)

// v is a utility function to return the pointer to an integer
func v(v int) *int {
	return &v
}

func generateSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, big.NewInt(1000000000000000000))
}

// generateCertKeyPair generates fresh x509 certificate/key pairs for testing
func generateCertKeyPair() (*x509.Certificate, crypto.Signer, error) {

	pub, priv, err := keyutil.GenerateKeyPair("EC", "P-256", 0)
	if err != nil {
		return nil, nil, err
	}

	serial, err := generateSerial()
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		Issuer:       pkix.Name{CommonName: "Test ACME Revoke Certificate"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:         false,
		MaxPathLen:   0,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		NotBefore:    now,
		NotAfter:     now.Add(time.Hour),
		SerialNumber: serial,
	}

	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, nil, errors.Errorf("result is not a crypto.Signer: type %T", priv)
	}

	cert, err := x509util.CreateCertificate(template, template, pub, signer)

	return cert, signer, err
}

var errUnsupportedKey = fmt.Errorf("unknown key type; only RSA and ECDSA are supported")

// keyID is the account identity provided by a CA during registration.
type keyID string

// noKeyID indicates that jwsEncodeJSON should compute and use JWK instead of a KID.
// See jwsEncodeJSON for details.
const noKeyID = keyID("")

// jwsEncodeJSON signs claimset using provided key and a nonce.
// The result is serialized in JSON format containing either kid or jwk
// fields based on the provided keyID value.
//
// If kid is non-empty, its quoted value is inserted in the protected head
// as "kid" field value. Otherwise, JWK is computed using jwkEncode and inserted
// as "jwk" field value. The "jwk" and "kid" fields are mutually exclusive.
//
// See https://tools.ietf.org/html/rfc7515#section-7.
//
// If nonce is empty, it will not be encoded into the header.
// Implementation taken from github.com/mholt/acmez, which seems to be based on
// https://github.com/golang/crypto/blob/master/acme/jws.go.
func jwsEncodeJSON(claimset interface{}, key crypto.Signer, kid keyID, nonce, u string) ([]byte, error) {
	alg, sha := jwsHasher(key.Public())
	if alg == "" || !sha.Available() {
		return nil, errUnsupportedKey
	}

	phead, err := jwsHead(alg, nonce, u, kid, key)
	if err != nil {
		return nil, err
	}

	var payload string
	if claimset != nil {
		cs, err := json.Marshal(claimset)
		if err != nil {
			return nil, err
		}
		payload = base64.RawURLEncoding.EncodeToString(cs)
	}

	payloadToSign := []byte(phead + "." + payload)
	hash := sha.New()
	_, _ = hash.Write(payloadToSign)
	digest := hash.Sum(nil)

	sig, err := jwsSign(key, sha, digest)
	if err != nil {
		return nil, err
	}

	return jwsFinal(sha, sig, phead, payload)
}

// jwsHasher indicates suitable JWS algorithm name and a hash function
// to use for signing a digest with the provided key.
// It returns ("", 0) if the key is not supported.
// Implementation taken from github.com/mholt/acmez, which seems to be based on
// https://github.com/golang/crypto/blob/master/acme/jws.go.
func jwsHasher(pub crypto.PublicKey) (string, crypto.Hash) {
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return "RS256", crypto.SHA256
	case *ecdsa.PublicKey:
		switch pub.Params().Name {
		case "P-256":
			return "ES256", crypto.SHA256
		case "P-384":
			return "ES384", crypto.SHA384
		case "P-521":
			return "ES512", crypto.SHA512
		}
	}
	return "", 0
}

// jwsSign signs the digest using the given key.
// The hash is unused for ECDSA keys.
//
// Note: non-stdlib crypto.Signer implementations are expected to return
// the signature in the format as specified in RFC7518.
// See https://tools.ietf.org/html/rfc7518 for more details.
// Implementation taken from github.com/mholt/acmez, which seems to be based on
// https://github.com/golang/crypto/blob/master/acme/jws.go.
func jwsSign(key crypto.Signer, hash crypto.Hash, digest []byte) ([]byte, error) {
	if key, ok := key.(*ecdsa.PrivateKey); ok {
		// The key.Sign method of ecdsa returns ASN1-encoded signature.
		// So, we use the package Sign function instead
		// to get R and S values directly and format the result accordingly.
		r, s, err := ecdsa.Sign(rand.Reader, key, digest)
		if err != nil {
			return nil, err
		}
		rb, sb := r.Bytes(), s.Bytes()
		size := key.Params().BitSize / 8
		if size%8 > 0 {
			size++
		}
		sig := make([]byte, size*2)
		copy(sig[size-len(rb):], rb)
		copy(sig[size*2-len(sb):], sb)
		return sig, nil
	}
	return key.Sign(rand.Reader, digest, hash)
}

// jwsHead constructs the protected JWS header for the given fields.
// Since jwk and kid are mutually-exclusive, the jwk will be encoded
// only if kid is empty. If nonce is empty, it will not be encoded.
// Implementation taken from github.com/mholt/acmez, which seems to be based on
// https://github.com/golang/crypto/blob/master/acme/jws.go.
func jwsHead(alg, nonce, u string, kid keyID, key crypto.Signer) (string, error) {
	phead := fmt.Sprintf(`{"alg":%q`, alg)
	if kid == noKeyID {
		jwk, err := jwkEncode(key.Public())
		if err != nil {
			return "", err
		}
		phead += fmt.Sprintf(`,"jwk":%s`, jwk)
	} else {
		phead += fmt.Sprintf(`,"kid":%q`, kid)
	}
	if nonce != "" {
		phead += fmt.Sprintf(`,"nonce":%q`, nonce)
	}
	phead += fmt.Sprintf(`,"url":%q}`, u)
	phead = base64.RawURLEncoding.EncodeToString([]byte(phead))
	return phead, nil
}

// jwkEncode encodes public part of an RSA or ECDSA key into a JWK.
// The result is also suitable for creating a JWK thumbprint.
// https://tools.ietf.org/html/rfc7517
// Implementation taken from github.com/mholt/acmez, which seems to be based on
// https://github.com/golang/crypto/blob/master/acme/jws.go.
func jwkEncode(pub crypto.PublicKey) (string, error) {
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		// https://tools.ietf.org/html/rfc7518#section-6.3.1
		n := pub.N
		e := big.NewInt(int64(pub.E))
		// Field order is important.
		// See https://tools.ietf.org/html/rfc7638#section-3.3 for details.
		return fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`,
			base64.RawURLEncoding.EncodeToString(e.Bytes()),
			base64.RawURLEncoding.EncodeToString(n.Bytes()),
		), nil
	case *ecdsa.PublicKey:
		// https://tools.ietf.org/html/rfc7518#section-6.2.1
		p := pub.Curve.Params()
		n := p.BitSize / 8
		if p.BitSize%8 != 0 {
			n++
		}
		x := pub.X.Bytes()
		if n > len(x) {
			x = append(make([]byte, n-len(x)), x...)
		}
		y := pub.Y.Bytes()
		if n > len(y) {
			y = append(make([]byte, n-len(y)), y...)
		}
		// Field order is important.
		// See https://tools.ietf.org/html/rfc7638#section-3.3 for details.
		return fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`,
			p.Name,
			base64.RawURLEncoding.EncodeToString(x),
			base64.RawURLEncoding.EncodeToString(y),
		), nil
	}
	return "", errUnsupportedKey
}

// jwsFinal constructs the final JWS object.
// Implementation taken from github.com/mholt/acmez, which seems to be based on
// https://github.com/golang/crypto/blob/master/acme/jws.go.
func jwsFinal(sha crypto.Hash, sig []byte, phead, payload string) ([]byte, error) {
	enc := struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Sig       string `json:"signature"`
	}{
		Protected: phead,
		Payload:   payload,
		Sig:       base64.RawURLEncoding.EncodeToString(sig),
	}
	result, err := json.Marshal(&enc)
	if err != nil {
		return nil, err
	}
	return result, nil
}

type mockCA struct {
	MockIsRevoked      func(sn string) (bool, error)
	MockRevoke         func(ctx context.Context, opts *authority.RevokeOptions) error
	MockAreSANsallowed func(ctx context.Context, sans []string) error
}

func (m *mockCA) Sign(cr *x509.CertificateRequest, opts provisioner.SignOptions, signOpts ...provisioner.SignOption) ([]*x509.Certificate, error) {
	return nil, nil
}

func (m *mockCA) AreSANsAllowed(ctx context.Context, sans []string) error {
	if m.MockAreSANsallowed != nil {
		return m.MockAreSANsallowed(ctx, sans)
	}
	return nil
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
	cert, _, err := generateCertKeyPair()
	assert.FatalError(t, err)
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
				Crt:    cert,
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
				Crt:        cert,
				ACME:       true,
				ReasonCode: 1,
				Reason:     "key compromised",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := revokeOptions(tt.args.serial, tt.args.certToBeRevoked, tt.args.reasonCode); !cmp.Equal(got, tt.want) {
				t.Errorf("revokeOptions() diff =\n%s", cmp.Diff(got, tt.want))
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

	cert, key, err := generateCertKeyPair()
	assert.FatalError(t, err)
	rp := &revokePayload{
		Certificate: base64.RawURLEncoding.EncodeToString(cert.Raw),
	}
	payloadBytes, err := json.Marshal(rp)
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

	type test struct {
		db         acme.DB
		ca         acme.CertificateAuthority
		ctx        context.Context
		statusCode int
		err        *acme.Error
	}

	var tests = map[string]func(t *testing.T) test{
		"fail/no-jws": func(t *testing.T) test {
			ctx := context.Background()
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("jws expected in request context"),
			}
		},
		"fail/nil-jws": func(t *testing.T) test {
			ctx := context.WithValue(context.Background(), jwsContextKey, nil)
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("jws expected in request context"),
			}
		},
		"fail/no-provisioner": func(t *testing.T) test {
			ctx := context.WithValue(context.Background(), jwsContextKey, jws)
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("provisioner does not exist"),
			}
		},
		"fail/nil-provisioner": func(t *testing.T) test {
			ctx := context.WithValue(context.Background(), jwsContextKey, jws)
			ctx = acme.NewProvisionerContext(ctx, nil)
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("provisioner does not exist"),
			}
		},
		"fail/no-payload": func(t *testing.T) test {
			ctx := context.WithValue(context.Background(), jwsContextKey, jws)
			ctx = acme.NewProvisionerContext(ctx, prov)
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("payload does not exist"),
			}
		},
		"fail/nil-payload": func(t *testing.T) test {
			ctx := context.WithValue(context.Background(), jwsContextKey, jws)
			ctx = acme.NewProvisionerContext(ctx, prov)
			ctx = context.WithValue(ctx, payloadContextKey, nil)
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("payload does not exist"),
			}
		},
		"fail/unmarshal-payload": func(t *testing.T) test {
			malformedPayload := []byte(`{"payload":malformed?}`)
			ctx := context.WithValue(context.Background(), jwsContextKey, jws)
			ctx = acme.NewProvisionerContext(ctx, prov)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: malformedPayload})
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("error unmarshaling payload"),
			}
		},
		"fail/wrong-certificate-encoding": func(t *testing.T) test {
			wrongPayload := &revokePayload{
				Certificate: base64.StdEncoding.EncodeToString(cert.Raw),
			}
			wronglyEncodedPayloadBytes, err := json.Marshal(wrongPayload)
			assert.FatalError(t, err)
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: wronglyEncodedPayloadBytes})
			ctx = context.WithValue(ctx, jwsContextKey, jws)
			return test{
				db:         &acme.MockDB{},
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
			emptyPayload := &revokePayload{
				Certificate: base64.RawURLEncoding.EncodeToString([]byte{}),
			}
			emptyPayloadBytes, err := json.Marshal(emptyPayload)
			assert.FatalError(t, err)
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: emptyPayloadBytes})
			ctx = context.WithValue(ctx, jwsContextKey, jws)
			return test{
				db:         &acme.MockDB{},
				ctx:        ctx,
				statusCode: 400,
				err: &acme.Error{
					Type:   "urn:ietf:params:acme:error:malformed",
					Status: 400,
					Detail: "The request message was malformed",
				},
			}
		},
		"fail/db.GetCertificateBySerial": func(t *testing.T) test {
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: payloadBytes})
			ctx = context.WithValue(ctx, jwsContextKey, jws)
			db := &acme.MockDB{
				MockGetCertificateBySerial: func(ctx context.Context, serial string) (*acme.Certificate, error) {
					return nil, errors.New("force")
				},
			}
			return test{
				db:         db,
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("error retrieving certificate by serial"),
			}
		},
		"fail/different-certificate-contents": func(t *testing.T) test {
			aDifferentCert, _, err := generateCertKeyPair()
			assert.FatalError(t, err)
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: payloadBytes})
			ctx = context.WithValue(ctx, jwsContextKey, jws)
			db := &acme.MockDB{
				MockGetCertificateBySerial: func(ctx context.Context, serial string) (*acme.Certificate, error) {
					assert.Equals(t, cert.SerialNumber.String(), serial)
					return &acme.Certificate{
						Leaf: aDifferentCert,
					}, nil
				},
			}
			return test{
				db:         db,
				ctx:        ctx,
				statusCode: 500,
				err:        acme.NewErrorISE("certificate raw bytes are not equal"),
			}
		},
		"fail/no-account": func(t *testing.T) test {
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: payloadBytes})
			ctx = context.WithValue(ctx, jwsContextKey, jws)
			db := &acme.MockDB{
				MockGetCertificateBySerial: func(ctx context.Context, serial string) (*acme.Certificate, error) {
					assert.Equals(t, cert.SerialNumber.String(), serial)
					return &acme.Certificate{
						Leaf: cert,
					}, nil
				},
			}
			return test{
				db:         db,
				ctx:        ctx,
				statusCode: 400,
				err:        acme.NewError(acme.ErrorAccountDoesNotExistType, "account not in context"),
			}
		},
		"fail/nil-account": func(t *testing.T) test {
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: payloadBytes})
			ctx = context.WithValue(ctx, jwsContextKey, jws)
			ctx = context.WithValue(ctx, accContextKey, nil)
			db := &acme.MockDB{
				MockGetCertificateBySerial: func(ctx context.Context, serial string) (*acme.Certificate, error) {
					assert.Equals(t, cert.SerialNumber.String(), serial)
					return &acme.Certificate{
						Leaf: cert,
					}, nil
				},
			}
			return test{
				db:         db,
				ctx:        ctx,
				statusCode: 400,
				err:        acme.NewError(acme.ErrorAccountDoesNotExistType, "account not in context"),
			}
		},
		"fail/account-not-valid": func(t *testing.T) test {
			acc := &acme.Account{ID: "accountID", Status: acme.StatusInvalid}
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: payloadBytes})
			ctx = context.WithValue(ctx, jwsContextKey, jws)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			db := &acme.MockDB{
				MockGetCertificateBySerial: func(ctx context.Context, serial string) (*acme.Certificate, error) {
					assert.Equals(t, cert.SerialNumber.String(), serial)
					return &acme.Certificate{
						AccountID: "accountID",
						Leaf:      cert,
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
					Detail: "No authorization provided for name 127.0.0.1",
					Status: 403,
				},
			}
		},
		"fail/account-not-authorized": func(t *testing.T) test {
			acc := &acme.Account{ID: "accountID", Status: acme.StatusValid}
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: payloadBytes})
			ctx = context.WithValue(ctx, jwsContextKey, jws)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			db := &acme.MockDB{
				MockGetCertificateBySerial: func(ctx context.Context, serial string) (*acme.Certificate, error) {
					assert.Equals(t, cert.SerialNumber.String(), serial)
					return &acme.Certificate{
						AccountID: "differentAccountID",
						Leaf:      cert,
					}, nil
				},
				MockGetAuthorizationsByAccountID: func(ctx context.Context, accountID string) ([]*acme.Authorization, error) {
					assert.Equals(t, "accountID", accountID)
					return []*acme.Authorization{
						{
							AccountID: "accountID",
							Status:    acme.StatusValid,
							Identifier: acme.Identifier{
								Type:  acme.IP,
								Value: "127.0.1.0",
							},
						},
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
					Detail: "No authorization provided for name 127.0.0.1",
					Status: 403,
				},
			}
		},
		"fail/unauthorized-certificate-key": func(t *testing.T) test {
			_, unauthorizedKey, err := generateCertKeyPair()
			assert.FatalError(t, err)
			jwsPayload := &revokePayload{
				Certificate: base64.RawURLEncoding.EncodeToString(cert.Raw),
				ReasonCode:  v(2),
			}
			jwsBytes, err := jwsEncodeJSON(rp, unauthorizedKey, "", "nonce", revokeURL)
			assert.FatalError(t, err)
			parsedJWS, err := jose.ParseJWS(string(jwsBytes))
			assert.FatalError(t, err)
			unauthorizedPayloadBytes, err := json.Marshal(jwsPayload)
			assert.FatalError(t, err)
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: unauthorizedPayloadBytes})
			ctx = context.WithValue(ctx, jwsContextKey, parsedJWS)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			db := &acme.MockDB{
				MockGetCertificateBySerial: func(ctx context.Context, serial string) (*acme.Certificate, error) {
					assert.Equals(t, cert.SerialNumber.String(), serial)
					return &acme.Certificate{
						AccountID: "accountID",
						Leaf:      cert,
					}, nil
				},
			}
			ca := &mockCA{}
			acmeErr := acme.NewError(acme.ErrorUnauthorizedType, "verification of jws using certificate public key failed")
			acmeErr.Detail = "No authorization provided for name 127.0.0.1"
			return test{
				db:         db,
				ca:         ca,
				ctx:        ctx,
				statusCode: 403,
				err:        acmeErr,
			}
		},
		"fail/certificate-revoked-check-fails": func(t *testing.T) test {
			acc := &acme.Account{ID: "accountID", Status: acme.StatusValid}
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: payloadBytes})
			ctx = context.WithValue(ctx, jwsContextKey, jws)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			db := &acme.MockDB{
				MockGetCertificateBySerial: func(ctx context.Context, serial string) (*acme.Certificate, error) {
					assert.Equals(t, cert.SerialNumber.String(), serial)
					return &acme.Certificate{
						AccountID: "accountID",
						Leaf:      cert,
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
			acc := &acme.Account{ID: "accountID", Status: acme.StatusValid}
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: payloadBytes})
			ctx = context.WithValue(ctx, jwsContextKey, jws)
			db := &acme.MockDB{
				MockGetCertificateBySerial: func(ctx context.Context, serial string) (*acme.Certificate, error) {
					assert.Equals(t, cert.SerialNumber.String(), serial)
					return &acme.Certificate{
						AccountID: "accountID",
						Leaf:      cert,
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
		"fail/invalid-reasoncode": func(t *testing.T) test {
			invalidReasonPayload := &revokePayload{
				Certificate: base64.RawURLEncoding.EncodeToString(cert.Raw),
				ReasonCode:  v(7),
			}
			invalidReasonCodePayloadBytes, err := json.Marshal(invalidReasonPayload)
			assert.FatalError(t, err)
			acc := &acme.Account{ID: "accountID", Status: acme.StatusValid}
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: invalidReasonCodePayloadBytes})
			ctx = context.WithValue(ctx, jwsContextKey, jws)
			db := &acme.MockDB{
				MockGetCertificateBySerial: func(ctx context.Context, serial string) (*acme.Certificate, error) {
					assert.Equals(t, cert.SerialNumber.String(), serial)
					return &acme.Certificate{
						AccountID: "accountID",
						Leaf:      cert,
					}, nil
				},
			}
			ca := &mockCA{
				MockIsRevoked: func(sn string) (bool, error) {
					return false, nil
				},
			}
			return test{
				db:         db,
				ca:         ca,
				ctx:        ctx,
				statusCode: 400,
				err: &acme.Error{
					Type:   "urn:ietf:params:acme:error:badRevocationReason",
					Detail: "The revocation reason provided is not allowed by the server",
					Status: 400,
				},
			}
		},
		"fail/prov.AuthorizeRevoke": func(t *testing.T) test {
			assert.FatalError(t, err)
			mockACMEProv := &acme.MockProvisioner{
				MauthorizeRevoke: func(ctx context.Context, token string) error {
					return errors.New("force")
				},
			}
			acc := &acme.Account{ID: "accountID", Status: acme.StatusValid}
			ctx := acme.NewProvisionerContext(context.Background(), mockACMEProv)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: payloadBytes})
			ctx = context.WithValue(ctx, jwsContextKey, jws)
			db := &acme.MockDB{
				MockGetCertificateBySerial: func(ctx context.Context, serial string) (*acme.Certificate, error) {
					assert.Equals(t, cert.SerialNumber.String(), serial)
					return &acme.Certificate{
						AccountID: "accountID",
						Leaf:      cert,
					}, nil
				},
			}
			ca := &mockCA{
				MockIsRevoked: func(sn string) (bool, error) {
					return false, nil
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
		"fail/ca.Revoke": func(t *testing.T) test {
			acc := &acme.Account{ID: "accountID", Status: acme.StatusValid}
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: payloadBytes})
			ctx = context.WithValue(ctx, jwsContextKey, jws)
			db := &acme.MockDB{
				MockGetCertificateBySerial: func(ctx context.Context, serial string) (*acme.Certificate, error) {
					assert.Equals(t, cert.SerialNumber.String(), serial)
					return &acme.Certificate{
						AccountID: "accountID",
						Leaf:      cert,
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
		"fail/ca.Revoke-already-revoked": func(t *testing.T) test {
			acc := &acme.Account{ID: "accountID", Status: acme.StatusValid}
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: payloadBytes})
			ctx = context.WithValue(ctx, jwsContextKey, jws)
			db := &acme.MockDB{
				MockGetCertificateBySerial: func(ctx context.Context, serial string) (*acme.Certificate, error) {
					assert.Equals(t, cert.SerialNumber.String(), serial)
					return &acme.Certificate{
						AccountID: "accountID",
						Leaf:      cert,
					}, nil
				},
			}
			ca := &mockCA{
				MockIsRevoked: func(sn string) (bool, error) {
					return false, nil
				},
				MockRevoke: func(ctx context.Context, opts *authority.RevokeOptions) error {
					return fmt.Errorf("certificate with serial number '%s' is already revoked", cert.SerialNumber.String())
				},
			}
			return test{
				db:         db,
				ca:         ca,
				ctx:        ctx,
				statusCode: 400,
				err:        acme.NewError(acme.ErrorAlreadyRevokedType, "certificate with serial number '%s' is already revoked", cert.SerialNumber.String()),
			}
		},
		"ok/using-account-key": func(t *testing.T) test {
			acc := &acme.Account{ID: "accountID", Status: acme.StatusValid}
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: payloadBytes})
			ctx = context.WithValue(ctx, jwsContextKey, jws)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			db := &acme.MockDB{
				MockGetCertificateBySerial: func(ctx context.Context, serial string) (*acme.Certificate, error) {
					assert.Equals(t, cert.SerialNumber.String(), serial)
					return &acme.Certificate{
						AccountID: "accountID",
						Leaf:      cert,
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
		"ok/using-certificate-key": func(t *testing.T) test {
			jwsBytes, err := jwsEncodeJSON(rp, key, "", "nonce", revokeURL)
			assert.FatalError(t, err)
			jws, err := jose.ParseJWS(string(jwsBytes))
			assert.FatalError(t, err)
			ctx := acme.NewProvisionerContext(context.Background(), prov)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: payloadBytes})
			ctx = context.WithValue(ctx, jwsContextKey, jws)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			db := &acme.MockDB{
				MockGetCertificateBySerial: func(ctx context.Context, serial string) (*acme.Certificate, error) {
					assert.Equals(t, cert.SerialNumber.String(), serial)
					return &acme.Certificate{
						AccountID: "someDifferentAccountID",
						Leaf:      cert,
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
			ctx := newBaseContext(tc.ctx, tc.db, acme.NewLinker("test.ca.smallstep.com", "acme"))
			mockMustAuthority(t, tc.ca)
			req := httptest.NewRequest("POST", revokeURL, nil)
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()
			RevokeCert(w, req)
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

func TestHandler_isAccountAuthorized(t *testing.T) {
	type test struct {
		db              acme.DB
		ctx             context.Context
		existingCert    *acme.Certificate
		certToBeRevoked *x509.Certificate
		account         *acme.Account
		err             *acme.Error
	}
	accountID := "accountID"
	var tests = map[string]func(t *testing.T) test{
		"fail/account-invalid": func(t *testing.T) test {
			account := &acme.Account{
				ID:     accountID,
				Status: acme.StatusInvalid,
			}
			certToBeRevoked := &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "127.0.0.1",
				},
			}
			return test{
				ctx:             context.TODO(),
				certToBeRevoked: certToBeRevoked,
				account:         account,
				err: &acme.Error{
					Type:   "urn:ietf:params:acme:error:unauthorized",
					Status: http.StatusForbidden,
					Detail: "No authorization provided for name 127.0.0.1",
					Err:    errors.New("account 'accountID' has status 'invalid'"),
				},
			}
		},
		"fail/different-account": func(t *testing.T) test {
			account := &acme.Account{
				ID:     accountID,
				Status: acme.StatusValid,
			}
			certToBeRevoked := &x509.Certificate{
				IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
			}
			existingCert := &acme.Certificate{
				AccountID: "differentAccountID",
			}
			return test{
				db: &acme.MockDB{
					MockGetAuthorizationsByAccountID: func(ctx context.Context, accountID string) ([]*acme.Authorization, error) {
						assert.Equals(t, "accountID", accountID)
						return []*acme.Authorization{
							{
								AccountID: accountID,
								Status:    acme.StatusValid,
								Identifier: acme.Identifier{
									Type:  acme.IP,
									Value: "127.0.0.1",
								},
							},
						}, nil
					},
				},
				ctx:             context.TODO(),
				existingCert:    existingCert,
				certToBeRevoked: certToBeRevoked,
				account:         account,
				err: &acme.Error{
					Type:   "urn:ietf:params:acme:error:unauthorized",
					Status: http.StatusForbidden,
					Detail: "No authorization provided",
					Err:    errors.New("account 'accountID' is not authorized"),
				},
			}
		},
		"ok": func(t *testing.T) test {
			account := &acme.Account{
				ID:     accountID,
				Status: acme.StatusValid,
			}
			certToBeRevoked := &x509.Certificate{
				IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
			}
			existingCert := &acme.Certificate{
				AccountID: "accountID",
			}
			return test{
				db: &acme.MockDB{
					MockGetAuthorizationsByAccountID: func(ctx context.Context, accountID string) ([]*acme.Authorization, error) {
						assert.Equals(t, "accountID", accountID)
						return []*acme.Authorization{
							{
								AccountID: accountID,
								Status:    acme.StatusValid,
								Identifier: acme.Identifier{
									Type:  acme.IP,
									Value: "127.0.0.1",
								},
							},
						}, nil
					},
				},
				ctx:             context.TODO(),
				existingCert:    existingCert,
				certToBeRevoked: certToBeRevoked,
				account:         account,
				err:             nil,
			}
		},
	}
	for name, setup := range tests {
		tc := setup(t)
		t.Run(name, func(t *testing.T) {
			// h := &Handler{db: tc.db}
			acmeErr := isAccountAuthorized(tc.ctx, tc.existingCert, tc.certToBeRevoked, tc.account)

			expectError := tc.err != nil
			gotError := acmeErr != nil
			if expectError != gotError {
				t.Errorf("expected: %t, got: %t", expectError, gotError)
				return
			}

			if !gotError {
				return // nothing to check; return early
			}

			assert.Equals(t, acmeErr.Err.Error(), tc.err.Err.Error())
			assert.Equals(t, acmeErr.Type, tc.err.Type)
			assert.Equals(t, acmeErr.Status, tc.err.Status)
			assert.Equals(t, acmeErr.Detail, tc.err.Detail)
			assert.Equals(t, acmeErr.Identifier, tc.err.Identifier)
			assert.Equals(t, acmeErr.Subproblems, tc.err.Subproblems)

		})
	}
}

func Test_wrapUnauthorizedError(t *testing.T) {
	type test struct {
		cert                    *x509.Certificate
		unauthorizedIdentifiers []acme.Identifier
		msg                     string
		err                     error
		want                    *acme.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"unauthorizedIdentifiers": func(t *testing.T) test {
			acmeErr := acme.NewError(acme.ErrorUnauthorizedType, "account 'accountID' is not authorized")
			acmeErr.Status = http.StatusForbidden
			acmeErr.Detail = "No authorization provided for name 127.0.0.1"
			return test{
				err:  nil,
				cert: nil,
				unauthorizedIdentifiers: []acme.Identifier{
					{
						Type:  acme.IP,
						Value: "127.0.0.1",
					},
				},
				msg:  "account 'accountID' is not authorized",
				want: acmeErr,
			}
		},
		"subject": func(t *testing.T) test {
			acmeErr := acme.NewError(acme.ErrorUnauthorizedType, "account 'accountID' is not authorized")
			acmeErr.Status = http.StatusForbidden
			acmeErr.Detail = "No authorization provided for name test.example.com"
			cert := &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "test.example.com",
				},
			}
			return test{
				err:                     nil,
				cert:                    cert,
				unauthorizedIdentifiers: []acme.Identifier{},
				msg:                     "account 'accountID' is not authorized",
				want:                    acmeErr,
			}
		},
		"wrap-subject": func(t *testing.T) test {
			acmeErr := acme.NewError(acme.ErrorUnauthorizedType, "verification of jws using certificate public key failed: square/go-jose: error in cryptographic primitive")
			acmeErr.Status = http.StatusForbidden
			acmeErr.Detail = "No authorization provided for name test.example.com"
			cert := &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "test.example.com",
				},
			}
			return test{
				err:                     errors.New("square/go-jose: error in cryptographic primitive"),
				cert:                    cert,
				unauthorizedIdentifiers: []acme.Identifier{},
				msg:                     "verification of jws using certificate public key failed",
				want:                    acmeErr,
			}
		},
		"default": func(t *testing.T) test {
			acmeErr := acme.NewError(acme.ErrorUnauthorizedType, "account 'accountID' is not authorized")
			acmeErr.Status = http.StatusForbidden
			acmeErr.Detail = "No authorization provided"
			cert := &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "",
				},
			}
			return test{
				err:                     nil,
				cert:                    cert,
				unauthorizedIdentifiers: []acme.Identifier{},
				msg:                     "account 'accountID' is not authorized",
				want:                    acmeErr,
			}
		},
	}
	for name, prep := range tests {
		tc := prep(t)
		t.Run(name, func(t *testing.T) {
			acmeErr := wrapUnauthorizedError(tc.cert, tc.unauthorizedIdentifiers, tc.msg, tc.err)
			assert.Equals(t, acmeErr.Err.Error(), tc.want.Err.Error())
			assert.Equals(t, acmeErr.Type, tc.want.Type)
			assert.Equals(t, acmeErr.Status, tc.want.Status)
			assert.Equals(t, acmeErr.Detail, tc.want.Detail)
			assert.Equals(t, acmeErr.Identifier, tc.want.Identifier)
			assert.Equals(t, acmeErr.Subproblems, tc.want.Subproblems)
		})
	}
}
