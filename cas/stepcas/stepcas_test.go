package stepcas

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/cas/apiv1"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/randutil"
	"go.step.sm/crypto/x509util"
)

var (
	testRootCrt                   *x509.Certificate
	testRootKey                   crypto.Signer
	testRootPath, testRootKeyPath string
	testRootFingerprint           string

	testIssCrt                  *x509.Certificate
	testIssKey                  crypto.Signer
	testIssPath, testIssKeyPath string

	testX5CCrt                         *x509.Certificate
	testX5CKey                         crypto.Signer
	testX5CPath, testX5CKeyPath        string
	testPassword, testEncryptedKeyPath string
	testKeyID, testEncryptedJWKKey     string

	testCR     *x509.CertificateRequest
	testCrt    *x509.Certificate
	testKey    crypto.Signer
	testFailCR *x509.CertificateRequest
)

func mustSignCertificate(subject string, sans []string, template string, parent *x509.Certificate, signer crypto.Signer) (*x509.Certificate, crypto.Signer) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	cr, err := x509util.CreateCertificateRequest(subject, sans, priv)
	if err != nil {
		panic(err)
	}
	cert, err := x509util.NewCertificate(cr, x509util.WithTemplate(template, x509util.CreateTemplateData(subject, sans)))
	if err != nil {
		panic(err)
	}

	crt := cert.GetCertificate()
	crt.NotBefore = time.Now()
	crt.NotAfter = crt.NotBefore.Add(time.Hour)
	if parent == nil {
		parent = crt
	}
	if signer == nil {
		signer = priv
	}
	if crt, err = x509util.CreateCertificate(crt, parent, pub, signer); err != nil {
		panic(err)
	}
	return crt, priv
}

func mustSerializeCrt(filename string, certs ...*x509.Certificate) {
	buf := new(bytes.Buffer)
	for _, c := range certs {
		if err := pem.Encode(buf, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.Raw,
		}); err != nil {
			panic(err)
		}
	}
	if err := os.WriteFile(filename, buf.Bytes(), 0600); err != nil {
		panic(err)
	}
}

func mustSerializeKey(filename string, key crypto.Signer) {
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}
	b = pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	})
	if err := os.WriteFile(filename, b, 0600); err != nil {
		panic(err)
	}
}

func mustEncryptKey(filename string, key crypto.Signer) {
	_, err := pemutil.Serialize(key,
		pemutil.ToFile(filename, 0600),
		pemutil.WithPKCS8(true),
		pemutil.WithPassword([]byte(testPassword)))
	if err != nil {
		panic(err)
	}
}

func testCAHelper(t *testing.T) (*url.URL, *ca.Client) {
	t.Helper()

	writeJSON := func(w http.ResponseWriter, v interface{}) {
		_ = json.NewEncoder(w).Encode(v)
	}
	parseJSON := func(r *http.Request, v interface{}) {
		_ = json.NewDecoder(r.Body).Decode(v)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.RequestURI == "/root/"+testRootFingerprint:
			w.WriteHeader(http.StatusOK)
			writeJSON(w, api.RootResponse{
				RootPEM: api.NewCertificate(testRootCrt),
			})
		case r.RequestURI == "/sign":
			var msg api.SignRequest
			parseJSON(r, &msg)
			if msg.CsrPEM.DNSNames[0] == "fail.doe.org" {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, `{"error":"fail","message":"fail"}`)
				return
			}
			w.WriteHeader(http.StatusOK)
			writeJSON(w, api.SignResponse{
				CertChainPEM: []api.Certificate{api.NewCertificate(testCrt), api.NewCertificate(testIssCrt)},
			})
		case r.RequestURI == "/renew":
			if r.Header.Get("Authorization") == "Bearer fail" {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, `{"error":"fail","message":"fail"}`)
				return
			}
			w.WriteHeader(http.StatusOK)
			writeJSON(w, api.SignResponse{
				CertChainPEM: []api.Certificate{api.NewCertificate(testCrt), api.NewCertificate(testIssCrt)},
			})
		case r.RequestURI == "/revoke":
			var msg api.RevokeRequest
			parseJSON(r, &msg)
			if msg.Serial == "fail" {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, `{"error":"fail","message":"fail"}`)
				return
			}
			w.WriteHeader(http.StatusOK)
			writeJSON(w, api.RevokeResponse{
				Status: "ok",
			})
		case r.RequestURI == "/provisioners":
			w.WriteHeader(http.StatusOK)
			writeJSON(w, api.ProvisionersResponse{
				NextCursor: "cursor",
				Provisioners: []provisioner.Interface{
					&provisioner.JWK{
						Type:         "JWK",
						Name:         "ra@doe.org",
						Key:          &jose.JSONWebKey{KeyID: testKeyID, Key: testX5CKey.Public()},
						EncryptedKey: testEncryptedJWKKey,
					},
					&provisioner.JWK{
						Type: "JWK",
						Name: "empty@doe.org",
						Key:  &jose.JSONWebKey{KeyID: testKeyID, Key: testX5CKey.Public()},
					},
				},
			})
		case r.RequestURI == "/provisioners?cursor=cursor":
			w.WriteHeader(http.StatusOK)
			writeJSON(w, api.ProvisionersResponse{})
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

	client, err := ca.NewClient(srv.URL, ca.WithTransport(http.DefaultTransport))
	if err != nil {
		srv.Close()
		t.Fatal(err)
	}

	return u, client
}

func testX5CIssuer(t *testing.T, caURL *url.URL, password string) *x5cIssuer {
	t.Helper()
	key, givenPassword := testX5CKeyPath, password
	if password != "" {
		key = testEncryptedKeyPath
		password = testPassword
	}
	x5c, err := newX5CIssuer(caURL, &apiv1.CertificateIssuer{
		Type:        "x5c",
		Provisioner: "X5C",
		Certificate: testX5CPath,
		Key:         key,
		Password:    password,
	})
	if err != nil {
		t.Fatal(err)
	}
	x5c.password = givenPassword
	return x5c
}

func testJWKIssuer(t *testing.T, caURL *url.URL, password string) *jwkIssuer {
	t.Helper()
	client, err := ca.NewClient(caURL.String(), ca.WithTransport(http.DefaultTransport))
	if err != nil {
		t.Fatal(err)
	}
	key := testX5CKeyPath
	if password != "" {
		key = testEncryptedKeyPath
		password = testPassword
	}
	jwk, err := newJWKIssuer(context.TODO(), caURL, client, &apiv1.CertificateIssuer{
		Type:        "jwk",
		Provisioner: "ra@doe.org",
		Key:         key,
		Password:    password,
	})
	if err != nil {
		t.Fatal(err)
	}

	return jwk
}

func TestMain(m *testing.M) {
	testRootCrt, testRootKey = mustSignCertificate("Test Root Certificate", nil, x509util.DefaultRootTemplate, nil, nil)
	testIssCrt, testIssKey = mustSignCertificate("Test Intermediate Certificate", nil, x509util.DefaultIntermediateTemplate, testRootCrt, testRootKey)
	testX5CCrt, testX5CKey = mustSignCertificate("Test X5C Certificate", nil, x509util.DefaultLeafTemplate, testIssCrt, testIssKey)
	testRootFingerprint = x509util.Fingerprint(testRootCrt)

	// Final certificate.
	var err error
	sans := []string{"doe.org", "jane@doe.org", "127.0.0.1", "::1", "localhost", "uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6;name=value"}
	testCrt, testKey = mustSignCertificate("Test Certificate", sans, x509util.DefaultLeafTemplate, testIssCrt, testIssKey)
	testCR, err = x509util.CreateCertificateRequest("Test Certificate", sans, testKey)
	if err != nil {
		panic(err)
	}

	// CR used in errors.
	testFailCR, err = x509util.CreateCertificateRequest("", []string{"fail.doe.org"}, testKey)
	if err != nil {
		panic(err)
	}

	// Password used to encrypt the key.
	testPassword, err = randutil.Hex(32)
	if err != nil {
		panic(err)
	}

	// Encrypted JWK key used when the key is downloaded from the CA.
	jwe, err := jose.EncryptJWK(&jose.JSONWebKey{Key: testX5CKey}, []byte(testPassword))
	if err != nil {
		panic(err)
	}
	testEncryptedJWKKey, err = jwe.CompactSerialize()
	if err != nil {
		panic(err)
	}
	testKeyID, err = jose.Thumbprint(&jose.JSONWebKey{Key: testX5CKey})
	if err != nil {
		panic(err)
	}

	// Create test files.
	path, err := os.MkdirTemp(os.TempDir(), "stepcas")
	if err != nil {
		panic(err)
	}

	testRootPath = filepath.Join(path, "root_ca.crt")
	testRootKeyPath = filepath.Join(path, "root_ca.key")
	mustSerializeCrt(testRootPath, testRootCrt)
	mustSerializeKey(testRootKeyPath, testRootKey)

	testIssPath = filepath.Join(path, "intermediate_ca.crt")
	testIssKeyPath = filepath.Join(path, "intermediate_ca.key")
	mustSerializeCrt(testIssPath, testIssCrt)
	mustSerializeKey(testIssKeyPath, testIssKey)

	testX5CPath = filepath.Join(path, "x5c.crt")
	testX5CKeyPath = filepath.Join(path, "x5c.key")
	mustSerializeCrt(testX5CPath, testX5CCrt, testIssCrt)
	mustSerializeKey(testX5CKeyPath, testX5CKey)

	testEncryptedKeyPath = filepath.Join(path, "x5c.enc.key")
	mustEncryptKey(testEncryptedKeyPath, testX5CKey)

	code := m.Run()
	if err := os.RemoveAll(path); err != nil {
		panic(err)
	}
	os.Exit(code)
}

func Test_init(t *testing.T) {
	caURL, _ := testCAHelper(t)

	fn, ok := apiv1.LoadCertificateAuthorityServiceNewFunc(apiv1.StepCAS)
	if !ok {
		t.Errorf("apiv1.Register() ok = %v, want true", ok)
		return
	}
	fn(context.Background(), apiv1.Options{
		CertificateAuthority:            caURL.String(),
		CertificateAuthorityFingerprint: testRootFingerprint,
		CertificateIssuer: &apiv1.CertificateIssuer{
			Type:        "x5c",
			Provisioner: "X5C",
			Certificate: testX5CPath,
			Key:         testX5CKeyPath,
		},
	})
}

func TestNew(t *testing.T) {
	caURL, client := testCAHelper(t)
	signer, err := newJWKSignerFromEncryptedKey(testKeyID, testEncryptedJWKKey, testPassword)
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		ctx  context.Context
		opts apiv1.Options
	}
	tests := []struct {
		name    string
		args    args
		want    *StepCAS
		wantErr bool
	}{
		{"ok", args{context.TODO(), apiv1.Options{
			CertificateAuthority:            caURL.String(),
			CertificateAuthorityFingerprint: testRootFingerprint,
			CertificateIssuer: &apiv1.CertificateIssuer{
				Type:        "x5c",
				Provisioner: "X5C",
				Certificate: testX5CPath,
				Key:         testX5CKeyPath,
			},
		}}, &StepCAS{
			iss: &x5cIssuer{
				caURL:    caURL,
				certFile: testX5CPath,
				keyFile:  testX5CKeyPath,
				issuer:   "X5C",
			},
			client:      client,
			fingerprint: testRootFingerprint,
		}, false},
		{"ok jwk", args{context.TODO(), apiv1.Options{
			CertificateAuthority:            caURL.String(),
			CertificateAuthorityFingerprint: testRootFingerprint,
			CertificateIssuer: &apiv1.CertificateIssuer{
				Type:        "jwk",
				Provisioner: "ra@doe.org",
				Key:         testX5CKeyPath,
			},
		}}, &StepCAS{
			iss: &jwkIssuer{
				caURL:  caURL,
				issuer: "ra@doe.org",
				signer: signer,
			},
			client:      client,
			fingerprint: testRootFingerprint,
		}, false},
		{"ok jwk provisioners", args{context.TODO(), apiv1.Options{
			CertificateAuthority:            caURL.String(),
			CertificateAuthorityFingerprint: testRootFingerprint,
			CertificateIssuer: &apiv1.CertificateIssuer{
				Type:        "jwk",
				Provisioner: "ra@doe.org",
				Password:    testPassword,
			},
		}}, &StepCAS{
			iss: &jwkIssuer{
				caURL:  caURL,
				issuer: "ra@doe.org",
				signer: signer,
			},
			client:      client,
			fingerprint: testRootFingerprint,
		}, false},
		{"ok ca getter", args{context.TODO(), apiv1.Options{
			IsCAGetter:                      true,
			CertificateAuthority:            caURL.String(),
			CertificateAuthorityFingerprint: testRootFingerprint,
			CertificateIssuer: &apiv1.CertificateIssuer{
				Type:        "jwk",
				Provisioner: "ra@doe.org",
			},
		}}, &StepCAS{
			iss:         nil,
			client:      client,
			fingerprint: testRootFingerprint,
		}, false},
		{"fail authority", args{context.TODO(), apiv1.Options{
			CertificateAuthority:            "",
			CertificateAuthorityFingerprint: testRootFingerprint,
			CertificateIssuer: &apiv1.CertificateIssuer{
				Type:        "x5c",
				Provisioner: "X5C",
				Certificate: testX5CPath,
				Key:         testX5CKeyPath,
			},
		}}, nil, true},
		{"fail fingerprint", args{context.TODO(), apiv1.Options{
			CertificateAuthority:            caURL.String(),
			CertificateAuthorityFingerprint: "",
			CertificateIssuer: &apiv1.CertificateIssuer{
				Type:        "x5c",
				Provisioner: "X5C",
				Certificate: testX5CPath,
				Key:         testX5CKeyPath,
			},
		}}, nil, true},
		{"fail type", args{context.TODO(), apiv1.Options{
			CertificateAuthority:            caURL.String(),
			CertificateAuthorityFingerprint: testRootFingerprint,
			CertificateIssuer: &apiv1.CertificateIssuer{
				Type:        "",
				Provisioner: "X5C",
				Certificate: testX5CPath,
				Key:         testX5CKeyPath,
			},
		}}, nil, true},
		{"fail provisioner", args{context.TODO(), apiv1.Options{
			CertificateAuthority:            caURL.String(),
			CertificateAuthorityFingerprint: testRootFingerprint,
			CertificateIssuer: &apiv1.CertificateIssuer{
				Type:        "x5c",
				Provisioner: "",
				Certificate: testX5CPath,
				Key:         testX5CKeyPath,
			},
		}}, nil, true},
		{"fail provisioner jwk", args{context.TODO(), apiv1.Options{
			CertificateAuthority:            caURL.String(),
			CertificateAuthorityFingerprint: testRootFingerprint,
			CertificateIssuer: &apiv1.CertificateIssuer{
				Type:        "jwk",
				Provisioner: "",
				Key:         testX5CKeyPath,
			},
		}}, nil, true},
		{"fail provisioner not found", args{context.TODO(), apiv1.Options{
			CertificateAuthority:            caURL.String(),
			CertificateAuthorityFingerprint: testRootFingerprint,
			CertificateIssuer: &apiv1.CertificateIssuer{
				Type:        "jwk",
				Provisioner: "notfound@doe.org",
				Password:    testPassword,
			},
		}}, nil, true},
		{"fail invalid password", args{context.TODO(), apiv1.Options{
			CertificateAuthority:            caURL.String(),
			CertificateAuthorityFingerprint: testRootFingerprint,
			CertificateIssuer: &apiv1.CertificateIssuer{
				Type:        "jwk",
				Provisioner: "ra@doe.org",
				Password:    "bad-password",
			},
		}}, nil, true},
		{"fail no key", args{context.TODO(), apiv1.Options{
			CertificateAuthority:            caURL.String(),
			CertificateAuthorityFingerprint: testRootFingerprint,
			CertificateIssuer: &apiv1.CertificateIssuer{
				Type:        "jwk",
				Provisioner: "empty@doe.org",
				Password:    testPassword,
			},
		}}, nil, true},
		{"fail certificate", args{context.TODO(), apiv1.Options{
			CertificateAuthority:            caURL.String(),
			CertificateAuthorityFingerprint: testRootFingerprint,
			CertificateIssuer: &apiv1.CertificateIssuer{
				Type:        "x5c",
				Provisioner: "X5C",
				Certificate: "",
				Key:         testX5CKeyPath,
			},
		}}, nil, true},
		{"fail key", args{context.TODO(), apiv1.Options{
			CertificateAuthority:            caURL.String(),
			CertificateAuthorityFingerprint: testRootFingerprint,
			CertificateIssuer: &apiv1.CertificateIssuer{
				Type:        "x5c",
				Provisioner: "X5C",
				Certificate: testX5CPath,
				Key:         "",
			},
		}}, nil, true},
		{"fail key jwk", args{context.TODO(), apiv1.Options{
			CertificateAuthority:            caURL.String(),
			CertificateAuthorityFingerprint: testRootFingerprint,
			CertificateIssuer: &apiv1.CertificateIssuer{
				Type:        "jwk",
				Provisioner: "ra@smallstep.com",
				Key:         "",
			},
		}}, nil, true},
		{"bad authority", args{context.TODO(), apiv1.Options{
			CertificateAuthority:            "https://foobar",
			CertificateAuthorityFingerprint: testRootFingerprint,
			CertificateIssuer: &apiv1.CertificateIssuer{
				Type:        "x5c",
				Provisioner: "X5C",
				Certificate: testX5CPath,
				Key:         testX5CKeyPath,
			},
		}}, nil, true},
		{"fail parse url", args{context.TODO(), apiv1.Options{
			CertificateAuthority:            "::failparse",
			CertificateAuthorityFingerprint: testRootFingerprint,
			CertificateIssuer: &apiv1.CertificateIssuer{
				Type:        "x5c",
				Provisioner: "X5C",
				Certificate: testX5CPath,
				Key:         testX5CKeyPath,
			},
		}}, nil, true},
		{"fail new client", args{context.TODO(), apiv1.Options{
			CertificateAuthority:            caURL.String(),
			CertificateAuthorityFingerprint: "foobar",
			CertificateIssuer: &apiv1.CertificateIssuer{
				Type:        "x5c",
				Provisioner: "X5C",
				Certificate: testX5CPath,
				Key:         testX5CKeyPath,
			},
		}}, nil, true},
		{"fail new x5c issuer", args{context.TODO(), apiv1.Options{
			CertificateAuthority:            caURL.String(),
			CertificateAuthorityFingerprint: testRootFingerprint,
			CertificateIssuer: &apiv1.CertificateIssuer{
				Type:        "x5c",
				Provisioner: "X5C",
				Certificate: testX5CPath + ".missing",
				Key:         testX5CKeyPath,
			},
		}}, nil, true},
		{"fail new jwk issuer", args{context.TODO(), apiv1.Options{
			CertificateAuthority:            caURL.String(),
			CertificateAuthorityFingerprint: testRootFingerprint,
			CertificateIssuer: &apiv1.CertificateIssuer{
				Type:        "jwk",
				Provisioner: "ra@doe.org",
				Key:         testX5CKeyPath + ".missing",
			},
		}}, nil, true},
		{"bad issuer", args{context.TODO(), apiv1.Options{
			CertificateAuthority:            caURL.String(),
			CertificateAuthorityFingerprint: testRootFingerprint,
			CertificateIssuer:               nil}}, nil, true},
		{"bad issuer type", args{context.TODO(), apiv1.Options{
			CertificateAuthority:            caURL.String(),
			CertificateAuthorityFingerprint: testRootFingerprint,
			CertificateIssuer: &apiv1.CertificateIssuer{
				Type:        "fail",
				Provisioner: "X5C",
				Certificate: testX5CPath,
				Key:         testX5CKeyPath,
			},
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.args.ctx, tt.args.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			// We cannot compare neither the client nor the signer.
			if got != nil && tt.want != nil {
				got.client = tt.want.client
				if jwk, ok := got.iss.(*jwkIssuer); ok {
					jwk.signer = signer
				}
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStepCAS_CreateCertificate(t *testing.T) {
	caURL, client := testCAHelper(t)
	x5c := testX5CIssuer(t, caURL, "")
	jwk := testJWKIssuer(t, caURL, "")
	x5cEnc := testX5CIssuer(t, caURL, testPassword)
	jwkEnc := testJWKIssuer(t, caURL, testPassword)
	x5cBad := testX5CIssuer(t, caURL, "bad-password")

	type fields struct {
		iss         stepIssuer
		client      *ca.Client
		fingerprint string
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
		{"ok", fields{x5c, client, testRootFingerprint}, args{&apiv1.CreateCertificateRequest{
			CSR:      testCR,
			Lifetime: time.Hour,
		}}, &apiv1.CreateCertificateResponse{
			Certificate:      testCrt,
			CertificateChain: []*x509.Certificate{testIssCrt},
		}, false},
		{"ok with password", fields{x5cEnc, client, testRootFingerprint}, args{&apiv1.CreateCertificateRequest{
			CSR:      testCR,
			Lifetime: time.Hour,
		}}, &apiv1.CreateCertificateResponse{
			Certificate:      testCrt,
			CertificateChain: []*x509.Certificate{testIssCrt},
		}, false},
		{"ok jwk", fields{jwk, client, testRootFingerprint}, args{&apiv1.CreateCertificateRequest{
			CSR:      testCR,
			Lifetime: time.Hour,
		}}, &apiv1.CreateCertificateResponse{
			Certificate:      testCrt,
			CertificateChain: []*x509.Certificate{testIssCrt},
		}, false},
		{"ok jwk with password", fields{jwkEnc, client, testRootFingerprint}, args{&apiv1.CreateCertificateRequest{
			CSR:      testCR,
			Lifetime: time.Hour,
		}}, &apiv1.CreateCertificateResponse{
			Certificate:      testCrt,
			CertificateChain: []*x509.Certificate{testIssCrt},
		}, false},
		{"ok with provisioner", fields{jwk, client, testRootFingerprint}, args{&apiv1.CreateCertificateRequest{
			CSR:         testCR,
			Lifetime:    time.Hour,
			Provisioner: &apiv1.ProvisionerInfo{ID: "provisioner-id", Type: "ACME"},
		}}, &apiv1.CreateCertificateResponse{
			Certificate:      testCrt,
			CertificateChain: []*x509.Certificate{testIssCrt},
		}, false},
		{"ok with server cert", fields{jwk, client, testRootFingerprint}, args{&apiv1.CreateCertificateRequest{
			CSR:            testCR,
			Lifetime:       time.Hour,
			IsCAServerCert: true,
		}}, &apiv1.CreateCertificateResponse{
			Certificate:      testCrt,
			CertificateChain: []*x509.Certificate{testIssCrt},
		}, false},
		{"fail CSR", fields{x5c, client, testRootFingerprint}, args{&apiv1.CreateCertificateRequest{
			CSR:      nil,
			Lifetime: time.Hour,
		}}, nil, true},
		{"fail lifetime", fields{x5c, client, testRootFingerprint}, args{&apiv1.CreateCertificateRequest{
			CSR:      testCR,
			Lifetime: 0,
		}}, nil, true},
		{"fail sign token", fields{mockErrIssuer{}, client, testRootFingerprint}, args{&apiv1.CreateCertificateRequest{
			CSR:      testCR,
			Lifetime: time.Hour,
		}}, nil, true},
		{"fail client sign", fields{x5c, client, testRootFingerprint}, args{&apiv1.CreateCertificateRequest{
			CSR:      testFailCR,
			Lifetime: time.Hour,
		}}, nil, true},
		{"fail password", fields{x5cBad, client, testRootFingerprint}, args{&apiv1.CreateCertificateRequest{
			CSR:      testCR,
			Lifetime: time.Hour,
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &StepCAS{
				iss:         tt.fields.iss,
				client:      tt.fields.client,
				authorityID: "authority-id",
				fingerprint: tt.fields.fingerprint,
			}
			got, err := s.CreateCertificate(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("StepCAS.CreateCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("StepCAS.CreateCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStepCAS_RenewCertificate(t *testing.T) {
	caURL, client := testCAHelper(t)
	jwk := testJWKIssuer(t, caURL, "")

	tokenIssuer := testX5CIssuer(t, caURL, "")
	token, err := tokenIssuer.SignToken("test", []string{"test.example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	type fields struct {
		iss         stepIssuer
		client      *ca.Client
		fingerprint string
	}
	type args struct {
		req *apiv1.RenewCertificateRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *apiv1.RenewCertificateResponse
		wantErr bool
	}{
		{"ok", fields{jwk, client, testRootFingerprint}, args{&apiv1.RenewCertificateRequest{
			Template: &x509.Certificate{},
			Backdate: time.Minute,
			Lifetime: time.Hour,
			Token:    token,
		}}, &apiv1.RenewCertificateResponse{
			Certificate:      testCrt,
			CertificateChain: []*x509.Certificate{testIssCrt},
		}, false},
		{"fail no token", fields{jwk, client, testRootFingerprint}, args{&apiv1.RenewCertificateRequest{
			Template: &x509.Certificate{},
			Backdate: time.Minute,
			Lifetime: time.Hour,
		}}, nil, true},
		{"fail bad token", fields{jwk, client, testRootFingerprint}, args{&apiv1.RenewCertificateRequest{
			Template: &x509.Certificate{},
			Backdate: time.Minute,
			Lifetime: time.Hour,
			Token:    "fail",
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &StepCAS{
				iss:         tt.fields.iss,
				client:      tt.fields.client,
				fingerprint: tt.fields.fingerprint,
			}
			got, err := s.RenewCertificate(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("StepCAS.RenewCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Error(reflect.DeepEqual(got.Certificate, tt.want.Certificate))
				t.Error(reflect.DeepEqual(got.CertificateChain, tt.want.CertificateChain))

				t.Errorf("StepCAS.RenewCertificate() = %v, want %v", got.Certificate.Subject, tt.want.Certificate.Subject)
			}
		})
	}
}

func TestStepCAS_RevokeCertificate(t *testing.T) {
	caURL, client := testCAHelper(t)
	x5c := testX5CIssuer(t, caURL, "")
	jwk := testJWKIssuer(t, caURL, "")
	x5cEnc := testX5CIssuer(t, caURL, testPassword)
	jwkEnc := testJWKIssuer(t, caURL, testPassword)
	x5cBad := testX5CIssuer(t, caURL, "bad-password")

	type fields struct {
		iss         stepIssuer
		client      *ca.Client
		fingerprint string
	}
	type args struct {
		req *apiv1.RevokeCertificateRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *apiv1.RevokeCertificateResponse
		wantErr bool
	}{
		{"ok serial number", fields{x5c, client, testRootFingerprint}, args{&apiv1.RevokeCertificateRequest{
			SerialNumber: "ok",
			Certificate:  nil,
		}}, &apiv1.RevokeCertificateResponse{}, false},
		{"ok certificate", fields{x5c, client, testRootFingerprint}, args{&apiv1.RevokeCertificateRequest{
			SerialNumber: "",
			Certificate:  testCrt,
		}}, &apiv1.RevokeCertificateResponse{
			Certificate: testCrt,
		}, false},
		{"ok both", fields{x5c, client, testRootFingerprint}, args{&apiv1.RevokeCertificateRequest{
			SerialNumber: "ok",
			Certificate:  testCrt,
		}}, &apiv1.RevokeCertificateResponse{
			Certificate: testCrt,
		}, false},
		{"ok with password", fields{x5cEnc, client, testRootFingerprint}, args{&apiv1.RevokeCertificateRequest{
			SerialNumber: "ok",
			Certificate:  nil,
		}}, &apiv1.RevokeCertificateResponse{}, false},
		{"ok serial number jwk", fields{jwk, client, testRootFingerprint}, args{&apiv1.RevokeCertificateRequest{
			SerialNumber: "ok",
			Certificate:  nil,
		}}, &apiv1.RevokeCertificateResponse{}, false},
		{"ok certificate jwk", fields{jwk, client, testRootFingerprint}, args{&apiv1.RevokeCertificateRequest{
			SerialNumber: "",
			Certificate:  testCrt,
		}}, &apiv1.RevokeCertificateResponse{
			Certificate: testCrt,
		}, false},
		{"ok both jwk", fields{jwk, client, testRootFingerprint}, args{&apiv1.RevokeCertificateRequest{
			SerialNumber: "ok",
			Certificate:  testCrt,
		}}, &apiv1.RevokeCertificateResponse{
			Certificate: testCrt,
		}, false},
		{"ok jwk with password", fields{jwkEnc, client, testRootFingerprint}, args{&apiv1.RevokeCertificateRequest{
			SerialNumber: "ok",
			Certificate:  nil,
		}}, &apiv1.RevokeCertificateResponse{}, false},
		{"fail request", fields{x5c, client, testRootFingerprint}, args{&apiv1.RevokeCertificateRequest{
			SerialNumber: "",
			Certificate:  nil,
		}}, nil, true},
		{"fail revoke token", fields{mockErrIssuer{}, client, testRootFingerprint}, args{&apiv1.RevokeCertificateRequest{
			SerialNumber: "ok",
		}}, nil, true},
		{"fail client revoke", fields{x5c, client, testRootFingerprint}, args{&apiv1.RevokeCertificateRequest{
			SerialNumber: "fail",
		}}, nil, true},
		{"fail password", fields{x5cBad, client, testRootFingerprint}, args{&apiv1.RevokeCertificateRequest{
			SerialNumber: "ok",
			Certificate:  nil,
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &StepCAS{
				iss:         tt.fields.iss,
				client:      tt.fields.client,
				fingerprint: tt.fields.fingerprint,
			}
			got, err := s.RevokeCertificate(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("StepCAS.RevokeCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("StepCAS.RevokeCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStepCAS_GetCertificateAuthority(t *testing.T) {
	caURL, client := testCAHelper(t)
	x5c := testX5CIssuer(t, caURL, "")
	jwk := testJWKIssuer(t, caURL, "")

	type fields struct {
		iss         stepIssuer
		client      *ca.Client
		fingerprint string
	}
	type args struct {
		req *apiv1.GetCertificateAuthorityRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *apiv1.GetCertificateAuthorityResponse
		wantErr bool
	}{
		{"ok", fields{x5c, client, testRootFingerprint}, args{&apiv1.GetCertificateAuthorityRequest{
			Name: caURL.String(),
		}}, &apiv1.GetCertificateAuthorityResponse{
			RootCertificate: testRootCrt,
		}, false},
		{"ok jwk", fields{jwk, client, testRootFingerprint}, args{&apiv1.GetCertificateAuthorityRequest{
			Name: caURL.String(),
		}}, &apiv1.GetCertificateAuthorityResponse{
			RootCertificate: testRootCrt,
		}, false},
		{"fail fingerprint", fields{x5c, client, "fail"}, args{&apiv1.GetCertificateAuthorityRequest{
			Name: caURL.String(),
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &StepCAS{
				iss:         tt.fields.iss,
				client:      tt.fields.client,
				fingerprint: tt.fields.fingerprint,
			}
			got, err := s.GetCertificateAuthority(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("StepCAS.GetCertificateAuthority() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("StepCAS.GetCertificateAuthority() = %v, want %v", got, tt.want)
			}
		})
	}
}
