package authority

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // used to create the Subject Key Identifier by RFC 5280
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"

	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/minica"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/x509util"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/policy"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/cas/softcas"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/certificates/errs"
	"github.com/smallstep/nosql/database"
)

var (
	stepOIDRoot        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64}
	stepOIDProvisioner = append(asn1.ObjectIdentifier(nil), append(stepOIDRoot, 1)...)
)

const provisionerTypeJWK = 1

type stepProvisionerASN1 struct {
	Type         int
	Name         []byte
	CredentialID []byte
}

type certificateDurationEnforcer struct {
	NotBefore time.Time
	NotAfter  time.Time
}

func (m *certificateDurationEnforcer) Enforce(cert *x509.Certificate) error {
	cert.NotBefore = m.NotBefore
	cert.NotAfter = m.NotAfter
	return nil
}

type certificateChainDB struct {
	db.MockAuthDB
	MStoreCertificateChain func(provisioner.Interface, ...*x509.Certificate) error
}

func (d *certificateChainDB) StoreCertificateChain(p provisioner.Interface, certs ...*x509.Certificate) error {
	return d.MStoreCertificateChain(p, certs...)
}

func getDefaultIssuer(a *Authority) *x509.Certificate {
	return a.x509CAService.(*softcas.SoftCAS).CertificateChain[len(a.x509CAService.(*softcas.SoftCAS).CertificateChain)-1]
}

func getDefaultSigner(a *Authority) crypto.Signer {
	return a.x509CAService.(*softcas.SoftCAS).Signer
}

func generateCertificate(t *testing.T, commonName string, sans []string, opts ...interface{}) *x509.Certificate {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.FatalError(t, err)

	cr, err := x509util.CreateCertificateRequest(commonName, sans, priv)
	assert.FatalError(t, err)

	template, err := x509util.NewCertificate(cr)
	assert.FatalError(t, err)

	cert := template.GetCertificate()
	for _, m := range opts {
		switch m := m.(type) {
		case provisioner.CertificateModifierFunc:
			err = m.Modify(cert, provisioner.SignOptions{})
			assert.FatalError(t, err)
		case signerFunc:
			cert, err = m(cert, priv.Public())
			assert.FatalError(t, err)
		default:
			t.Fatalf("unknown type %T", m)
		}

	}
	return cert
}

func generateRootCertificate(t *testing.T) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.FatalError(t, err)

	cr, err := x509util.CreateCertificateRequest("TestRootCA", nil, priv)
	assert.FatalError(t, err)

	data := x509util.CreateTemplateData("TestRootCA", nil)
	template, err := x509util.NewCertificate(cr, x509util.WithTemplate(x509util.DefaultRootTemplate, data))
	assert.FatalError(t, err)

	cert := template.GetCertificate()
	cert, err = x509util.CreateCertificate(cert, cert, priv.Public(), priv)
	assert.FatalError(t, err)
	return cert, priv
}

func generateIntermidiateCertificate(t *testing.T, issuer *x509.Certificate, signer crypto.Signer) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.FatalError(t, err)

	cr, err := x509util.CreateCertificateRequest("TestIntermediateCA", nil, priv)
	assert.FatalError(t, err)

	data := x509util.CreateTemplateData("TestIntermediateCA", nil)
	template, err := x509util.NewCertificate(cr, x509util.WithTemplate(x509util.DefaultRootTemplate, data))
	assert.FatalError(t, err)

	cert := template.GetCertificate()
	cert, err = x509util.CreateCertificate(cert, issuer, priv.Public(), signer)
	assert.FatalError(t, err)
	return cert, priv
}

func withSubject(sub pkix.Name) provisioner.CertificateModifierFunc {
	return func(crt *x509.Certificate, _ provisioner.SignOptions) error {
		crt.Subject = sub
		return nil
	}
}

func withProvisionerOID(name, kid string) provisioner.CertificateModifierFunc {
	return func(crt *x509.Certificate, _ provisioner.SignOptions) error {
		b, err := asn1.Marshal(stepProvisionerASN1{
			Type:         provisionerTypeJWK,
			Name:         []byte(name),
			CredentialID: []byte(kid),
		})
		if err != nil {
			return err
		}
		crt.ExtraExtensions = append(crt.ExtraExtensions, pkix.Extension{
			Id:       stepOIDProvisioner,
			Critical: false,
			Value:    b,
		})
		return nil
	}
}

func withNotBeforeNotAfter(notBefore, notAfter time.Time) provisioner.CertificateModifierFunc {
	return func(crt *x509.Certificate, _ provisioner.SignOptions) error {
		crt.NotBefore = notBefore
		crt.NotAfter = notAfter
		return nil
	}
}

type signerFunc func(crt *x509.Certificate, pub crypto.PublicKey) (*x509.Certificate, error)

func withSigner(issuer *x509.Certificate, signer crypto.Signer) signerFunc {
	return func(crt *x509.Certificate, pub crypto.PublicKey) (*x509.Certificate, error) {
		return x509util.CreateCertificate(crt, issuer, pub, signer)
	}
}

func getCSR(t *testing.T, priv interface{}, opts ...func(*x509.CertificateRequest)) *x509.CertificateRequest {
	_csr := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "smallstep test"},
		DNSNames: []string{"test.smallstep.com"},
	}
	for _, opt := range opts {
		opt(_csr)
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, _csr, priv)
	assert.FatalError(t, err)
	csr, err := x509.ParseCertificateRequest(csrBytes)
	assert.FatalError(t, err)
	return csr
}

func setExtraExtsCSR(exts []pkix.Extension) func(*x509.CertificateRequest) {
	return func(csr *x509.CertificateRequest) {
		csr.ExtraExtensions = exts
	}
}

func generateSubjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("error marshaling public key: %w", err)
	}
	info := struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}{}
	if _, err = asn1.Unmarshal(b, &info); err != nil {
		return nil, fmt.Errorf("error unmarshaling public key: %w", err)
	}
	//nolint:gosec // used to create the Subject Key Identifier by RFC 5280
	hash := sha1.Sum(info.SubjectPublicKey.Bytes)
	return hash[:], nil
}

type basicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

type testEnforcer struct {
	enforcer func(*x509.Certificate) error
}

func (e *testEnforcer) Enforce(cert *x509.Certificate) error {
	if e.enforcer != nil {
		return e.enforcer(cert)
	}
	return nil
}

func TestAuthority_Sign(t *testing.T) {
	pub, priv, err := keyutil.GenerateDefaultKeyPair()
	assert.FatalError(t, err)

	a := testAuthority(t)
	assert.FatalError(t, err)
	a.config.AuthorityConfig.Template = &ASN1DN{
		Country:       "Tazmania",
		Organization:  "Acme Co",
		Locality:      "Landscapes",
		Province:      "Sudden Cliffs",
		StreetAddress: "TNT",
		CommonName:    "test.smallstep.com",
	}

	nb := time.Now()
	signOpts := provisioner.SignOptions{
		NotBefore: provisioner.NewTimeDuration(nb),
		NotAfter:  provisioner.NewTimeDuration(nb.Add(time.Minute * 5)),
		Backdate:  1 * time.Minute,
	}

	// Create a token to get test extra opts.
	p := a.config.AuthorityConfig.Provisioners[1].(*provisioner.JWK)
	key, err := jose.ReadKey("testdata/secrets/step_cli_key_priv.jwk", jose.WithPassword([]byte("pass")))
	assert.FatalError(t, err)
	token, err := generateToken("smallstep test", "step-cli", testAudiences.Sign[0], []string{"test.smallstep.com"}, time.Now(), key)
	assert.FatalError(t, err)
	ctx := provisioner.NewContextWithMethod(context.Background(), provisioner.SignMethod)
	extraOpts, err := a.Authorize(ctx, token)
	assert.FatalError(t, err)

	type signTest struct {
		auth            *Authority
		csr             *x509.CertificateRequest
		signOpts        provisioner.SignOptions
		extraOpts       []provisioner.SignOption
		notBefore       time.Time
		notAfter        time.Time
		extensionsCount int
		err             error
		code            int
	}
	tests := map[string]func(*testing.T) *signTest{
		"fail invalid signature": func(t *testing.T) *signTest {
			csr := getCSR(t, priv)
			csr.Signature = []byte("foo")
			return &signTest{
				auth:      a,
				csr:       csr,
				extraOpts: extraOpts,
				signOpts:  signOpts,
				err:       errors.New("invalid certificate request"),
				code:      http.StatusBadRequest,
			}
		},
		"fail invalid extra option": func(t *testing.T) *signTest {
			csr := getCSR(t, priv)
			csr.Raw = []byte("foo")
			return &signTest{
				auth:      a,
				csr:       csr,
				extraOpts: append(extraOpts, "42"),
				signOpts:  signOpts,
				err:       errors.New("authority.Sign; invalid extra option type string"),
				code:      http.StatusInternalServerError,
			}
		},
		"fail merge default ASN1DN": func(t *testing.T) *signTest {
			_a := testAuthority(t)
			_a.config.AuthorityConfig.Template = nil
			csr := getCSR(t, priv)
			return &signTest{
				auth:      _a,
				csr:       csr,
				extraOpts: extraOpts,
				signOpts:  signOpts,
				err:       errors.New("default ASN1DN template cannot be nil"),
				code:      http.StatusForbidden,
			}
		},
		"fail create cert": func(t *testing.T) *signTest {
			_a := testAuthority(t)
			_a.x509CAService.(*softcas.SoftCAS).Signer = nil
			csr := getCSR(t, priv)
			return &signTest{
				auth:      _a,
				csr:       csr,
				extraOpts: extraOpts,
				signOpts:  signOpts,
				err:       errors.New("authority.Sign; error creating certificate"),
				code:      http.StatusInternalServerError,
			}
		},
		"fail provisioner duration claim": func(t *testing.T) *signTest {
			csr := getCSR(t, priv)
			_signOpts := provisioner.SignOptions{
				NotBefore: provisioner.NewTimeDuration(nb),
				NotAfter:  provisioner.NewTimeDuration(nb.Add(time.Hour * 25)),
			}
			return &signTest{
				auth:      a,
				csr:       csr,
				extraOpts: extraOpts,
				signOpts:  _signOpts,
				err:       errors.New("requested duration of 25h0m0s is more than the authorized maximum certificate duration of 24h1m0s"),
				code:      http.StatusForbidden,
			}
		},
		"fail validate sans when adding common name not in claims": func(t *testing.T) *signTest {
			csr := getCSR(t, priv, func(csr *x509.CertificateRequest) {
				csr.DNSNames = append(csr.DNSNames, csr.Subject.CommonName)
			})
			return &signTest{
				auth:      a,
				csr:       csr,
				extraOpts: extraOpts,
				signOpts:  signOpts,
				err:       errors.New("certificate request does not contain the valid DNS names - got [test.smallstep.com smallstep test], want [test.smallstep.com]"),
				code:      http.StatusForbidden,
			}
		},
		"fail rsa key too short": func(t *testing.T) *signTest {
			shortRSAKeyPEM := `-----BEGIN CERTIFICATE REQUEST-----
MIIBhDCB7gIBADAZMRcwFQYDVQQDEw5zbWFsbHN0ZXAgdGVzdDCBnzANBgkqhkiG
9w0BAQEFAAOBjQAwgYkCgYEA5JlgH99HvHHsCD6XTqqYj3bXU2oIlnYGoLVs7IJ4
k205rv5/YWky2gjdpIv0Tnaf3o57IJ891lB7GiyO5iHIEUv5N9dVzrdUboyzk2uZ
7JMMNB43CSLB2oNuwJjLeAM/yBzlhRnvpKjrNSfSV+cH54FXdnbFbcTFMStnjqKG
MeECAwEAAaAsMCoGCSqGSIb3DQEJDjEdMBswGQYDVR0RBBIwEIIOc21hbGxzdGVw
IHRlc3QwDQYJKoZIhvcNAQELBQADgYEAKwsbr8Zfcq05DgOoJ//cXMFK1SP8ktRU
N2++E8Ww0Tet9oyNRArqxxS/UyVio63D3wynzRAB25PFGpYG1cN4b81Gv/foFUT6
W5kR63lNVHBHgQmv5mA8YFsfrJHstaz5k727v2LMHEYIf5/3i16d5zhuxUoaPTYr
ZYtQ9Ot36qc=
-----END CERTIFICATE REQUEST-----`
			block, _ := pem.Decode([]byte(shortRSAKeyPEM))
			assert.FatalError(t, err)
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			assert.FatalError(t, err)

			return &signTest{
				auth:      a,
				csr:       csr,
				extraOpts: extraOpts,
				signOpts:  signOpts,
				err:       errors.New("certificate request RSA key must be at least 2048 bits (256 bytes)"),
				code:      http.StatusForbidden,
			}
		},
		"fail store cert in db": func(t *testing.T) *signTest {
			csr := getCSR(t, priv)
			_a := testAuthority(t)
			_a.db = &db.MockAuthDB{
				MStoreCertificate: func(crt *x509.Certificate) error {
					return errors.New("force")
				},
			}
			return &signTest{
				auth:      _a,
				csr:       csr,
				extraOpts: extraOpts,
				signOpts:  signOpts,
				err:       errors.New("authority.Sign; error storing certificate in db: force"),
				code:      http.StatusInternalServerError,
			}
		},
		"fail custom template": func(t *testing.T) *signTest {
			csr := getCSR(t, priv)
			testAuthority := testAuthority(t)
			p, ok := testAuthority.provisioners.Load("step-cli:4UELJx8e0aS9m0CH3fZ0EB7D5aUPICb759zALHFejvc")
			if !ok {
				t.Fatal("provisioner not found")
			}
			p.(*provisioner.JWK).Options = &provisioner.Options{
				X509: &provisioner.X509Options{Template: `{{ fail "fail message" }}`},
			}
			testExtraOpts, err := testAuthority.Authorize(ctx, token)
			assert.FatalError(t, err)
			testAuthority.db = &db.MockAuthDB{
				MStoreCertificate: func(crt *x509.Certificate) error {
					assert.Equals(t, crt.Subject.CommonName, "smallstep test")
					return nil
				},
			}
			return &signTest{
				auth:      testAuthority,
				csr:       csr,
				extraOpts: testExtraOpts,
				signOpts:  signOpts,
				err:       errors.New("fail message"),
				code:      http.StatusBadRequest,
			}
		},
		"fail bad JSON syntax template file": func(t *testing.T) *signTest {
			csr := getCSR(t, priv)
			testAuthority := testAuthority(t)
			p, ok := testAuthority.provisioners.Load("step-cli:4UELJx8e0aS9m0CH3fZ0EB7D5aUPICb759zALHFejvc")
			if !ok {
				t.Fatal("provisioner not found")
			}
			p.(*provisioner.JWK).Options = &provisioner.Options{
				X509: &provisioner.X509Options{
					TemplateFile: "./testdata/templates/badjsonsyntax.tpl",
				},
			}
			testExtraOpts, err := testAuthority.Authorize(ctx, token)
			assert.FatalError(t, err)
			testAuthority.db = &db.MockAuthDB{
				MStoreCertificate: func(crt *x509.Certificate) error {
					assert.Equals(t, crt.Subject.CommonName, "smallstep test")
					return nil
				},
			}
			return &signTest{
				auth:      testAuthority,
				csr:       csr,
				extraOpts: testExtraOpts,
				signOpts:  signOpts,
				err:       errors.New("error applying certificate template: invalid character"),
				code:      http.StatusInternalServerError,
			}
		},
		"fail bad JSON value template file": func(t *testing.T) *signTest {
			csr := getCSR(t, priv)
			testAuthority := testAuthority(t)
			p, ok := testAuthority.provisioners.Load("step-cli:4UELJx8e0aS9m0CH3fZ0EB7D5aUPICb759zALHFejvc")
			if !ok {
				t.Fatal("provisioner not found")
			}
			p.(*provisioner.JWK).Options = &provisioner.Options{
				X509: &provisioner.X509Options{
					TemplateFile: "./testdata/templates/badjsonvalue.tpl",
				},
			}
			testExtraOpts, err := testAuthority.Authorize(ctx, token)
			assert.FatalError(t, err)
			testAuthority.db = &db.MockAuthDB{
				MStoreCertificate: func(crt *x509.Certificate) error {
					assert.Equals(t, crt.Subject.CommonName, "smallstep test")
					return nil
				},
			}
			return &signTest{
				auth:      testAuthority,
				csr:       csr,
				extraOpts: testExtraOpts,
				signOpts:  signOpts,
				err:       errors.New("error applying certificate template: cannot unmarshal"),
				code:      http.StatusInternalServerError,
			}
		},
		"fail with provisioner enforcer": func(t *testing.T) *signTest {
			csr := getCSR(t, priv)
			aa := testAuthority(t)
			aa.db = &db.MockAuthDB{
				MStoreCertificate: func(crt *x509.Certificate) error {
					assert.Equals(t, crt.Subject.CommonName, "smallstep test")
					return nil
				},
			}

			return &signTest{
				auth: aa,
				csr:  csr,
				extraOpts: append(extraOpts, &testEnforcer{
					enforcer: func(crt *x509.Certificate) error { return fmt.Errorf("an error") },
				}),
				signOpts: signOpts,
				err:      errors.New("error creating certificate"),
				code:     http.StatusForbidden,
			}
		},
		"fail with custom enforcer": func(t *testing.T) *signTest {
			csr := getCSR(t, priv)
			aa := testAuthority(t, WithX509Enforcers(&testEnforcer{
				enforcer: func(cert *x509.Certificate) error {
					return fmt.Errorf("an error")
				},
			}))
			aa.db = &db.MockAuthDB{
				MStoreCertificate: func(crt *x509.Certificate) error {
					assert.Equals(t, crt.Subject.CommonName, "smallstep test")
					return nil
				},
			}
			return &signTest{
				auth:      aa,
				csr:       csr,
				extraOpts: extraOpts,
				signOpts:  signOpts,
				err:       errors.New("error creating certificate"),
				code:      http.StatusForbidden,
			}
		},
		"fail with policy": func(t *testing.T) *signTest {
			csr := getCSR(t, priv)
			aa := testAuthority(t)
			aa.config.AuthorityConfig.Template = a.config.AuthorityConfig.Template
			aa.db = &db.MockAuthDB{
				MStoreCertificate: func(crt *x509.Certificate) error {
					fmt.Println(crt.Subject)
					assert.Equals(t, crt.Subject.CommonName, "smallstep test")
					return nil
				},
			}
			options := &policy.Options{
				X509: &policy.X509PolicyOptions{
					DeniedNames: &policy.X509NameOptions{
						DNSDomains: []string{"test.smallstep.com"},
					},
				},
			}
			engine, err := policy.New(options)
			assert.FatalError(t, err)
			aa.policyEngine = engine
			return &signTest{
				auth:            aa,
				csr:             csr,
				extraOpts:       extraOpts,
				signOpts:        signOpts,
				notBefore:       signOpts.NotBefore.Time().Truncate(time.Second),
				notAfter:        signOpts.NotAfter.Time().Truncate(time.Second),
				extensionsCount: 6,
				err:             errors.New("dns name \"test.smallstep.com\" not allowed"),
				code:            http.StatusForbidden,
			}
		},
		"fail enriching webhooks": func(t *testing.T) *signTest {
			csr := getCSR(t, priv)
			csr.Raw = []byte("foo")
			return &signTest{
				auth:            a,
				csr:             csr,
				extensionsCount: 7,
				extraOpts: append(extraOpts, &mockWebhookController{
					enrichErr: provisioner.ErrWebhookDenied,
				}),
				signOpts: signOpts,
				err:      provisioner.ErrWebhookDenied,
				code:     http.StatusForbidden,
			}
		},
		"fail authorizing webhooks": func(t *testing.T) *signTest {
			csr := getCSR(t, priv)
			csr.Raw = []byte("foo")
			return &signTest{
				auth:            a,
				csr:             csr,
				extensionsCount: 7,
				extraOpts: append(extraOpts, &mockWebhookController{
					authorizeErr: provisioner.ErrWebhookDenied,
				}),
				signOpts: signOpts,
				err:      provisioner.ErrWebhookDenied,
				code:     http.StatusForbidden,
			}
		},
		"ok": func(t *testing.T) *signTest {
			csr := getCSR(t, priv)
			_a := testAuthority(t)
			_a.db = &db.MockAuthDB{
				MStoreCertificate: func(crt *x509.Certificate) error {
					assert.Equals(t, crt.Subject.CommonName, "smallstep test")
					return nil
				},
			}
			return &signTest{
				auth:            a,
				csr:             csr,
				extraOpts:       extraOpts,
				signOpts:        signOpts,
				notBefore:       signOpts.NotBefore.Time().Truncate(time.Second),
				notAfter:        signOpts.NotAfter.Time().Truncate(time.Second),
				extensionsCount: 6,
			}
		},
		"ok with enforced modifier": func(t *testing.T) *signTest {
			bcExt := pkix.Extension{}
			bcExt.Id = asn1.ObjectIdentifier{2, 5, 29, 19}
			bcExt.Critical = false
			bcExt.Value, err = asn1.Marshal(basicConstraints{IsCA: true, MaxPathLen: 4})
			assert.FatalError(t, err)

			csr := getCSR(t, priv, setExtraExtsCSR([]pkix.Extension{
				bcExt,
				{Id: stepOIDProvisioner, Value: []byte("foo")},
				{Id: []int{1, 1, 1}, Value: []byte("bar")}}))
			now := time.Now().UTC()
			//nolint:gocritic
			enforcedExtraOptions := append(extraOpts, &certificateDurationEnforcer{
				NotBefore: now,
				NotAfter:  now.Add(365 * 24 * time.Hour),
			})
			_a := testAuthority(t)
			_a.db = &db.MockAuthDB{
				MStoreCertificate: func(crt *x509.Certificate) error {
					assert.Equals(t, crt.Subject.CommonName, "smallstep test")
					return nil
				},
			}
			return &signTest{
				auth:            a,
				csr:             csr,
				extraOpts:       enforcedExtraOptions,
				signOpts:        signOpts,
				notBefore:       now.Truncate(time.Second),
				notAfter:        now.Add(365 * 24 * time.Hour).Truncate(time.Second),
				extensionsCount: 6,
			}
		},
		"ok with custom template": func(t *testing.T) *signTest {
			csr := getCSR(t, priv)
			testAuthority := testAuthority(t)
			testAuthority.config.AuthorityConfig.Template = a.config.AuthorityConfig.Template
			p, ok := testAuthority.provisioners.Load("step-cli:4UELJx8e0aS9m0CH3fZ0EB7D5aUPICb759zALHFejvc")
			if !ok {
				t.Fatal("provisioner not found")
			}
			p.(*provisioner.JWK).Options = &provisioner.Options{
				X509: &provisioner.X509Options{Template: `{
					"subject": {{toJson .Subject}},
					"dnsNames": {{ toJson .Insecure.CR.DNSNames }},
					"keyUsage": ["digitalSignature"],
					"extKeyUsage": ["serverAuth","clientAuth"]
				}`},
			}
			testExtraOpts, err := testAuthority.Authorize(ctx, token)
			assert.FatalError(t, err)
			testAuthority.db = &db.MockAuthDB{
				MStoreCertificate: func(crt *x509.Certificate) error {
					assert.Equals(t, crt.Subject.CommonName, "smallstep test")
					return nil
				},
			}
			return &signTest{
				auth:            testAuthority,
				csr:             csr,
				extraOpts:       testExtraOpts,
				signOpts:        signOpts,
				notBefore:       signOpts.NotBefore.Time().Truncate(time.Second),
				notAfter:        signOpts.NotAfter.Time().Truncate(time.Second),
				extensionsCount: 6,
			}
		},
		"ok with enriching webhook": func(t *testing.T) *signTest {
			csr := getCSR(t, priv)
			testAuthority := testAuthority(t)
			testAuthority.config.AuthorityConfig.Template = a.config.AuthorityConfig.Template
			p, ok := testAuthority.provisioners.Load("step-cli:4UELJx8e0aS9m0CH3fZ0EB7D5aUPICb759zALHFejvc")
			if !ok {
				t.Fatal("provisioner not found")
			}
			p.(*provisioner.JWK).Options = &provisioner.Options{
				X509: &provisioner.X509Options{Template: `{
					"subject": {"commonName": {{ toJson .Webhooks.people.role }} },
					"dnsNames": {{ toJson .Insecure.CR.DNSNames }},
					"keyUsage": ["digitalSignature"],
					"extKeyUsage": ["serverAuth","clientAuth"]
				}`},
			}
			testExtraOpts, err := testAuthority.Authorize(ctx, token)
			assert.FatalError(t, err)
			testAuthority.db = &db.MockAuthDB{
				MStoreCertificate: func(crt *x509.Certificate) error {
					assert.Equals(t, crt.Subject.CommonName, "smallstep test")
					return nil
				},
			}
			for i, o := range testExtraOpts {
				if wc, ok := o.(*provisioner.WebhookController); ok {
					testExtraOpts[i] = &mockWebhookController{
						templateData: wc.TemplateData,
						respData:     map[string]any{"people": map[string]any{"role": "smallstep test"}},
					}
				}
			}
			return &signTest{
				auth:            testAuthority,
				csr:             csr,
				extraOpts:       testExtraOpts,
				signOpts:        signOpts,
				notBefore:       signOpts.NotBefore.Time().Truncate(time.Second),
				notAfter:        signOpts.NotAfter.Time().Truncate(time.Second),
				extensionsCount: 6,
			}
		},
		"ok/csr with no template critical SAN extension": func(t *testing.T) *signTest {
			csr := getCSR(t, priv, func(csr *x509.CertificateRequest) {
				csr.Subject = pkix.Name{}
			}, func(csr *x509.CertificateRequest) {
				csr.DNSNames = []string{"foo", "bar"}
			})
			now := time.Now().UTC()
			enforcedExtraOptions := []provisioner.SignOption{&certificateDurationEnforcer{
				NotBefore: now,
				NotAfter:  now.Add(365 * 24 * time.Hour),
			}}
			_a := testAuthority(t)
			_a.config.AuthorityConfig.Template = &ASN1DN{}
			_a.db = &db.MockAuthDB{
				MStoreCertificate: func(crt *x509.Certificate) error {
					assert.Equals(t, crt.Subject, pkix.Name{})
					return nil
				},
			}
			return &signTest{
				auth:            _a,
				csr:             csr,
				extraOpts:       enforcedExtraOptions,
				signOpts:        provisioner.SignOptions{},
				notBefore:       now.Truncate(time.Second),
				notAfter:        now.Add(365 * 24 * time.Hour).Truncate(time.Second),
				extensionsCount: 5,
			}
		},
		"ok with custom enforcer": func(t *testing.T) *signTest {
			csr := getCSR(t, priv)
			aa := testAuthority(t, WithX509Enforcers(&testEnforcer{
				enforcer: func(cert *x509.Certificate) error {
					cert.CRLDistributionPoints = []string{"http://ca.example.org/leaf.crl"}
					return nil
				},
			}))
			aa.config.AuthorityConfig.Template = a.config.AuthorityConfig.Template
			aa.db = &db.MockAuthDB{
				MStoreCertificate: func(crt *x509.Certificate) error {
					assert.Equals(t, crt.Subject.CommonName, "smallstep test")
					assert.Equals(t, crt.CRLDistributionPoints, []string{"http://ca.example.org/leaf.crl"})
					return nil
				},
			}
			return &signTest{
				auth:            aa,
				csr:             csr,
				extraOpts:       extraOpts,
				signOpts:        signOpts,
				notBefore:       signOpts.NotBefore.Time().Truncate(time.Second),
				notAfter:        signOpts.NotAfter.Time().Truncate(time.Second),
				extensionsCount: 7,
			}
		},
		"ok with policy": func(t *testing.T) *signTest {
			csr := getCSR(t, priv)
			aa := testAuthority(t)
			aa.config.AuthorityConfig.Template = a.config.AuthorityConfig.Template
			aa.db = &db.MockAuthDB{
				MStoreCertificate: func(crt *x509.Certificate) error {
					assert.Equals(t, crt.Subject.CommonName, "smallstep test")
					return nil
				},
			}
			options := &policy.Options{
				X509: &policy.X509PolicyOptions{
					AllowedNames: &policy.X509NameOptions{
						CommonNames: []string{"smallstep test"},
						DNSDomains:  []string{"*.smallstep.com"},
					},
				},
			}
			engine, err := policy.New(options)
			assert.FatalError(t, err)
			aa.policyEngine = engine
			return &signTest{
				auth:            aa,
				csr:             csr,
				extraOpts:       extraOpts,
				signOpts:        signOpts,
				notBefore:       signOpts.NotBefore.Time().Truncate(time.Second),
				notAfter:        signOpts.NotAfter.Time().Truncate(time.Second),
				extensionsCount: 6,
			}
		},
		"ok with attestation data": func(t *testing.T) *signTest {
			csr := getCSR(t, priv)
			aa := testAuthority(t)
			aa.config.AuthorityConfig.Template = a.config.AuthorityConfig.Template
			aa.db = &certificateChainDB{
				MStoreCertificateChain: func(prov provisioner.Interface, certs ...*x509.Certificate) error {
					p, ok := prov.(attProvisioner)
					if assert.True(t, ok) {
						assert.Equals(t, &provisioner.AttestationData{
							PermanentIdentifier: "1234567890",
						}, p.AttestationData())
					}
					if assert.Len(t, 2, certs) {
						assert.Equals(t, certs[0].Subject.CommonName, "smallstep test")
						assert.Equals(t, certs[1].Subject.CommonName, "smallstep Intermediate CA")
					}
					return nil
				},
			}

			return &signTest{
				auth: aa,
				csr:  csr,
				extraOpts: append(extraOpts, provisioner.AttestationData{
					PermanentIdentifier: "1234567890",
				}),
				signOpts:        signOpts,
				notBefore:       signOpts.NotBefore.Time().Truncate(time.Second),
				notAfter:        signOpts.NotAfter.Time().Truncate(time.Second),
				extensionsCount: 6,
			}
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)

			certChain, err := tc.auth.Sign(tc.csr, tc.signOpts, tc.extraOpts...)
			if err != nil {
				if assert.NotNil(t, tc.err, fmt.Sprintf("unexpected error: %s", err)) {
					assert.Nil(t, certChain)
					var sc render.StatusCodedError
					assert.Fatal(t, errors.As(err, &sc), "error does not implement StatusCodedError interface")
					assert.Equals(t, sc.StatusCode(), tc.code)
					assert.HasPrefix(t, err.Error(), tc.err.Error())

					var ctxErr *errs.Error
					assert.Fatal(t, errors.As(err, &ctxErr), "error is not of type *errs.Error")
					assert.Equals(t, ctxErr.Details["csr"], tc.csr)
					assert.Equals(t, ctxErr.Details["signOptions"], tc.signOpts)
				}
			} else {
				leaf := certChain[0]
				intermediate := certChain[1]
				if assert.Nil(t, tc.err) {
					assert.Equals(t, leaf.NotBefore, tc.notBefore)
					assert.Equals(t, leaf.NotAfter, tc.notAfter)
					tmplt := a.config.AuthorityConfig.Template
					if tc.csr.Subject.CommonName == "" {
						assert.Equals(t, leaf.Subject, pkix.Name{})
					} else {
						assert.Equals(t, leaf.Subject.String(),
							pkix.Name{
								Country:       []string{tmplt.Country},
								Organization:  []string{tmplt.Organization},
								Locality:      []string{tmplt.Locality},
								StreetAddress: []string{tmplt.StreetAddress},
								Province:      []string{tmplt.Province},
								CommonName:    "smallstep test",
							}.String())
						assert.Equals(t, leaf.DNSNames, []string{"test.smallstep.com"})
					}
					assert.Equals(t, leaf.Issuer, intermediate.Subject)
					assert.Equals(t, leaf.SignatureAlgorithm, x509.ECDSAWithSHA256)
					assert.Equals(t, leaf.PublicKeyAlgorithm, x509.ECDSA)
					assert.Equals(t, leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})

					issuer := getDefaultIssuer(a)
					subjectKeyID, err := generateSubjectKeyID(pub)
					assert.FatalError(t, err)
					assert.Equals(t, leaf.SubjectKeyId, subjectKeyID)
					assert.Equals(t, leaf.AuthorityKeyId, issuer.SubjectKeyId)

					// Verify Provisioner OID
					found := 0
					for _, ext := range leaf.Extensions {
						switch {
						case ext.Id.Equal(stepOIDProvisioner):
							found++
							val := stepProvisionerASN1{}
							_, err := asn1.Unmarshal(ext.Value, &val)
							assert.FatalError(t, err)
							assert.Equals(t, val.Type, provisionerTypeJWK)
							assert.Equals(t, val.Name, []byte(p.Name))
							assert.Equals(t, val.CredentialID, []byte(p.Key.KeyID))

						// Basic Constraints
						case ext.Id.Equal(asn1.ObjectIdentifier([]int{2, 5, 29, 19})):
							val := basicConstraints{}
							_, err := asn1.Unmarshal(ext.Value, &val)
							assert.FatalError(t, err)
							assert.False(t, val.IsCA, false)
							assert.Equals(t, val.MaxPathLen, 0)

						// SAN extension
						case ext.Id.Equal(asn1.ObjectIdentifier([]int{2, 5, 29, 17})):
							if tc.csr.Subject.CommonName == "" {
								// Empty CSR subject test does not use any provisioner extensions.
								// So provisioner ID ext will be missing.
								found = 1
							}
						}
					}
					assert.Equals(t, found, 1)
					realIntermediate, err := x509.ParseCertificate(issuer.Raw)
					assert.FatalError(t, err)
					assert.Equals(t, intermediate, realIntermediate)
					assert.Len(t, tc.extensionsCount, leaf.Extensions)
				}
			}
		})
	}
}

func TestAuthority_Renew(t *testing.T) {
	a := testAuthority(t)
	a.config.AuthorityConfig.Template = &ASN1DN{
		Country:       "Tazmania",
		Organization:  "Acme Co",
		Locality:      "Landscapes",
		Province:      "Sudden Cliffs",
		StreetAddress: "TNT",
		CommonName:    "renew",
	}

	now := time.Now().UTC()
	nb1 := now.Add(-time.Minute * 7)
	na1 := now.Add(time.Hour)
	so := &provisioner.SignOptions{
		NotBefore: provisioner.NewTimeDuration(nb1),
		NotAfter:  provisioner.NewTimeDuration(na1),
	}

	issuer := getDefaultIssuer(a)
	signer := getDefaultSigner(a)

	cert := generateCertificate(t, "renew", []string{"test.smallstep.com", "test"},
		withNotBeforeNotAfter(so.NotBefore.Time(), so.NotAfter.Time()),
		withDefaultASN1DN(a.config.AuthorityConfig.Template),
		withProvisionerOID("Max", a.config.AuthorityConfig.Provisioners[0].(*provisioner.JWK).Key.KeyID),
		withSigner(issuer, signer))

	certExtraNames := generateCertificate(t, "renew", []string{"test.smallstep.com", "test"},
		withSubject(pkix.Name{
			CommonName: "renew",
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}, Value: "dc"},
			},
		}),
		withNotBeforeNotAfter(so.NotBefore.Time(), so.NotAfter.Time()),
		withDefaultASN1DN(a.config.AuthorityConfig.Template),
		withProvisionerOID("Max", a.config.AuthorityConfig.Provisioners[0].(*provisioner.JWK).Key.KeyID),
		withSigner(issuer, signer))

	certNoRenew := generateCertificate(t, "renew", []string{"test.smallstep.com", "test"},
		withNotBeforeNotAfter(so.NotBefore.Time(), so.NotAfter.Time()),
		withDefaultASN1DN(a.config.AuthorityConfig.Template),
		withProvisionerOID("dev", a.config.AuthorityConfig.Provisioners[2].(*provisioner.JWK).Key.KeyID),
		withSigner(issuer, signer))

	type renewTest struct {
		auth *Authority
		cert *x509.Certificate
		err  error
		code int
	}
	tests := map[string]func() (*renewTest, error){
		"fail/create-cert": func() (*renewTest, error) {
			_a := testAuthority(t)
			_a.x509CAService.(*softcas.SoftCAS).Signer = nil
			return &renewTest{
				auth: _a,
				cert: cert,
				err:  errors.New("error creating certificate"),
				code: http.StatusInternalServerError,
			}, nil
		},
		"fail/unauthorized": func() (*renewTest, error) {
			return &renewTest{
				cert: certNoRenew,
				err:  errors.New("authority.authorizeRenew: renew is disabled for provisioner 'dev'"),
				code: http.StatusUnauthorized,
			}, nil
		},
		"fail/WithAuthorizeRenewFunc": func() (*renewTest, error) {
			aa := testAuthority(t, WithAuthorizeRenewFunc(func(ctx context.Context, p *provisioner.Controller, cert *x509.Certificate) error {
				return errs.Unauthorized("not authorized")
			}))
			aa.x509CAService = a.x509CAService
			aa.config.AuthorityConfig.Template = a.config.AuthorityConfig.Template
			return &renewTest{
				auth: aa,
				cert: cert,
				err:  errors.New("authority.authorizeRenew: not authorized"),
				code: http.StatusUnauthorized,
			}, nil
		},
		"ok": func() (*renewTest, error) {
			return &renewTest{
				auth: a,
				cert: cert,
			}, nil
		},
		"ok/WithExtraNames": func() (*renewTest, error) {
			return &renewTest{
				auth: a,
				cert: certExtraNames,
			}, nil
		},
		"ok/success-new-intermediate": func() (*renewTest, error) {
			rootCert, rootSigner := generateRootCertificate(t)
			intCert, intSigner := generateIntermidiateCertificate(t, rootCert, rootSigner)

			_a := testAuthority(t)
			_a.x509CAService.(*softcas.SoftCAS).CertificateChain = []*x509.Certificate{intCert}
			_a.x509CAService.(*softcas.SoftCAS).Signer = intSigner
			return &renewTest{
				auth: _a,
				cert: cert,
			}, nil
		},
		"ok/WithAuthorizeRenewFunc": func() (*renewTest, error) {
			aa := testAuthority(t, WithAuthorizeRenewFunc(func(ctx context.Context, p *provisioner.Controller, cert *x509.Certificate) error {
				return nil
			}))
			aa.x509CAService = a.x509CAService
			aa.config.AuthorityConfig.Template = a.config.AuthorityConfig.Template
			return &renewTest{
				auth: aa,
				cert: cert,
			}, nil
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc, err := genTestCase()
			assert.FatalError(t, err)

			var certChain []*x509.Certificate
			if tc.auth != nil {
				certChain, err = tc.auth.Renew(tc.cert)
			} else {
				certChain, err = a.Renew(tc.cert)
			}
			if err != nil {
				if assert.NotNil(t, tc.err, fmt.Sprintf("unexpected error: %s", err)) {
					assert.Nil(t, certChain)
					var sc render.StatusCodedError
					assert.Fatal(t, errors.As(err, &sc), "error does not implement StatusCodedError interface")
					assert.Equals(t, sc.StatusCode(), tc.code)
					assert.HasPrefix(t, err.Error(), tc.err.Error())

					var ctxErr *errs.Error
					assert.Fatal(t, errors.As(err, &ctxErr), "error is not of type *errs.Error")
					assert.Equals(t, ctxErr.Details["serialNumber"], tc.cert.SerialNumber.String())
				}
			} else {
				leaf := certChain[0]
				intermediate := certChain[1]
				if assert.Nil(t, tc.err) {
					assert.Equals(t, leaf.NotAfter.Sub(leaf.NotBefore), tc.cert.NotAfter.Sub(cert.NotBefore))

					assert.True(t, leaf.NotBefore.After(now.Add(-2*time.Minute)))
					assert.True(t, leaf.NotBefore.Before(now.Add(time.Minute)))

					expiry := now.Add(time.Minute * 7)
					assert.True(t, leaf.NotAfter.After(expiry.Add(-2*time.Minute)))
					assert.True(t, leaf.NotAfter.Before(expiry.Add(time.Hour)))

					tmplt := a.config.AuthorityConfig.Template
					assert.Equals(t, leaf.RawSubject, tc.cert.RawSubject)
					assert.Equals(t, leaf.Subject.Country, []string{tmplt.Country})
					assert.Equals(t, leaf.Subject.Organization, []string{tmplt.Organization})
					assert.Equals(t, leaf.Subject.Locality, []string{tmplt.Locality})
					assert.Equals(t, leaf.Subject.StreetAddress, []string{tmplt.StreetAddress})
					assert.Equals(t, leaf.Subject.Province, []string{tmplt.Province})
					assert.Equals(t, leaf.Subject.CommonName, tmplt.CommonName)

					assert.Equals(t, leaf.Issuer, intermediate.Subject)

					assert.Equals(t, leaf.SignatureAlgorithm, x509.ECDSAWithSHA256)
					assert.Equals(t, leaf.PublicKeyAlgorithm, x509.ECDSA)
					assert.Equals(t, leaf.ExtKeyUsage,
						[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
					assert.Equals(t, leaf.DNSNames, []string{"test.smallstep.com", "test"})

					subjectKeyID, err := generateSubjectKeyID(leaf.PublicKey)
					assert.FatalError(t, err)
					assert.Equals(t, leaf.SubjectKeyId, subjectKeyID)

					// We did not change the intermediate before renewing.
					authIssuer := getDefaultIssuer(tc.auth)
					if issuer.SerialNumber == authIssuer.SerialNumber {
						assert.Equals(t, leaf.AuthorityKeyId, issuer.SubjectKeyId)
						// Compare extensions: they can be in a different order
						for _, ext1 := range tc.cert.Extensions {
							//skip SubjectKeyIdentifier
							if ext1.Id.Equal(oidSubjectKeyIdentifier) {
								continue
							}
							found := false
							for _, ext2 := range leaf.Extensions {
								if reflect.DeepEqual(ext1, ext2) {
									found = true
									break
								}
							}
							if !found {
								t.Errorf("x509 extension %s not found in renewed certificate", ext1.Id.String())
							}
						}
					} else {
						// We did change the intermediate before renewing.
						assert.Equals(t, leaf.AuthorityKeyId, authIssuer.SubjectKeyId)
						// Compare extensions: they can be in a different order
						for _, ext1 := range tc.cert.Extensions {
							//skip SubjectKeyIdentifier
							if ext1.Id.Equal(oidSubjectKeyIdentifier) {
								continue
							}
							// The authority key id extension should be different b/c the intermediates are different.
							if ext1.Id.Equal(oidAuthorityKeyIdentifier) {
								for _, ext2 := range leaf.Extensions {
									assert.False(t, reflect.DeepEqual(ext1, ext2))
								}
								continue
							} else {
								found := false
								for _, ext2 := range leaf.Extensions {
									if reflect.DeepEqual(ext1, ext2) {
										found = true
										break
									}
								}
								if !found {
									t.Errorf("x509 extension %s not found in renewed certificate", ext1.Id.String())
								}
							}
						}
					}

					realIntermediate, err := x509.ParseCertificate(authIssuer.Raw)
					assert.FatalError(t, err)
					assert.Equals(t, intermediate, realIntermediate)
				}
			}
		})
	}
}

func TestAuthority_Rekey(t *testing.T) {
	pub, _, err := keyutil.GenerateDefaultKeyPair()
	assert.FatalError(t, err)

	a := testAuthority(t)
	a.config.AuthorityConfig.Template = &ASN1DN{
		Country:       "Tazmania",
		Organization:  "Acme Co",
		Locality:      "Landscapes",
		Province:      "Sudden Cliffs",
		StreetAddress: "TNT",
		CommonName:    "renew",
	}

	now := time.Now().UTC()
	nb1 := now.Add(-time.Minute * 7)
	na1 := now.Add(time.Hour)
	so := &provisioner.SignOptions{
		NotBefore: provisioner.NewTimeDuration(nb1),
		NotAfter:  provisioner.NewTimeDuration(na1),
	}

	issuer := getDefaultIssuer(a)
	signer := getDefaultSigner(a)

	cert := generateCertificate(t, "renew", []string{"test.smallstep.com", "test"},
		withNotBeforeNotAfter(so.NotBefore.Time(), so.NotAfter.Time()),
		withDefaultASN1DN(a.config.AuthorityConfig.Template),
		withProvisionerOID("Max", a.config.AuthorityConfig.Provisioners[0].(*provisioner.JWK).Key.KeyID),
		withSigner(issuer, signer))

	certNoRenew := generateCertificate(t, "renew", []string{"test.smallstep.com", "test"},
		withNotBeforeNotAfter(so.NotBefore.Time(), so.NotAfter.Time()),
		withDefaultASN1DN(a.config.AuthorityConfig.Template),
		withProvisionerOID("dev", a.config.AuthorityConfig.Provisioners[2].(*provisioner.JWK).Key.KeyID),
		withSigner(issuer, signer))

	type renewTest struct {
		auth *Authority
		cert *x509.Certificate
		pk   crypto.PublicKey
		err  error
		code int
	}
	tests := map[string]func() (*renewTest, error){
		"fail/create-cert": func() (*renewTest, error) {
			_a := testAuthority(t)
			_a.x509CAService.(*softcas.SoftCAS).Signer = nil
			return &renewTest{
				auth: _a,
				cert: cert,
				err:  errors.New("error creating certificate"),
				code: http.StatusInternalServerError,
			}, nil
		},
		"fail/unauthorized": func() (*renewTest, error) {
			return &renewTest{
				cert: certNoRenew,
				err:  errors.New("authority.authorizeRenew: renew is disabled for provisioner 'dev'"),
				code: http.StatusUnauthorized,
			}, nil
		},
		"ok/renew": func() (*renewTest, error) {
			return &renewTest{
				auth: a,
				cert: cert,
			}, nil
		},
		"ok/rekey": func() (*renewTest, error) {
			return &renewTest{
				auth: a,
				cert: cert,
				pk:   pub,
			}, nil
		},
		"ok/renew/success-new-intermediate": func() (*renewTest, error) {
			rootCert, rootSigner := generateRootCertificate(t)
			intCert, intSigner := generateIntermidiateCertificate(t, rootCert, rootSigner)

			_a := testAuthority(t)
			_a.x509CAService.(*softcas.SoftCAS).CertificateChain = []*x509.Certificate{intCert}
			_a.x509CAService.(*softcas.SoftCAS).Signer = intSigner
			return &renewTest{
				auth: _a,
				cert: cert,
			}, nil
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc, err := genTestCase()
			assert.FatalError(t, err)

			var certChain []*x509.Certificate
			if tc.auth != nil {
				certChain, err = tc.auth.Rekey(tc.cert, tc.pk)
			} else {
				certChain, err = a.Rekey(tc.cert, tc.pk)
			}
			if err != nil {
				if assert.NotNil(t, tc.err, fmt.Sprintf("unexpected error: %s", err)) {
					assert.Nil(t, certChain)
					var sc render.StatusCodedError
					assert.Fatal(t, errors.As(err, &sc), "error does not implement StatusCodedError interface")
					assert.Equals(t, sc.StatusCode(), tc.code)
					assert.HasPrefix(t, err.Error(), tc.err.Error())

					var ctxErr *errs.Error
					assert.Fatal(t, errors.As(err, &ctxErr), "error is not of type *errs.Error")
					assert.Equals(t, ctxErr.Details["serialNumber"], tc.cert.SerialNumber.String())
				}
			} else {
				leaf := certChain[0]
				intermediate := certChain[1]
				if assert.Nil(t, tc.err) {
					assert.Equals(t, leaf.NotAfter.Sub(leaf.NotBefore), tc.cert.NotAfter.Sub(cert.NotBefore))

					assert.True(t, leaf.NotBefore.After(now.Add(-2*time.Minute)))
					assert.True(t, leaf.NotBefore.Before(now.Add(time.Minute)))

					expiry := now.Add(time.Minute * 7)
					assert.True(t, leaf.NotAfter.After(expiry.Add(-2*time.Minute)))
					assert.True(t, leaf.NotAfter.Before(expiry.Add(time.Hour)))

					tmplt := a.config.AuthorityConfig.Template
					assert.Equals(t, leaf.Subject.String(),
						pkix.Name{
							Country:       []string{tmplt.Country},
							Organization:  []string{tmplt.Organization},
							Locality:      []string{tmplt.Locality},
							StreetAddress: []string{tmplt.StreetAddress},
							Province:      []string{tmplt.Province},
							CommonName:    tmplt.CommonName,
						}.String())
					assert.Equals(t, leaf.Issuer, intermediate.Subject)

					assert.Equals(t, leaf.SignatureAlgorithm, x509.ECDSAWithSHA256)
					assert.Equals(t, leaf.PublicKeyAlgorithm, x509.ECDSA)
					assert.Equals(t, leaf.ExtKeyUsage,
						[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
					assert.Equals(t, leaf.DNSNames, []string{"test.smallstep.com", "test"})

					// Test Public Key and SubjectKeyId
					expectedPK := tc.pk
					if tc.pk == nil {
						expectedPK = cert.PublicKey
					}
					assert.Equals(t, leaf.PublicKey, expectedPK)

					subjectKeyID, err := generateSubjectKeyID(expectedPK)
					assert.FatalError(t, err)
					assert.Equals(t, leaf.SubjectKeyId, subjectKeyID)
					if tc.pk == nil {
						assert.Equals(t, leaf.SubjectKeyId, cert.SubjectKeyId)
					}

					// We did not change the intermediate before renewing.
					authIssuer := getDefaultIssuer(tc.auth)
					if issuer.SerialNumber == authIssuer.SerialNumber {
						assert.Equals(t, leaf.AuthorityKeyId, issuer.SubjectKeyId)
						// Compare extensions: they can be in a different order
						for _, ext1 := range tc.cert.Extensions {
							//skip SubjectKeyIdentifier
							if ext1.Id.Equal(oidSubjectKeyIdentifier) {
								continue
							}
							found := false
							for _, ext2 := range leaf.Extensions {
								if reflect.DeepEqual(ext1, ext2) {
									found = true
									break
								}
							}
							if !found {
								t.Errorf("x509 extension %s not found in renewed certificate", ext1.Id.String())
							}
						}
					} else {
						// We did change the intermediate before renewing.
						assert.Equals(t, leaf.AuthorityKeyId, authIssuer.SubjectKeyId)
						// Compare extensions: they can be in a different order
						for _, ext1 := range tc.cert.Extensions {
							//skip SubjectKeyIdentifier
							if ext1.Id.Equal(oidSubjectKeyIdentifier) {
								continue
							}
							// The authority key id extension should be different b/c the intermediates are different.
							if ext1.Id.Equal(oidAuthorityKeyIdentifier) {
								for _, ext2 := range leaf.Extensions {
									assert.False(t, reflect.DeepEqual(ext1, ext2))
								}
								continue
							} else {
								found := false
								for _, ext2 := range leaf.Extensions {
									if reflect.DeepEqual(ext1, ext2) {
										found = true
										break
									}
								}
								if !found {
									t.Errorf("x509 extension %s not found in renewed certificate", ext1.Id.String())
								}
							}
						}
					}

					realIntermediate, err := x509.ParseCertificate(authIssuer.Raw)
					assert.FatalError(t, err)
					assert.Equals(t, intermediate, realIntermediate)
				}
			}
		})
	}
}

func TestAuthority_GetTLSOptions(t *testing.T) {
	type renewTest struct {
		auth *Authority
		opts *TLSOptions
	}
	tests := map[string]func() (*renewTest, error){
		"default": func() (*renewTest, error) {
			a := testAuthority(t)
			return &renewTest{auth: a, opts: &DefaultTLSOptions}, nil
		},
		"non-default": func() (*renewTest, error) {
			a := testAuthority(t)
			a.config.TLS = &TLSOptions{
				CipherSuites: CipherSuites{
					"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
					"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
				},
				MinVersion:    1.0,
				MaxVersion:    1.1,
				Renegotiation: true,
			}
			return &renewTest{auth: a, opts: a.config.TLS}, nil
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc, err := genTestCase()
			assert.FatalError(t, err)

			opts := tc.auth.GetTLSOptions()
			assert.Equals(t, opts, tc.opts)
		})
	}
}

func TestAuthority_Revoke(t *testing.T) {
	reasonCode := 2
	reason := "bob was let go"
	validIssuer := "step-cli"
	validAudience := testAudiences.Revoke
	now := time.Now().UTC()

	jwk, err := jose.ReadKey("testdata/secrets/step_cli_key_priv.jwk", jose.WithPassword([]byte("pass")))
	assert.FatalError(t, err)

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jwk.Key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", jwk.KeyID))
	assert.FatalError(t, err)

	a := testAuthority(t)

	tlsRevokeCtx := provisioner.NewContextWithMethod(context.Background(), provisioner.RevokeMethod)

	type test struct {
		auth            *Authority
		ctx             context.Context
		opts            *RevokeOptions
		err             error
		code            int
		checkErrDetails func(err *errs.Error)
	}
	tests := map[string]func() test{
		"fail/token/authorizeRevoke error": func() test {
			return test{
				auth: a,
				ctx:  tlsRevokeCtx,
				opts: &RevokeOptions{
					OTT:        "foo",
					Serial:     "sn",
					ReasonCode: reasonCode,
					Reason:     reason,
				},
				err:  errors.New("authority.Revoke; error parsing token"),
				code: http.StatusUnauthorized,
			}
		},
		"fail/nil-db": func() test {
			cl := jose.Claims{
				Subject:   "sn",
				Issuer:    validIssuer,
				NotBefore: jose.NewNumericDate(now),
				Expiry:    jose.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "44",
			}
			raw, err := jose.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)

			return test{
				auth: a,
				ctx:  tlsRevokeCtx,
				opts: &RevokeOptions{
					Serial:     "sn",
					ReasonCode: reasonCode,
					Reason:     reason,
					OTT:        raw,
				},
				err:  errors.New("authority.Revoke; no persistence layer configured"),
				code: http.StatusNotImplemented,
				checkErrDetails: func(err *errs.Error) {
					assert.Equals(t, err.Details["token"], raw)
					assert.Equals(t, err.Details["tokenID"], "44")
					assert.Equals(t, err.Details["provisionerID"], "step-cli:4UELJx8e0aS9m0CH3fZ0EB7D5aUPICb759zALHFejvc")
				},
			}
		},
		"fail/db-revoke": func() test {
			_a := testAuthority(t, WithDatabase(&db.MockAuthDB{
				MUseToken: func(id, tok string) (bool, error) {
					return true, nil
				},
				MGetCertificate: func(sn string) (*x509.Certificate, error) {
					return nil, errors.New("not found")
				},
				Err: errors.New("force"),
			}))

			cl := jose.Claims{
				Subject:   "sn",
				Issuer:    validIssuer,
				NotBefore: jose.NewNumericDate(now),
				Expiry:    jose.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "44",
			}
			raw, err := jose.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)

			return test{
				auth: _a,
				ctx:  tlsRevokeCtx,
				opts: &RevokeOptions{
					Serial:     "sn",
					ReasonCode: reasonCode,
					Reason:     reason,
					OTT:        raw,
				},
				err:  errors.New("authority.Revoke: force"),
				code: http.StatusInternalServerError,
				checkErrDetails: func(err *errs.Error) {
					assert.Equals(t, err.Details["token"], raw)
					assert.Equals(t, err.Details["tokenID"], "44")
					assert.Equals(t, err.Details["provisionerID"], "step-cli:4UELJx8e0aS9m0CH3fZ0EB7D5aUPICb759zALHFejvc")
				},
			}
		},
		"fail/already-revoked": func() test {
			_a := testAuthority(t, WithDatabase(&db.MockAuthDB{
				MUseToken: func(id, tok string) (bool, error) {
					return true, nil
				},
				MGetCertificate: func(sn string) (*x509.Certificate, error) {
					return nil, errors.New("not found")
				},
				Err: db.ErrAlreadyExists,
			}))

			cl := jose.Claims{
				Subject:   "sn",
				Issuer:    validIssuer,
				NotBefore: jose.NewNumericDate(now),
				Expiry:    jose.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "44",
			}
			raw, err := jose.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)

			return test{
				auth: _a,
				ctx:  tlsRevokeCtx,
				opts: &RevokeOptions{
					Serial:     "sn",
					ReasonCode: reasonCode,
					Reason:     reason,
					OTT:        raw,
				},
				err:  errors.New("certificate with serial number 'sn' is already revoked"),
				code: http.StatusBadRequest,
				checkErrDetails: func(err *errs.Error) {
					assert.Equals(t, err.Details["token"], raw)
					assert.Equals(t, err.Details["tokenID"], "44")
					assert.Equals(t, err.Details["provisionerID"], "step-cli:4UELJx8e0aS9m0CH3fZ0EB7D5aUPICb759zALHFejvc")
				},
			}
		},
		"ok/token": func() test {
			_a := testAuthority(t, WithDatabase(&db.MockAuthDB{
				MUseToken: func(id, tok string) (bool, error) {
					return true, nil
				},
				MGetCertificate: func(sn string) (*x509.Certificate, error) {
					return nil, errors.New("not found")
				},
			}))

			cl := jose.Claims{
				Subject:   "sn",
				Issuer:    validIssuer,
				NotBefore: jose.NewNumericDate(now),
				Expiry:    jose.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "44",
			}
			raw, err := jose.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return test{
				auth: _a,
				ctx:  tlsRevokeCtx,
				opts: &RevokeOptions{
					Serial:     "sn",
					ReasonCode: reasonCode,
					Reason:     reason,
					OTT:        raw,
				},
			}
		},
		"ok/mTLS": func() test {
			_a := testAuthority(t, WithDatabase(&db.MockAuthDB{}))

			crt, err := pemutil.ReadCertificate("./testdata/certs/foo.crt")
			assert.FatalError(t, err)

			return test{
				auth: _a,
				ctx:  tlsRevokeCtx,
				opts: &RevokeOptions{
					Crt:        crt,
					Serial:     "102012593071130646873265215610956555026",
					ReasonCode: reasonCode,
					Reason:     reason,
					MTLS:       true,
				},
			}
		},
		"ok/mTLS-no-provisioner": func() test {
			_a := testAuthority(t, WithDatabase(&db.MockAuthDB{}))

			crt, err := pemutil.ReadCertificate("./testdata/certs/foo.crt")
			assert.FatalError(t, err)
			// Filter out provisioner extension.
			for i, ext := range crt.Extensions {
				if ext.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64, 1}) {
					crt.Extensions = append(crt.Extensions[:i], crt.Extensions[i+1:]...)
					break
				}
			}

			return test{
				auth: _a,
				ctx:  tlsRevokeCtx,
				opts: &RevokeOptions{
					Crt:        crt,
					Serial:     "102012593071130646873265215610956555026",
					ReasonCode: reasonCode,
					Reason:     reason,
					MTLS:       true,
				},
			}
		},
		"ok/ACME": func() test {
			_a := testAuthority(t, WithDatabase(&db.MockAuthDB{}))

			crt, err := pemutil.ReadCertificate("./testdata/certs/foo.crt")
			assert.FatalError(t, err)

			return test{
				auth: _a,
				ctx:  tlsRevokeCtx,
				opts: &RevokeOptions{
					Crt:        crt,
					Serial:     "102012593071130646873265215610956555026",
					ReasonCode: reasonCode,
					Reason:     reason,
					ACME:       true,
				},
			}
		},
		"ok/ssh": func() test {
			a := testAuthority(t, WithDatabase(&db.MockAuthDB{
				MRevoke: func(rci *db.RevokedCertificateInfo) error {
					return errors.New("Revoke was called")
				},
				MRevokeSSH: func(rci *db.RevokedCertificateInfo) error {
					return nil
				},
			}))

			cl := jose.Claims{
				Subject:   "sn",
				Issuer:    validIssuer,
				NotBefore: jose.NewNumericDate(now),
				Expiry:    jose.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "44",
			}
			raw, err := jose.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return test{
				auth: a,
				ctx:  provisioner.NewContextWithMethod(context.Background(), provisioner.SSHRevokeMethod),
				opts: &RevokeOptions{
					Serial:     "sn",
					ReasonCode: reasonCode,
					Reason:     reason,
					OTT:        raw,
				},
			}
		},
	}
	for name, f := range tests {
		tc := f()
		t.Run(name, func(t *testing.T) {
			if err := tc.auth.Revoke(tc.ctx, tc.opts); err != nil {
				if assert.NotNil(t, tc.err, fmt.Sprintf("unexpected error: %s", err)) {
					var sc render.StatusCodedError
					assert.Fatal(t, errors.As(err, &sc), "error does not implement StatusCodedError interface")
					assert.Equals(t, sc.StatusCode(), tc.code)
					assert.HasPrefix(t, err.Error(), tc.err.Error())

					var ctxErr *errs.Error
					assert.Fatal(t, errors.As(err, &ctxErr), "error is not of type *errs.Error")
					assert.Equals(t, ctxErr.Details["serialNumber"], tc.opts.Serial)
					assert.Equals(t, ctxErr.Details["reasonCode"], tc.opts.ReasonCode)
					assert.Equals(t, ctxErr.Details["reason"], tc.opts.Reason)
					assert.Equals(t, ctxErr.Details["MTLS"], tc.opts.MTLS)
					assert.Equals(t, ctxErr.Details["context"], provisioner.RevokeMethod.String())

					if tc.checkErrDetails != nil {
						tc.checkErrDetails(ctxErr)
					}
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

func TestAuthority_constraints(t *testing.T) {
	ca, err := minica.New(
		minica.WithIntermediateTemplate(`{
				"subject": {{ toJson .Subject }},
				"keyUsage": ["certSign", "crlSign"],
				"basicConstraints": {
					"isCA": true,
					"maxPathLen": 0
				},
				"nameConstraints": {
					"critical": true,
					"permittedDNSDomains": ["internal.example.org"],
					"excludedDNSDomains": ["internal.example.com"],
					"permittedIPRanges": ["192.168.1.0/24", "192.168.2.1/32"],
					"excludedIPRanges": ["192.168.3.0/24", "192.168.4.0/28"],
					"permittedEmailAddresses": ["root@example.org", "example.org", ".acme.org"],
					"excludedEmailAddresses": ["root@example.com", "example.com", ".acme.com"],
					"permittedURIDomains": ["uuid.example.org", ".acme.org"],
					"excludedURIDomains": ["uuid.example.com", ".acme.com"]
				}
			}`),
	)
	if err != nil {
		t.Fatal(err)
	}

	auth, err := NewEmbedded(WithX509RootCerts(ca.Root), WithX509Signer(ca.Intermediate, ca.Signer))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := keyutil.GenerateDefaultSigner()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		sans    []string
		wantErr bool
	}{
		{"ok dns", []string{"internal.example.org", "host.internal.example.org"}, false},
		{"ok ip", []string{"192.168.1.10", "192.168.2.1"}, false},
		{"ok email", []string{"root@example.org", "info@example.org", "info@www.acme.org"}, false},
		{"ok uri", []string{"https://uuid.example.org/b908d973-5167-4a62-abe3-6beda358d82a", "https://uuid.acme.org/1724aae1-1bb3-44fb-83c3-9a1a18df67c8"}, false},
		{"fail permitted dns", []string{"internal.acme.org"}, true},
		{"fail excluded dns", []string{"internal.example.com"}, true},
		{"fail permitted ips", []string{"192.168.2.10"}, true},
		{"fail excluded ips", []string{"192.168.3.1"}, true},
		{"fail permitted emails", []string{"root@acme.org"}, true},
		{"fail excluded emails", []string{"root@example.com"}, true},
		{"fail permitted uris", []string{"https://acme.org/uuid/7848819c-9d0b-4e12-bbff-cd66079a3444"}, true},
		{"fail excluded uris", []string{"https://uuid.example.com/d325eda7-6356-4d60-b8f6-3d64724afeb3"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			csr, err := x509util.CreateCertificateRequest(tt.sans[0], tt.sans, signer)
			if err != nil {
				t.Fatal(err)
			}
			cert, err := ca.SignCSR(csr)
			if err != nil {
				t.Fatal(err)
			}

			data := x509util.CreateTemplateData(tt.sans[0], tt.sans)
			templateOption, err := provisioner.TemplateOptions(nil, data)
			if err != nil {
				t.Fatal(err)
			}

			_, err = auth.Sign(csr, provisioner.SignOptions{}, templateOption)
			if (err != nil) != tt.wantErr {
				t.Errorf("Authority.Sign() error = %v, wantErr %v", err, tt.wantErr)
			}

			_, err = auth.Renew(cert)
			if (err != nil) != tt.wantErr {
				t.Errorf("Authority.Renew() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAuthority_CRL(t *testing.T) {
	reasonCode := 2
	reason := "bob was let go"
	validIssuer := "step-cli"
	validAudience := testAudiences.Revoke
	now := time.Now().UTC()
	//
	jwk, err := jose.ReadKey("testdata/secrets/step_cli_key_priv.jwk", jose.WithPassword([]byte("pass")))
	assert.FatalError(t, err)
	//
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jwk.Key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", jwk.KeyID))
	assert.FatalError(t, err)

	crlCtx := provisioner.NewContextWithMethod(context.Background(), provisioner.RevokeMethod)

	var crlStore db.CertificateRevocationListInfo
	var revokedList []db.RevokedCertificateInfo

	type test struct {
		auth     *Authority
		ctx      context.Context
		expected []string
		err      error
	}
	tests := map[string]func() test{
		"fail/empty-crl": func() test {
			a := testAuthority(t, WithDatabase(&db.MockAuthDB{
				MUseToken: func(id, tok string) (bool, error) {
					return true, nil
				},
				MGetCertificate: func(sn string) (*x509.Certificate, error) {
					return nil, errors.New("not found")
				},
				MStoreCRL: func(i *db.CertificateRevocationListInfo) error {
					crlStore = *i
					return nil
				},
				MGetCRL: func() (*db.CertificateRevocationListInfo, error) {
					return nil, database.ErrNotFound
				},
				MGetRevokedCertificates: func() (*[]db.RevokedCertificateInfo, error) {
					return &revokedList, nil
				},
				MRevoke: func(rci *db.RevokedCertificateInfo) error {
					revokedList = append(revokedList, *rci)
					return nil
				},
			}))
			a.config.CRL = &config.CRLConfig{
				Enabled: true,
			}

			return test{
				auth:     a,
				ctx:      crlCtx,
				expected: nil,
				err:      database.ErrNotFound,
			}
		},
		"ok/crl-full": func() test {
			a := testAuthority(t, WithDatabase(&db.MockAuthDB{
				MUseToken: func(id, tok string) (bool, error) {
					return true, nil
				},
				MGetCertificate: func(sn string) (*x509.Certificate, error) {
					return nil, errors.New("not found")
				},
				MStoreCRL: func(i *db.CertificateRevocationListInfo) error {
					crlStore = *i
					return nil
				},
				MGetCRL: func() (*db.CertificateRevocationListInfo, error) {
					return &crlStore, nil
				},
				MGetRevokedCertificates: func() (*[]db.RevokedCertificateInfo, error) {
					return &revokedList, nil
				},
				MRevoke: func(rci *db.RevokedCertificateInfo) error {
					revokedList = append(revokedList, *rci)
					return nil
				},
			}))
			a.config.CRL = &config.CRLConfig{
				Enabled:          true,
				GenerateOnRevoke: true,
			}

			var ex []string

			for i := 0; i < 100; i++ {
				sn := fmt.Sprintf("%v", i)

				cl := jose.Claims{
					Subject:   fmt.Sprintf("sn-%v", i),
					Issuer:    validIssuer,
					NotBefore: jose.NewNumericDate(now),
					Expiry:    jose.NewNumericDate(now.Add(time.Minute)),
					Audience:  validAudience,
					ID:        sn,
				}
				raw, err := jose.Signed(sig).Claims(cl).CompactSerialize()
				assert.FatalError(t, err)
				err = a.Revoke(crlCtx, &RevokeOptions{
					Serial:     sn,
					ReasonCode: reasonCode,
					Reason:     reason,
					OTT:        raw,
				})

				assert.FatalError(t, err)

				ex = append(ex, sn)
			}

			return test{
				auth:     a,
				ctx:      crlCtx,
				expected: ex,
			}
		},
	}
	for name, f := range tests {
		tc := f()
		t.Run(name, func(t *testing.T) {
			if crlBytes, err := tc.auth.GetCertificateRevocationList(); err == nil {
				crl, parseErr := x509.ParseCRL(crlBytes)
				if parseErr != nil {
					t.Errorf("x509.ParseCertificateRequest() error = %v, wantErr %v", parseErr, nil)
					return
				}

				var cmpList []string
				for _, c := range crl.TBSCertList.RevokedCertificates {
					cmpList = append(cmpList, c.SerialNumber.String())
				}

				assert.Equals(t, cmpList, tc.expected)
			} else {
				assert.NotNil(t, tc.err, err.Error())
			}
		})
	}
}
