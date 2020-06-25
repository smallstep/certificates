package authority

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/certificates/errs"
	"github.com/smallstep/cli/crypto/keys"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/crypto/tlsutil"
	"github.com/smallstep/cli/crypto/x509util"
	"github.com/smallstep/cli/jose"
	"gopkg.in/square/go-jose.v2/jwt"
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

func withProvisionerOID(name, kid string) x509util.WithOption {
	return func(p x509util.Profile) error {
		crt := p.Subject()

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

type basicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

func TestAuthority_Sign(t *testing.T) {
	pub, priv, err := keys.GenerateDefaultKeyPair()
	assert.FatalError(t, err)

	a := testAuthority(t)
	assert.FatalError(t, err)
	a.config.AuthorityConfig.Template = &x509util.ASN1DN{
		Country:       "Tazmania",
		Organization:  "Acme Co",
		Locality:      "Landscapes",
		Province:      "Sudden Cliffs",
		StreetAddress: "TNT",
		CommonName:    "test.smallstep.com",
	}

	nb := time.Now()
	signOpts := provisioner.Options{
		NotBefore: provisioner.NewTimeDuration(nb),
		NotAfter:  provisioner.NewTimeDuration(nb.Add(time.Minute * 5)),
	}

	// Create a token to get test extra opts.
	p := a.config.AuthorityConfig.Provisioners[1].(*provisioner.JWK)
	key, err := jose.ParseKey("testdata/secrets/step_cli_key_priv.jwk", jose.WithPassword([]byte("pass")))
	assert.FatalError(t, err)
	token, err := generateToken("smallstep test", "step-cli", testAudiences.Sign[0], []string{"test.smallstep.com"}, time.Now(), key)
	assert.FatalError(t, err)
	ctx := provisioner.NewContextWithMethod(context.Background(), provisioner.SignMethod)
	extraOpts, err := a.Authorize(ctx, token)
	assert.FatalError(t, err)

	type signTest struct {
		auth      *Authority
		csr       *x509.CertificateRequest
		signOpts  provisioner.Options
		extraOpts []provisioner.SignOption
		notBefore time.Time
		notAfter  time.Time
		err       error
		code      int
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
				err:       errors.New("authority.Sign; invalid certificate request"),
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
				err:       errors.New("authority.Sign: default ASN1DN template cannot be nil"),
				code:      http.StatusInternalServerError,
			}
		},
		"fail create cert": func(t *testing.T) *signTest {
			_a := testAuthority(t)
			_a.x509Signer = nil
			csr := getCSR(t, priv)
			return &signTest{
				auth:      _a,
				csr:       csr,
				extraOpts: extraOpts,
				signOpts:  signOpts,
				err:       errors.New("authority.Sign; error creating new leaf certificate"),
				code:      http.StatusInternalServerError,
			}
		},
		"fail provisioner duration claim": func(t *testing.T) *signTest {
			csr := getCSR(t, priv)
			_signOpts := provisioner.Options{
				NotBefore: provisioner.NewTimeDuration(nb),
				NotAfter:  provisioner.NewTimeDuration(nb.Add(time.Hour * 25)),
			}
			return &signTest{
				auth:      a,
				csr:       csr,
				extraOpts: extraOpts,
				signOpts:  _signOpts,
				err:       errors.New("authority.Sign: requested duration of 25h0m0s is more than the authorized maximum certificate duration of 24h1m0s"),
				code:      http.StatusUnauthorized,
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
				err:       errors.New("authority.Sign: certificate request does not contain the valid DNS names - got [test.smallstep.com smallstep test], want [test.smallstep.com]"),
				code:      http.StatusUnauthorized,
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
				err:       errors.New("authority.Sign: rsa key in CSR must be at least 2048 bits (256 bytes)"),
				code:      http.StatusUnauthorized,
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
				auth:      a,
				csr:       csr,
				extraOpts: extraOpts,
				signOpts:  signOpts,
				notBefore: signOpts.NotBefore.Time().Truncate(time.Second),
				notAfter:  signOpts.NotAfter.Time().Truncate(time.Second),
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
				auth:      a,
				csr:       csr,
				extraOpts: enforcedExtraOptions,
				signOpts:  signOpts,
				notBefore: now.Truncate(time.Second),
				notAfter:  now.Add(365 * 24 * time.Hour).Truncate(time.Second),
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
					sc, ok := err.(errs.StatusCoder)
					assert.Fatal(t, ok, "error does not implement StatusCoder interface")
					assert.Equals(t, sc.StatusCode(), tc.code)
					assert.HasPrefix(t, err.Error(), tc.err.Error())

					ctxErr, ok := err.(*errs.Error)
					assert.Fatal(t, ok, "error is not of type *errs.Error")
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
					assert.Equals(t, fmt.Sprintf("%v", leaf.Subject),
						fmt.Sprintf("%v", &pkix.Name{
							Country:       []string{tmplt.Country},
							Organization:  []string{tmplt.Organization},
							Locality:      []string{tmplt.Locality},
							StreetAddress: []string{tmplt.StreetAddress},
							Province:      []string{tmplt.Province},
							CommonName:    "smallstep test",
						}))
					assert.Equals(t, leaf.Issuer, intermediate.Subject)

					assert.Equals(t, leaf.SignatureAlgorithm, x509.ECDSAWithSHA256)
					assert.Equals(t, leaf.PublicKeyAlgorithm, x509.ECDSA)
					assert.Equals(t, leaf.ExtKeyUsage,
						[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
					assert.Equals(t, leaf.DNSNames, []string{"test.smallstep.com"})

					pubBytes, err := x509.MarshalPKIXPublicKey(pub)
					assert.FatalError(t, err)
					hash := sha1.Sum(pubBytes)
					assert.Equals(t, leaf.SubjectKeyId, hash[:])

					assert.Equals(t, leaf.AuthorityKeyId, a.x509Issuer.SubjectKeyId)

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
						}
					}
					assert.Equals(t, found, 1)
					assert.Len(t, 6, leaf.Extensions)

					realIntermediate, err := x509.ParseCertificate(a.x509Issuer.Raw)
					assert.FatalError(t, err)
					assert.Equals(t, intermediate, realIntermediate)
				}
			}
		})
	}
}

func TestAuthority_Renew(t *testing.T) {
	pub, _, err := keys.GenerateDefaultKeyPair()
	assert.FatalError(t, err)

	a := testAuthority(t)
	a.config.AuthorityConfig.Template = &x509util.ASN1DN{
		Country:       "Tazmania",
		Organization:  "Acme Co",
		Locality:      "Landscapes",
		Province:      "Sudden Cliffs",
		StreetAddress: "TNT",
		CommonName:    "renew",
	}

	now := time.Now().UTC()
	nb1 := now.Add(-time.Minute * 7)
	na1 := now
	so := &provisioner.Options{
		NotBefore: provisioner.NewTimeDuration(nb1),
		NotAfter:  provisioner.NewTimeDuration(na1),
	}

	leaf, err := x509util.NewLeafProfile("renew", a.x509Issuer, a.x509Signer,
		x509util.WithNotBeforeAfterDuration(so.NotBefore.Time(), so.NotAfter.Time(), 0),
		withDefaultASN1DN(a.config.AuthorityConfig.Template),
		x509util.WithPublicKey(pub), x509util.WithHosts("test.smallstep.com,test"),
		withProvisionerOID("Max", a.config.AuthorityConfig.Provisioners[0].(*provisioner.JWK).Key.KeyID))
	assert.FatalError(t, err)
	certBytes, err := leaf.CreateCertificate()
	assert.FatalError(t, err)
	cert, err := x509.ParseCertificate(certBytes)
	assert.FatalError(t, err)

	leafNoRenew, err := x509util.NewLeafProfile("norenew", a.x509Issuer, a.x509Signer,
		x509util.WithNotBeforeAfterDuration(so.NotBefore.Time(), so.NotAfter.Time(), 0),
		withDefaultASN1DN(a.config.AuthorityConfig.Template),
		x509util.WithPublicKey(pub), x509util.WithHosts("test.smallstep.com,test"),
		withProvisionerOID("dev", a.config.AuthorityConfig.Provisioners[2].(*provisioner.JWK).Key.KeyID),
	)
	assert.FatalError(t, err)
	certBytesNoRenew, err := leafNoRenew.CreateCertificate()
	assert.FatalError(t, err)
	certNoRenew, err := x509.ParseCertificate(certBytesNoRenew)
	assert.FatalError(t, err)

	type renewTest struct {
		auth *Authority
		cert *x509.Certificate
		err  error
		code int
	}
	tests := map[string]func() (*renewTest, error){
		"fail-create-cert": func() (*renewTest, error) {
			_a := testAuthority(t)
			_a.x509Signer = nil
			return &renewTest{
				auth: _a,
				cert: cert,
				err:  errors.New("authority.Renew; error renewing certificate from existing server certificate"),
				code: http.StatusInternalServerError,
			}, nil
		},
		"fail-unauthorized": func() (*renewTest, error) {
			return &renewTest{
				cert: certNoRenew,
				err:  errors.New("authority.Renew: authority.authorizeRenew: jwk.AuthorizeRenew; renew is disabled for jwk provisioner dev:IMi94WBNI6gP5cNHXlZYNUzvMjGdHyBRmFoo-lCEaqk"),
				code: http.StatusUnauthorized,
			}, nil
		},
		"success": func() (*renewTest, error) {
			return &renewTest{
				auth: a,
				cert: cert,
			}, nil
		},
		"success-new-intermediate": func() (*renewTest, error) {
			newRootProfile, err := x509util.NewRootProfile("new-root")
			assert.FatalError(t, err)
			newRootBytes, err := newRootProfile.CreateCertificate()
			assert.FatalError(t, err)
			newRootCert, err := x509.ParseCertificate(newRootBytes)
			assert.FatalError(t, err)

			newIntermediateProfile, err := x509util.NewIntermediateProfile("new-intermediate",
				newRootCert, newRootProfile.SubjectPrivateKey())
			assert.FatalError(t, err)
			newIntermediateBytes, err := newIntermediateProfile.CreateCertificate()
			assert.FatalError(t, err)
			newIntermediateCert, err := x509.ParseCertificate(newIntermediateBytes)
			assert.FatalError(t, err)

			_a := testAuthority(t)
			_a.x509Signer = newIntermediateProfile.SubjectPrivateKey().(crypto.Signer)
			_a.x509Issuer = newIntermediateCert
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
				certChain, err = tc.auth.Renew(tc.cert)
			} else {
				certChain, err = a.Renew(tc.cert)
			}
			if err != nil {
				if assert.NotNil(t, tc.err, fmt.Sprintf("unexpected error: %s", err)) {
					assert.Nil(t, certChain)
					sc, ok := err.(errs.StatusCoder)
					assert.Fatal(t, ok, "error does not implement StatusCoder interface")
					assert.Equals(t, sc.StatusCode(), tc.code)
					assert.HasPrefix(t, err.Error(), tc.err.Error())

					ctxErr, ok := err.(*errs.Error)
					assert.Fatal(t, ok, "error is not of type *errs.Error")
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
					assert.True(t, leaf.NotAfter.Before(expiry.Add(time.Minute)))

					tmplt := a.config.AuthorityConfig.Template
					assert.Equals(t, fmt.Sprintf("%v", leaf.Subject),
						fmt.Sprintf("%v", &pkix.Name{
							Country:       []string{tmplt.Country},
							Organization:  []string{tmplt.Organization},
							Locality:      []string{tmplt.Locality},
							StreetAddress: []string{tmplt.StreetAddress},
							Province:      []string{tmplt.Province},
							CommonName:    tmplt.CommonName,
						}))
					assert.Equals(t, leaf.Issuer, intermediate.Subject)

					assert.Equals(t, leaf.SignatureAlgorithm, x509.ECDSAWithSHA256)
					assert.Equals(t, leaf.PublicKeyAlgorithm, x509.ECDSA)
					assert.Equals(t, leaf.ExtKeyUsage,
						[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
					assert.Equals(t, leaf.DNSNames, []string{"test.smallstep.com", "test"})

					pubBytes, err := x509.MarshalPKIXPublicKey(pub)
					assert.FatalError(t, err)
					hash := sha1.Sum(pubBytes)
					assert.Equals(t, leaf.SubjectKeyId, hash[:])

					// We did not change the intermediate before renewing.
					if a.x509Issuer.SerialNumber == tc.auth.x509Issuer.SerialNumber {
						assert.Equals(t, leaf.AuthorityKeyId, a.x509Issuer.SubjectKeyId)
						// Compare extensions: they can be in a different order
						for _, ext1 := range tc.cert.Extensions {
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
						assert.Equals(t, leaf.AuthorityKeyId, tc.auth.x509Issuer.SubjectKeyId)
						// Compare extensions: they can be in a different order
						for _, ext1 := range tc.cert.Extensions {
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

					realIntermediate, err := x509.ParseCertificate(tc.auth.x509Issuer.Raw)
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
		opts *tlsutil.TLSOptions
	}
	tests := map[string]func() (*renewTest, error){
		"default": func() (*renewTest, error) {
			a := testAuthority(t)
			return &renewTest{auth: a, opts: &DefaultTLSOptions}, nil
		},
		"non-default": func() (*renewTest, error) {
			a := testAuthority(t)
			a.config.TLS = &tlsutil.TLSOptions{
				CipherSuites: x509util.CipherSuites{
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

	jwk, err := jose.ParseKey("testdata/secrets/step_cli_key_priv.jwk", jose.WithPassword([]byte("pass")))
	assert.FatalError(t, err)

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jwk.Key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", jwk.KeyID))
	assert.FatalError(t, err)

	a := testAuthority(t)

	type test struct {
		auth            *Authority
		opts            *RevokeOptions
		err             error
		code            int
		checkErrDetails func(err *errs.Error)
	}
	tests := map[string]func() test{
		"fail/token/authorizeRevoke error": func() test {
			return test{
				auth: a,
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
			cl := jwt.Claims{
				Subject:   "sn",
				Issuer:    validIssuer,
				NotBefore: jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "44",
			}
			raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)

			return test{
				auth: a,
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
				Err: errors.New("force"),
			}))

			cl := jwt.Claims{
				Subject:   "sn",
				Issuer:    validIssuer,
				NotBefore: jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "44",
			}
			raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)

			return test{
				auth: _a,
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
				Err: db.ErrAlreadyExists,
			}))

			cl := jwt.Claims{
				Subject:   "sn",
				Issuer:    validIssuer,
				NotBefore: jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "44",
			}
			raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)

			return test{
				auth: _a,
				opts: &RevokeOptions{
					Serial:     "sn",
					ReasonCode: reasonCode,
					Reason:     reason,
					OTT:        raw,
				},
				err:  errors.New("authority.Revoke; certificate with serial number sn has already been revoked"),
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
			}))

			cl := jwt.Claims{
				Subject:   "sn",
				Issuer:    validIssuer,
				NotBefore: jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "44",
			}
			raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return test{
				auth: _a,
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
				opts: &RevokeOptions{
					Crt:        crt,
					Serial:     "102012593071130646873265215610956555026",
					ReasonCode: reasonCode,
					Reason:     reason,
					MTLS:       true,
				},
			}
		},
	}
	for name, f := range tests {
		tc := f()
		t.Run(name, func(t *testing.T) {
			ctx := provisioner.NewContextWithMethod(context.Background(), provisioner.RevokeMethod)
			if err := tc.auth.Revoke(ctx, tc.opts); err != nil {
				if assert.NotNil(t, tc.err, fmt.Sprintf("unexpected error: %s", err)) {
					sc, ok := err.(errs.StatusCoder)
					assert.Fatal(t, ok, "error does not implement StatusCoder interface")
					assert.Equals(t, sc.StatusCode(), tc.code)
					assert.HasPrefix(t, err.Error(), tc.err.Error())

					ctxErr, ok := err.(*errs.Error)
					assert.Fatal(t, ok, "error is not of type *errs.Error")
					assert.Equals(t, ctxErr.Details["serialNumber"], tc.opts.Serial)
					assert.Equals(t, ctxErr.Details["reasonCode"], tc.opts.ReasonCode)
					assert.Equals(t, ctxErr.Details["reason"], tc.opts.Reason)
					assert.Equals(t, ctxErr.Details["MTLS"], tc.opts.MTLS)
					assert.Equals(t, ctxErr.Details["context"], string(provisioner.RevokeMethod))

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
