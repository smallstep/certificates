package authority

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/cli/crypto/keys"
	"github.com/smallstep/cli/crypto/tlsutil"
	"github.com/smallstep/cli/crypto/x509util"
	"github.com/smallstep/cli/jose"
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

func TestSign(t *testing.T) {
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
		NotBefore: nb,
		NotAfter:  nb.Add(time.Minute * 5),
	}

	// Create a token to get test extra opts.
	p := a.config.AuthorityConfig.Provisioners[1].(*provisioner.JWK)
	key, err := jose.ParseKey("testdata/secrets/step_cli_key_priv.jwk", jose.WithPassword([]byte("pass")))
	assert.FatalError(t, err)
	token, err := generateToken("smallstep test", "step-cli", "https://test.ca.smallstep.com/sign", []string{"test.smallstep.com"}, time.Now(), key)
	assert.FatalError(t, err)
	extraOpts, err := a.Authorize(token)
	assert.FatalError(t, err)

	type signTest struct {
		auth      *Authority
		csr       *x509.CertificateRequest
		signOpts  provisioner.Options
		extraOpts []provisioner.SignOption
		err       *apiError
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
				err: &apiError{errors.New("sign: invalid certificate request"),
					http.StatusBadRequest,
					context{"csr": csr, "signOptions": signOpts},
				},
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
				err: &apiError{errors.New("sign: invalid extra option type string"),
					http.StatusInternalServerError,
					context{"csr": csr, "signOptions": signOpts},
				},
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
				err: &apiError{errors.New("sign: default ASN1DN template cannot be nil"),
					http.StatusInternalServerError,
					context{"csr": csr, "signOptions": signOpts},
				},
			}
		},
		"fail create cert": func(t *testing.T) *signTest {
			_a := testAuthority(t)
			_a.intermediateIdentity.Key = nil
			csr := getCSR(t, priv)
			return &signTest{
				auth:      _a,
				csr:       csr,
				extraOpts: extraOpts,
				signOpts:  signOpts,
				err: &apiError{errors.New("sign: error creating new leaf certificate"),
					http.StatusInternalServerError,
					context{"csr": csr, "signOptions": signOpts},
				},
			}
		},
		"fail provisioner duration claim": func(t *testing.T) *signTest {
			csr := getCSR(t, priv)
			_signOpts := provisioner.Options{
				NotBefore: nb,
				NotAfter:  nb.Add(time.Hour * 25),
			}
			return &signTest{
				auth:      a,
				csr:       csr,
				extraOpts: extraOpts,
				signOpts:  _signOpts,
				err: &apiError{errors.New("sign: requested duration of 25h0m0s is more than the authorized maximum certificate duration of 24h0m0s"),
					http.StatusUnauthorized,
					context{"csr": csr, "signOptions": _signOpts},
				},
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
				err: &apiError{errors.New("sign: certificate request does not contain the valid DNS names - got [test.smallstep.com smallstep test], want [test.smallstep.com]"),
					http.StatusUnauthorized,
					context{"csr": csr, "signOptions": signOpts},
				},
			}
		},
		"ok": func(t *testing.T) *signTest {
			csr := getCSR(t, priv)
			return &signTest{
				auth:      a,
				csr:       csr,
				extraOpts: extraOpts,
				signOpts:  signOpts,
			}
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)

			leaf, intermediate, err := tc.auth.Sign(tc.csr, tc.signOpts, tc.extraOpts...)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					switch v := err.(type) {
					case *apiError:
						assert.HasPrefix(t, v.err.Error(), tc.err.Error())
						assert.Equals(t, v.code, tc.err.code)
						assert.Equals(t, v.context, tc.err.context)
					default:
						t.Errorf("unexpected error type: %T", v)
					}
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, leaf.NotBefore, signOpts.NotBefore.UTC().Truncate(time.Second))
					assert.Equals(t, leaf.NotAfter, signOpts.NotAfter.UTC().Truncate(time.Second))
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

					assert.Equals(t, leaf.AuthorityKeyId, a.intermediateIdentity.Crt.SubjectKeyId)

					// Verify Provisioner OID
					found := 0
					for _, ext := range leaf.Extensions {
						id := ext.Id.String()
						if id != stepOIDProvisioner.String() {
							continue
						}
						found++
						val := stepProvisionerASN1{}
						_, err := asn1.Unmarshal(ext.Value, &val)
						assert.FatalError(t, err)
						assert.Equals(t, val.Type, provisionerTypeJWK)
						assert.Equals(t, val.Name, []byte(p.Name))
						assert.Equals(t, val.CredentialID, []byte(p.Key.KeyID))
					}
					assert.Equals(t, found, 1)

					realIntermediate, err := x509.ParseCertificate(a.intermediateIdentity.Crt.Raw)
					assert.FatalError(t, err)
					assert.Equals(t, intermediate, realIntermediate)
				}
			}
		})
	}
}

func TestRenew(t *testing.T) {
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
		NotBefore: nb1,
		NotAfter:  na1,
	}

	leaf, err := x509util.NewLeafProfile("renew", a.intermediateIdentity.Crt,
		a.intermediateIdentity.Key,
		x509util.WithNotBeforeAfterDuration(so.NotBefore, so.NotAfter, 0),
		withDefaultASN1DN(a.config.AuthorityConfig.Template),
		x509util.WithPublicKey(pub), x509util.WithHosts("test.smallstep.com,test"),
		withProvisionerOID("Max", a.config.AuthorityConfig.Provisioners[0].(*provisioner.JWK).Key.KeyID))
	assert.FatalError(t, err)
	crtBytes, err := leaf.CreateCertificate()
	assert.FatalError(t, err)
	crt, err := x509.ParseCertificate(crtBytes)
	assert.FatalError(t, err)

	leafNoRenew, err := x509util.NewLeafProfile("norenew", a.intermediateIdentity.Crt,
		a.intermediateIdentity.Key,
		x509util.WithNotBeforeAfterDuration(so.NotBefore, so.NotAfter, 0),
		withDefaultASN1DN(a.config.AuthorityConfig.Template),
		x509util.WithPublicKey(pub), x509util.WithHosts("test.smallstep.com,test"),
		withProvisionerOID("dev", a.config.AuthorityConfig.Provisioners[2].(*provisioner.JWK).Key.KeyID),
	)
	assert.FatalError(t, err)
	crtBytesNoRenew, err := leafNoRenew.CreateCertificate()
	assert.FatalError(t, err)
	crtNoRenew, err := x509.ParseCertificate(crtBytesNoRenew)
	assert.FatalError(t, err)

	type renewTest struct {
		auth *Authority
		crt  *x509.Certificate
		err  *apiError
	}
	tests := map[string]func() (*renewTest, error){
		"fail-create-cert": func() (*renewTest, error) {
			_a := testAuthority(t)
			_a.intermediateIdentity.Key = nil
			return &renewTest{
				auth: _a,
				crt:  crt,
				err: &apiError{errors.New("error renewing certificate from existing server certificate"),
					http.StatusInternalServerError, context{}},
			}, nil
		},
		"fail-unauthorized": func() (*renewTest, error) {
			ctx := map[string]interface{}{
				"serialNumber": crtNoRenew.SerialNumber.String(),
			}
			return &renewTest{
				crt: crtNoRenew,
				err: &apiError{errors.New("renew is disabled for provisioner dev:IMi94WBNI6gP5cNHXlZYNUzvMjGdHyBRmFoo-lCEaqk"),
					http.StatusUnauthorized, ctx},
			}, nil
		},
		"success": func() (*renewTest, error) {
			return &renewTest{
				auth: a,
				crt:  crt,
			}, nil
		},
		"success-new-intermediate": func() (*renewTest, error) {
			newRootProfile, err := x509util.NewRootProfile("new-root")
			assert.FatalError(t, err)
			newRootBytes, err := newRootProfile.CreateCertificate()
			assert.FatalError(t, err)
			newRootCrt, err := x509.ParseCertificate(newRootBytes)
			assert.FatalError(t, err)

			newIntermediateProfile, err := x509util.NewIntermediateProfile("new-intermediate",
				newRootCrt, newRootProfile.SubjectPrivateKey())
			assert.FatalError(t, err)
			newIntermediateBytes, err := newIntermediateProfile.CreateCertificate()
			assert.FatalError(t, err)
			newIntermediateCrt, err := x509.ParseCertificate(newIntermediateBytes)
			assert.FatalError(t, err)

			_a := testAuthority(t)
			_a.intermediateIdentity.Key = newIntermediateProfile.SubjectPrivateKey()
			_a.intermediateIdentity.Crt = newIntermediateCrt
			return &renewTest{
				auth: _a,
				crt:  crt,
			}, nil
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc, err := genTestCase()
			assert.FatalError(t, err)

			var leaf, intermediate *x509.Certificate
			if tc.auth != nil {
				leaf, intermediate, err = tc.auth.Renew(tc.crt)
			} else {
				leaf, intermediate, err = a.Renew(tc.crt)
			}
			if err != nil {
				if assert.NotNil(t, tc.err) {
					switch v := err.(type) {
					case *apiError:
						assert.HasPrefix(t, v.err.Error(), tc.err.Error())
						assert.Equals(t, v.code, tc.err.code)
						assert.Equals(t, v.context, tc.err.context)
					default:
						t.Errorf("unexpected error type: %T", v)
					}
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, leaf.NotAfter.Sub(leaf.NotBefore), tc.crt.NotAfter.Sub(crt.NotBefore))

					assert.True(t, leaf.NotBefore.After(now.Add(-time.Minute)))
					assert.True(t, leaf.NotBefore.Before(now.Add(time.Minute)))

					expiry := now.Add(time.Minute * 7)
					assert.True(t, leaf.NotAfter.After(expiry.Add(-time.Minute)))
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
					if a.intermediateIdentity.Crt.SerialNumber == tc.auth.intermediateIdentity.Crt.SerialNumber {
						assert.Equals(t, leaf.AuthorityKeyId, a.intermediateIdentity.Crt.SubjectKeyId)
						// Compare extensions: they can be in a different order
						for _, ext1 := range tc.crt.Extensions {
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
						assert.Equals(t, leaf.AuthorityKeyId, tc.auth.intermediateIdentity.Crt.SubjectKeyId)
						// Compare extensions: they can be in a different order
						for _, ext1 := range tc.crt.Extensions {
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

					realIntermediate, err := x509.ParseCertificate(tc.auth.intermediateIdentity.Crt.Raw)
					assert.FatalError(t, err)
					assert.Equals(t, intermediate, realIntermediate)
				}
			}
		})
	}
}

func TestGetTLSOptions(t *testing.T) {
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
