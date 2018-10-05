package authority

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/ca-component/api"
	"github.com/smallstep/cli/crypto/keys"
	"github.com/smallstep/cli/crypto/tlsutil"
	"github.com/smallstep/cli/crypto/x509util"
)

func getCSR(t *testing.T, priv interface{}) *x509.CertificateRequest {
	_csr := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "test"},
		DNSNames: []string{"test.smallstep.com"},
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
		CommonName:    "test",
	}

	now := time.Now()

	type signTest struct {
		auth   *Authority
		csr    *x509.CertificateRequest
		opts   api.SignOptions
		claims []api.Claim
		err    *apiError
	}
	tests := map[string]func(*testing.T) *signTest{
		"fail-validate-claims": func(t *testing.T) *signTest {
			csr := getCSR(t, priv)
			return &signTest{
				auth: a,
				csr:  csr,
				opts: api.SignOptions{
					NotBefore: now,
					NotAfter:  now.Add(time.Minute * 5),
				},
				claims: []api.Claim{&commonNameClaim{"foo"}},
				err: &apiError{errors.New("common name claim failed - got test, want foo"),
					http.StatusUnauthorized, context{}},
			}
		},
		"fail-convert-stepCSR": func(t *testing.T) *signTest {
			csr := getCSR(t, priv)
			csr.Raw = []byte("foo")
			return &signTest{
				auth: a,
				csr:  csr,
				opts: api.SignOptions{
					NotBefore: now,
					NotAfter:  now.Add(time.Minute * 5),
				},
				claims: []api.Claim{&commonNameClaim{"test"}},
				err: &apiError{errors.New("error converting x509 csr to stepx509 csr"),
					http.StatusInternalServerError, context{}},
			}
		},
		"fail-merge-default-ASN1DN": func(t *testing.T) *signTest {
			_a := testAuthority(t)
			_a.config.AuthorityConfig.Template = nil
			csr := getCSR(t, priv)
			return &signTest{
				auth: _a,
				csr:  csr,
				opts: api.SignOptions{
					NotBefore: now,
					NotAfter:  now.Add(time.Minute * 5),
				},
				claims: []api.Claim{&commonNameClaim{"test"}},
				err: &apiError{errors.New("default ASN1DN template cannot be nil"),
					http.StatusInternalServerError, context{}},
			}
		},
		"fail-create-cert": func(t *testing.T) *signTest {
			_a := testAuthority(t)
			_a.intermediateIdentity.Key = nil
			csr := getCSR(t, priv)
			return &signTest{
				auth: _a,
				csr:  csr,
				opts: api.SignOptions{
					NotBefore: now,
					NotAfter:  now.Add(time.Minute * 5),
				},
				claims: []api.Claim{&commonNameClaim{"test"}},
				err: &apiError{errors.New("error creating new leaf certificate from input csr"),
					http.StatusInternalServerError, context{}},
			}
		},
		"success": func(t *testing.T) *signTest {
			csr := getCSR(t, priv)
			return &signTest{
				auth: a,
				csr:  csr,
				opts: api.SignOptions{
					NotBefore: now,
					NotAfter:  now.Add(time.Minute * 5),
				},
				claims: []api.Claim{&commonNameClaim{"test"}},
			}
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)

			leaf, intermediate, err := tc.auth.Sign(tc.csr, tc.opts, tc.claims...)
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
					assert.Equals(t, leaf.NotBefore, tc.opts.NotBefore.UTC().Truncate(time.Second))
					assert.Equals(t, leaf.NotAfter, tc.opts.NotAfter.UTC().Truncate(time.Second))
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
					assert.Equals(t, leaf.DNSNames, []string{"test"})

					pubBytes, err := x509.MarshalPKIXPublicKey(pub)
					assert.FatalError(t, err)
					hash := sha1.Sum(pubBytes)
					assert.Equals(t, leaf.SubjectKeyId, hash[:])

					assert.Equals(t, leaf.AuthorityKeyId, a.intermediateIdentity.Crt.SubjectKeyId)

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
	so := &api.SignOptions{
		NotBefore: nb1,
		NotAfter:  na1,
	}

	leaf, err := x509util.NewLeafProfile("renew", a.intermediateIdentity.Crt,
		a.intermediateIdentity.Key,
		x509util.WithNotBeforeAfter(so.NotBefore, so.NotAfter),
		withDefaultASN1DN(a.config.AuthorityConfig.Template),
		x509util.WithPublicKey(pub), x509util.WithHosts("test.smallstep.com,test"))
	assert.FatalError(t, err)
	crtBytes, err := leaf.CreateCertificate()
	assert.FatalError(t, err)
	crt, err := x509.ParseCertificate(crtBytes)
	assert.FatalError(t, err)

	type renewTest struct {
		auth *Authority
		crt  *x509.Certificate
		err  *apiError
	}
	tests := map[string]func() (*renewTest, error){
		"fail-conversion-stepx509": func() (*renewTest, error) {
			return &renewTest{
				crt: &x509.Certificate{Raw: []byte("foo")},
				err: &apiError{errors.New("error converting x509.Certificate to stepx509.Certificate"),
					http.StatusInternalServerError, context{}},
			}, nil
		},
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
		"success": func() (*renewTest, error) {
			return &renewTest{
				crt: crt,
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
					assert.Equals(t, leaf.NotAfter.Sub(leaf.NotBefore), crt.NotAfter.Sub(crt.NotBefore))

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

					assert.Equals(t, leaf.AuthorityKeyId, a.intermediateIdentity.Crt.SubjectKeyId)

					realIntermediate, err := x509.ParseCertificate(a.intermediateIdentity.Crt.Raw)
					assert.FatalError(t, err)
					assert.Equals(t, intermediate, realIntermediate)
				}
			}
		})
	}
}

func TestGetMinDuration(t *testing.T) {
	type renewTest struct {
		auth *Authority
		d    time.Duration
	}
	tests := map[string]func() (*renewTest, error){
		"default": func() (*renewTest, error) {
			a := testAuthority(t)
			return &renewTest{auth: a, d: time.Minute * 5}, nil
		},
		"non-default": func() (*renewTest, error) {
			a := testAuthority(t)
			a.config.AuthorityConfig.MinCertDuration = &duration{time.Minute * 7}
			return &renewTest{auth: a, d: time.Minute * 7}, nil
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc, err := genTestCase()
			assert.FatalError(t, err)

			d := tc.auth.GetMinDuration()
			assert.Equals(t, d, tc.d)
		})
	}
}

func TestGetMaxDuration(t *testing.T) {
	type renewTest struct {
		auth *Authority
		d    time.Duration
	}
	tests := map[string]func() (*renewTest, error){
		"default": func() (*renewTest, error) {
			a := testAuthority(t)
			return &renewTest{auth: a, d: time.Hour * 24}, nil
		},
		"non-default": func() (*renewTest, error) {
			a := testAuthority(t)
			a.config.AuthorityConfig.MaxCertDuration = &duration{time.Minute * 7}
			return &renewTest{auth: a, d: time.Minute * 7}, nil
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc, err := genTestCase()
			assert.FatalError(t, err)

			d := tc.auth.GetMaxDuration()
			assert.Equals(t, d, tc.d)
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
