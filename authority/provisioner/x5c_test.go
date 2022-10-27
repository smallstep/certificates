package provisioner

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/randutil"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/api/render"
)

func TestX5C_Getters(t *testing.T) {
	p, err := generateX5C(nil)
	assert.FatalError(t, err)
	id := "x5c/" + p.Name
	if got := p.GetID(); got != id {
		t.Errorf("X5C.GetID() = %v, want %v:%v", got, p.Name, id)
	}
	if got := p.GetName(); got != p.Name {
		t.Errorf("X5C.GetName() = %v, want %v", got, p.Name)
	}
	if got := p.GetType(); got != TypeX5C {
		t.Errorf("X5C.GetType() = %v, want %v", got, TypeX5C)
	}
	kid, key, ok := p.GetEncryptedKey()
	if kid != "" || key != "" || ok == true {
		t.Errorf("X5C.GetEncryptedKey() = (%v, %v, %v), want (%v, %v, %v)",
			kid, key, ok, "", "", false)
	}
}

func TestX5C_Init(t *testing.T) {
	type ProvisionerValidateTest struct {
		p          *X5C
		err        error
		extraValid func(*X5C) error
	}
	tests := map[string]func(*testing.T) ProvisionerValidateTest{
		"fail/empty": func(t *testing.T) ProvisionerValidateTest {
			return ProvisionerValidateTest{
				p:   &X5C{},
				err: errors.New("provisioner type cannot be empty"),
			}
		},
		"fail/empty-name": func(t *testing.T) ProvisionerValidateTest {
			return ProvisionerValidateTest{
				p: &X5C{
					Type: "X5C",
				},
				err: errors.New("provisioner name cannot be empty"),
			}
		},
		"fail/empty-type": func(t *testing.T) ProvisionerValidateTest {
			return ProvisionerValidateTest{
				p:   &X5C{Name: "foo"},
				err: errors.New("provisioner type cannot be empty"),
			}
		},
		"fail/empty-key": func(t *testing.T) ProvisionerValidateTest {
			return ProvisionerValidateTest{
				p:   &X5C{Name: "foo", Type: "bar"},
				err: errors.New("provisioner root(s) cannot be empty"),
			}
		},
		"fail/no-valid-root-certs": func(t *testing.T) ProvisionerValidateTest {
			return ProvisionerValidateTest{
				p:   &X5C{Name: "foo", Type: "bar", Roots: []byte("foo")},
				err: errors.New("no x509 certificates found in roots attribute for provisioner 'foo'"),
			}
		},
		"fail/invalid-duration": func(t *testing.T) ProvisionerValidateTest {
			p, err := generateX5C(nil)
			assert.FatalError(t, err)
			p.Claims = &Claims{DefaultTLSDur: &Duration{0}}
			return ProvisionerValidateTest{
				p:   p,
				err: errors.New("claims: MinTLSCertDuration must be greater than 0"),
			}
		},
		"ok": func(t *testing.T) ProvisionerValidateTest {
			p, err := generateX5C(nil)
			assert.FatalError(t, err)
			return ProvisionerValidateTest{
				p: p,
			}
		},
		"ok/root-chain": func(t *testing.T) ProvisionerValidateTest {
			p, err := generateX5C([]byte(`-----BEGIN CERTIFICATE-----
MIIBtjCCAVygAwIBAgIQNr+f4IkABY2n4wx4sLOMrTAKBggqhkjOPQQDAjAUMRIw
EAYDVQQDEwlyb290LXRlc3QwIBcNMTkxMDAyMDI0MDM0WhgPMjExOTA5MDgwMjQw
MzJaMBwxGjAYBgNVBAMTEWludGVybWVkaWF0ZS10ZXN0MFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAEflfRhPjgJXv4zsPWahXjM2UU61aRFErN0iw88ZPyxea22fxl
qN9ezntTXxzsS+mZiWapl8B40ACJgvP+WLQBHKOBhTCBgjAOBgNVHQ8BAf8EBAMC
AQYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUnJAxiZcy2ibHcuvfFx99
oDwzKXMwHwYDVR0jBBgwFoAUpHS7FfaQ5bCrTxUeu6R2ZC3VGOowHAYDVR0RBBUw
E4IRaW50ZXJtZWRpYXRlLXRlc3QwCgYIKoZIzj0EAwIDSAAwRQIgII8XpQ8ezDO1
2xdq3hShf155C5X/5jO8qr0VyEJgzlkCIQCTqph1Gwu/dmuf6dYLCfQqJyb371LC
lgsqsR63is+0YQ==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBhTCCASqgAwIBAgIRAMalM7pKi0GCdKjO6u88OyowCgYIKoZIzj0EAwIwFDES
MBAGA1UEAxMJcm9vdC10ZXN0MCAXDTE5MTAwMjAyMzk0OFoYDzIxMTkwOTA4MDIz
OTQ4WjAUMRIwEAYDVQQDEwlyb290LXRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMB
BwNCAAS29QTCXUu7cx9sa9wZPpRSFq/zXaw8Ai3EIygayrBsKnX42U2atBUjcBZO
BWL6A+PpLzU9ja867U5SYNHERS+Oo1swWTAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0T
AQH/BAgwBgEB/wIBATAdBgNVHQ4EFgQUpHS7FfaQ5bCrTxUeu6R2ZC3VGOowFAYD
VR0RBA0wC4IJcm9vdC10ZXN0MAoGCCqGSM49BAMCA0kAMEYCIQC2vgqwla0u8LHH
1MHob14qvS5o76HautbIBW7fcHzz5gIhAIx5A2+wkJYX4026kqaZCk/1sAwTxSGY
M46l92gdOozT
-----END CERTIFICATE-----`))
			assert.FatalError(t, err)
			return ProvisionerValidateTest{
				p: p,
				extraValid: func(p *X5C) error {
					//nolint:staticcheck // We don't have a different way to
					// check the number of certificates in the pool.
					numCerts := len(p.rootPool.Subjects())
					if numCerts != 2 {
						return fmt.Errorf("unexpected number of certs: want 2, but got %d", numCerts)
					}
					return nil
				},
			}
		},
	}

	config := Config{
		Claims:    globalProvisionerClaims,
		Audiences: testAudiences,
	}
	for name, get := range tests {
		t.Run(name, func(t *testing.T) {
			tc := get(t)
			err := tc.p.Init(config)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					assert.Equals(t, tc.err.Error(), err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, *tc.p.ctl.Audiences, config.Audiences.WithFragment(tc.p.GetID()))
					if tc.extraValid != nil {
						assert.Nil(t, tc.extraValid(tc.p))
					}
				}
			}
		})
	}
}

func TestX5C_authorizeToken(t *testing.T) {
	x5cCerts, err := pemutil.ReadCertificateBundle("./testdata/certs/x5c-leaf.crt")
	assert.FatalError(t, err)
	x5cJWK, err := jose.ReadKey("./testdata/secrets/x5c-leaf.key")
	assert.FatalError(t, err)

	type test struct {
		p     *X5C
		token string
		code  int
		err   error
	}
	tests := map[string]func(*testing.T) test{
		"fail/bad-token": func(t *testing.T) test {
			p, err := generateX5C(nil)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: "foo",
				code:  http.StatusUnauthorized,
				err:   errors.New("x5c.authorizeToken; error parsing x5c token"),
			}
		},
		"fail/invalid-cert-chain": func(t *testing.T) test {
			certs, err := parseCerts([]byte(`-----BEGIN CERTIFICATE-----
MIIBpTCCAUugAwIBAgIRAOn2LHXjYyTXQ7PNjDTSKiIwCgYIKoZIzj0EAwIwHDEa
MBgGA1UEAxMRU21hbGxzdGVwIFJvb3QgQ0EwHhcNMTkwOTE0MDk1NTM2WhcNMjkw
OTExMDk1NTM2WjAkMSIwIAYDVQQDExlTbWFsbHN0ZXAgSW50ZXJtZWRpYXRlIENB
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2Cs0TY0dLM4b2s+z8+cc3JJp/W5H
zQRvICX/1aJ4MuObNLcvoSguJwJEkYpGB5fhb0KvoL+ebHfEOywGNwrWkaNmMGQw
DgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFNLJ
4ZXoX9cI6YkGPxgs2US3ssVzMB8GA1UdIwQYMBaAFGIwpqz85wL29aF47Vj9XSVM
P9K7MAoGCCqGSM49BAMCA0gAMEUCIQC5c1ldDcesDb31GlO5cEJvOcRrIrNtkk8m
a5wpg+9s6QIgHIW6L60F8klQX+EO3o0SBqLeNcaskA4oSZsKjEdpSGo=
-----END CERTIFICATE-----`))
			assert.FatalError(t, err)
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			p, err := generateX5C(nil)
			assert.FatalError(t, err)
			tok, err := generateToken("", p.Name, testAudiences.Sign[0], "",
				[]string{"test.smallstep.com"}, time.Now(), jwk,
				withX5CHdr(certs))
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("x5c.authorizeToken; error verifying x5c certificate chain in token"),
			}
		},
		"fail/doubled-up-self-signed-cert": func(t *testing.T) test {
			certs, err := parseCerts([]byte(`-----BEGIN CERTIFICATE-----
MIIBgjCCASigAwIBAgIQIZiE9wpmSj6SMMDfHD17qjAKBggqhkjOPQQDAjAQMQ4w
DAYDVQQDEwVsZWFmMjAgFw0xOTEwMDIwMzEzNTlaGA8yMTE5MDkwODAzMTM1OVow
EDEOMAwGA1UEAxMFbGVhZjIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATuajJI
3YgDaj+jorioJzGJc2+V1hUM7XzN9tIHoUeItgny9GW08TrTc23h1cCZteNZvayG
M0wGpGeXOnE4IlH9o2IwYDAOBgNVHQ8BAf8EBAMCBSAwHQYDVR0lBBYwFAYIKwYB
BQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBT99+JChTh3LWOHaqlSwNiwND18/zAQ
BgNVHREECTAHggVsZWFmMjAKBggqhkjOPQQDAgNIADBFAiB7gMRy3t81HpcnoRAS
ELZmDFaEnoLCsVfbmanFykazQQIhAI0sZjoE9t6gvzQp7XQp6CoxzCc3Jv3FwZ8G
EXAHTA9L
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBgjCCASigAwIBAgIQIZiE9wpmSj6SMMDfHD17qjAKBggqhkjOPQQDAjAQMQ4w
DAYDVQQDEwVsZWFmMjAgFw0xOTEwMDIwMzEzNTlaGA8yMTE5MDkwODAzMTM1OVow
EDEOMAwGA1UEAxMFbGVhZjIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATuajJI
3YgDaj+jorioJzGJc2+V1hUM7XzN9tIHoUeItgny9GW08TrTc23h1cCZteNZvayG
M0wGpGeXOnE4IlH9o2IwYDAOBgNVHQ8BAf8EBAMCBSAwHQYDVR0lBBYwFAYIKwYB
BQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBT99+JChTh3LWOHaqlSwNiwND18/zAQ
BgNVHREECTAHggVsZWFmMjAKBggqhkjOPQQDAgNIADBFAiB7gMRy3t81HpcnoRAS
ELZmDFaEnoLCsVfbmanFykazQQIhAI0sZjoE9t6gvzQp7XQp6CoxzCc3Jv3FwZ8G
EXAHTA9L
-----END CERTIFICATE-----`))
			assert.FatalError(t, err)
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			p, err := generateX5C(nil)
			assert.FatalError(t, err)
			tok, err := generateToken("", p.Name, testAudiences.Sign[0], "",
				[]string{"test.smallstep.com"}, time.Now(), jwk,
				withX5CHdr(certs))
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("x5c.authorizeToken; error verifying x5c certificate chain in token"),
			}
		},
		"fail/digital-signature-ext-required": func(t *testing.T) test {
			certs, err := parseCerts([]byte(`-----BEGIN CERTIFICATE-----
MIIBuTCCAV+gAwIBAgIQeRJLdDMIdn/T2ORKxYABezAKBggqhkjOPQQDAjAcMRow
GAYDVQQDExFpbnRlcm1lZGlhdGUtdGVzdDAgFw0xOTEwMDIwMjQxMTRaGA8yMTE5
MDkwODAyNDExMlowFDESMBAGA1UEAxMJbGVhZi10ZXN0MFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAEDA1nGTOujobkcBWklyvymhWE5gQlvNLarVzhhhvPDw+MK2LX
yqkXrYZM10GrwQZuQ7ykHnjz00U/KXpPRQ7+0qOBiDCBhTAOBgNVHQ8BAf8EBAMC
BSAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBQYv0AK
3GUOvC+m8ZTfyhn7tKQOazAfBgNVHSMEGDAWgBSckDGJlzLaJsdy698XH32gPDMp
czAUBgNVHREEDTALgglsZWFmLXRlc3QwCgYIKoZIzj0EAwIDSAAwRQIhAPmertx0
lchRU3kAu647exvlhEr1xosPOu6P8kVYbtTEAiAA51w9EYIT/Zb26M3eQV817T2g
Dnhl0ElPQsA92pkqbA==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBtjCCAVygAwIBAgIQNr+f4IkABY2n4wx4sLOMrTAKBggqhkjOPQQDAjAUMRIw
EAYDVQQDEwlyb290LXRlc3QwIBcNMTkxMDAyMDI0MDM0WhgPMjExOTA5MDgwMjQw
MzJaMBwxGjAYBgNVBAMTEWludGVybWVkaWF0ZS10ZXN0MFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAEflfRhPjgJXv4zsPWahXjM2UU61aRFErN0iw88ZPyxea22fxl
qN9ezntTXxzsS+mZiWapl8B40ACJgvP+WLQBHKOBhTCBgjAOBgNVHQ8BAf8EBAMC
AQYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUnJAxiZcy2ibHcuvfFx99
oDwzKXMwHwYDVR0jBBgwFoAUpHS7FfaQ5bCrTxUeu6R2ZC3VGOowHAYDVR0RBBUw
E4IRaW50ZXJtZWRpYXRlLXRlc3QwCgYIKoZIzj0EAwIDSAAwRQIgII8XpQ8ezDO1
2xdq3hShf155C5X/5jO8qr0VyEJgzlkCIQCTqph1Gwu/dmuf6dYLCfQqJyb371LC
lgsqsR63is+0YQ==
-----END CERTIFICATE-----`))
			assert.FatalError(t, err)
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			p, err := generateX5C(nil)
			assert.FatalError(t, err)

			tok, err := generateToken("", p.Name, testAudiences.Sign[0], "",
				[]string{"test.smallstep.com"}, time.Now(), jwk,
				withX5CHdr(certs))
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("x5c.authorizeToken; certificate used to sign x5c token cannot be used for digital signature"),
			}
		},
		"fail/signature-does-not-match-x5c-pub-key": func(t *testing.T) test {
			certs, err := parseCerts([]byte(`-----BEGIN CERTIFICATE-----
MIIBuDCCAV+gAwIBAgIQFdu723gqgGaTaqjf6ny88zAKBggqhkjOPQQDAjAcMRow
GAYDVQQDExFpbnRlcm1lZGlhdGUtdGVzdDAgFw0xOTEwMDIwMzE4NTNaGA8yMTE5
MDkwODAzMTg1MVowFDESMBAGA1UEAxMJbGVhZi10ZXN0MFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAEaV6807GhWEtMxA39zjuMVHAiN2/Ri5B1R1s+Y/8mlrKIvuvr
VpgSPXYruNRFduPWX564Abz/TDmb276JbKGeQqOBiDCBhTAOBgNVHQ8BAf8EBAMC
BaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBReMkPW
f4MNWdg7KN4xI4ZLJd0IJDAfBgNVHSMEGDAWgBSckDGJlzLaJsdy698XH32gPDMp
czAUBgNVHREEDTALgglsZWFmLXRlc3QwCgYIKoZIzj0EAwIDRwAwRAIgKYLKXpTN
wtvZZaIvDzq1p8MO/SZ8yI42Ot69dNk/QtkCIBSvg5PozYcfbvwkgX5SwsjfYu0Z
AvUgkUQ2G25NBRmX
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBtjCCAVygAwIBAgIQNr+f4IkABY2n4wx4sLOMrTAKBggqhkjOPQQDAjAUMRIw
EAYDVQQDEwlyb290LXRlc3QwIBcNMTkxMDAyMDI0MDM0WhgPMjExOTA5MDgwMjQw
MzJaMBwxGjAYBgNVBAMTEWludGVybWVkaWF0ZS10ZXN0MFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAEflfRhPjgJXv4zsPWahXjM2UU61aRFErN0iw88ZPyxea22fxl
qN9ezntTXxzsS+mZiWapl8B40ACJgvP+WLQBHKOBhTCBgjAOBgNVHQ8BAf8EBAMC
AQYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUnJAxiZcy2ibHcuvfFx99
oDwzKXMwHwYDVR0jBBgwFoAUpHS7FfaQ5bCrTxUeu6R2ZC3VGOowHAYDVR0RBBUw
E4IRaW50ZXJtZWRpYXRlLXRlc3QwCgYIKoZIzj0EAwIDSAAwRQIgII8XpQ8ezDO1
2xdq3hShf155C5X/5jO8qr0VyEJgzlkCIQCTqph1Gwu/dmuf6dYLCfQqJyb371LC
lgsqsR63is+0YQ==
-----END CERTIFICATE-----`))
			assert.FatalError(t, err)
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			p, err := generateX5C(nil)
			assert.FatalError(t, err)
			tok, err := generateToken("", "foobar", testAudiences.Sign[0], "",
				[]string{"test.smallstep.com"}, time.Now(), jwk,
				withX5CHdr(certs))
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("x5c.authorizeToken; error parsing x5c claims"),
			}
		},
		"fail/invalid-issuer": func(t *testing.T) test {
			p, err := generateX5C(nil)
			assert.FatalError(t, err)
			tok, err := generateToken("", "foobar", testAudiences.Sign[0], "",
				[]string{"test.smallstep.com"}, time.Now(), x5cJWK,
				withX5CHdr(x5cCerts))
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("x5c.authorizeToken; invalid x5c claims"),
			}
		},
		"fail/invalid-audience": func(t *testing.T) test {
			p, err := generateX5C(nil)
			assert.FatalError(t, err)
			tok, err := generateToken("", p.GetName(), "foobar", "",
				[]string{"test.smallstep.com"}, time.Now(), x5cJWK,
				withX5CHdr(x5cCerts))
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("x5c.authorizeToken; x5c token has invalid audience claim (aud)"),
			}
		},
		"fail/empty-subject": func(t *testing.T) test {
			p, err := generateX5C(nil)
			assert.FatalError(t, err)
			tok, err := generateToken("", p.GetName(), testAudiences.Sign[0], "",
				[]string{"test.smallstep.com"}, time.Now(), x5cJWK,
				withX5CHdr(x5cCerts))
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("x5c.authorizeToken; x5c token subject cannot be empty"),
			}
		},
		"ok": func(t *testing.T) test {
			p, err := generateX5C(nil)
			assert.FatalError(t, err)
			tok, err := generateToken("foo", p.GetName(), testAudiences.Sign[0], "",
				[]string{"test.smallstep.com"}, time.Now(), x5cJWK,
				withX5CHdr(x5cCerts))
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
			}
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tc := tt(t)
			if claims, err := tc.p.authorizeToken(tc.token, testAudiences.Sign); err != nil {
				if assert.NotNil(t, tc.err) {
					var sc render.StatusCodedError
					if assert.True(t, errors.As(err, &sc), "error does not implement StatusCodedError interface") {
						assert.Equals(t, sc.StatusCode(), tc.code)
					}
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.NotNil(t, claims)
					assert.NotNil(t, claims.chains)
				}
			}
		})
	}
}

func TestX5C_AuthorizeSign(t *testing.T) {
	certs, err := pemutil.ReadCertificateBundle("./testdata/certs/x5c-leaf.crt")
	assert.FatalError(t, err)
	jwk, err := jose.ReadKey("./testdata/secrets/x5c-leaf.key")
	assert.FatalError(t, err)

	type test struct {
		p     *X5C
		token string
		code  int
		err   error
		sans  []string
	}
	tests := map[string]func(*testing.T) test{
		"fail/invalid-token": func(t *testing.T) test {
			p, err := generateX5C(nil)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: "foo",
				code:  http.StatusUnauthorized,
				err:   errors.New("x5c.AuthorizeSign: x5c.authorizeToken; error parsing x5c token"),
			}
		},
		"ok/empty-sans": func(t *testing.T) test {
			p, err := generateX5C(nil)
			assert.FatalError(t, err)
			tok, err := generateToken("foo", p.GetName(), testAudiences.Sign[0], "",
				[]string{}, time.Now(), jwk,
				withX5CHdr(certs))
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				sans:  []string{"foo"},
			}
		},
		"ok/multi-sans": func(t *testing.T) test {
			p, err := generateX5C(nil)
			assert.FatalError(t, err)
			tok, err := generateToken("foo", p.GetName(), testAudiences.Sign[0], "",
				[]string{"127.0.0.1", "foo", "max@smallstep.com"}, time.Now(), jwk,
				withX5CHdr(certs))
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				sans:  []string{"127.0.0.1", "foo", "max@smallstep.com"},
			}
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tc := tt(t)
			if opts, err := tc.p.AuthorizeSign(context.Background(), tc.token); err != nil {
				if assert.NotNil(t, tc.err) {
					var sc render.StatusCodedError
					if assert.True(t, errors.As(err, &sc), "error does not implement StatusCodedError interface") {
						assert.Equals(t, sc.StatusCode(), tc.code)
					}
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					if assert.NotNil(t, opts) {
						assert.Equals(t, 10, len(opts))
						for _, o := range opts {
							switch v := o.(type) {
							case *X5C:
							case certificateOptionsFunc:
							case *provisionerExtensionOption:
								assert.Equals(t, v.Type, TypeX5C)
								assert.Equals(t, v.Name, tc.p.GetName())
								assert.Equals(t, v.CredentialID, "")
								assert.Len(t, 0, v.KeyValuePairs)
							case profileLimitDuration:
								assert.Equals(t, v.def, tc.p.ctl.Claimer.DefaultTLSCertDuration())
								claims, err := tc.p.authorizeToken(tc.token, tc.p.ctl.Audiences.Sign)
								assert.FatalError(t, err)
								assert.Equals(t, v.notAfter, claims.chains[0][0].NotAfter)
							case commonNameValidator:
								assert.Equals(t, string(v), "foo")
							case defaultPublicKeyValidator:
							case defaultSANsValidator:
								assert.Equals(t, []string(v), tc.sans)
							case *validityValidator:
								assert.Equals(t, v.min, tc.p.ctl.Claimer.MinTLSCertDuration())
								assert.Equals(t, v.max, tc.p.ctl.Claimer.MaxTLSCertDuration())
							case *x509NamePolicyValidator:
								assert.Equals(t, nil, v.policyEngine)
							case *WebhookController:
								assert.Len(t, 0, v.webhooks)
							default:
								assert.FatalError(t, fmt.Errorf("unexpected sign option of type %T", v))
							}
						}
					}
				}
			}
		})
	}
}

func TestX5C_AuthorizeRevoke(t *testing.T) {
	type test struct {
		p     *X5C
		token string
		code  int
		err   error
	}
	tests := map[string]func(*testing.T) test{
		"fail/invalid-token": func(t *testing.T) test {
			p, err := generateX5C(nil)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: "foo",
				code:  http.StatusUnauthorized,
				err:   errors.New("x5c.AuthorizeRevoke: x5c.authorizeToken; error parsing x5c token"),
			}
		},
		"ok": func(t *testing.T) test {
			certs, err := pemutil.ReadCertificateBundle("./testdata/certs/x5c-leaf.crt")
			assert.FatalError(t, err)
			jwk, err := jose.ReadKey("./testdata/secrets/x5c-leaf.key")
			assert.FatalError(t, err)

			p, err := generateX5C(nil)
			assert.FatalError(t, err)
			tok, err := generateToken("foo", p.GetName(), testAudiences.Revoke[0], "",
				[]string{"test.smallstep.com"}, time.Now(), jwk,
				withX5CHdr(certs))
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
			}
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tc := tt(t)
			if err := tc.p.AuthorizeRevoke(context.Background(), tc.token); err != nil {
				if assert.NotNil(t, tc.err) {
					var sc render.StatusCodedError
					if assert.True(t, errors.As(err, &sc), "error does not implement StatusCodedError interface") {
						assert.Equals(t, sc.StatusCode(), tc.code)
					}
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

func TestX5C_AuthorizeRenew(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	type test struct {
		p    *X5C
		code int
		err  error
	}
	tests := map[string]func(*testing.T) test{
		"fail/renew-disabled": func(t *testing.T) test {
			p, err := generateX5C(nil)
			assert.FatalError(t, err)
			// disable renewal
			disable := true
			p.Claims = &Claims{DisableRenewal: &disable}
			p.ctl.Claimer, err = NewClaimer(p.Claims, globalProvisionerClaims)
			assert.FatalError(t, err)
			return test{
				p:    p,
				code: http.StatusUnauthorized,
				err:  fmt.Errorf("renew is disabled for provisioner '%s'", p.GetName()),
			}
		},
		"ok": func(t *testing.T) test {
			p, err := generateX5C(nil)
			assert.FatalError(t, err)
			return test{
				p: p,
			}
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tc := tt(t)
			if err := tc.p.AuthorizeRenew(context.Background(), &x509.Certificate{
				NotBefore: now,
				NotAfter:  now.Add(time.Hour),
			}); err != nil {
				if assert.NotNil(t, tc.err) {
					var sc render.StatusCodedError
					if assert.True(t, errors.As(err, &sc), "error does not implement StatusCodedError interface") {
						assert.Equals(t, sc.StatusCode(), tc.code)
					}
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

func TestX5C_AuthorizeSSHSign(t *testing.T) {
	x5cCerts, err := pemutil.ReadCertificateBundle("./testdata/certs/x5c-leaf.crt")
	assert.FatalError(t, err)
	x5cJWK, err := jose.ReadKey("./testdata/secrets/x5c-leaf.key")
	assert.FatalError(t, err)

	_, fn := mockNow()
	defer fn()
	type test struct {
		p      *X5C
		token  string
		claims *x5cPayload
		code   int
		err    error
	}
	tests := map[string]func(*testing.T) test{
		"fail/sshCA-disabled": func(t *testing.T) test {
			p, err := generateX5C(nil)
			assert.FatalError(t, err)
			// disable sshCA
			enable := false
			p.Claims = &Claims{EnableSSHCA: &enable}
			p.ctl.Claimer, err = NewClaimer(p.Claims, globalProvisionerClaims)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: "foo",
				code:  http.StatusUnauthorized,
				err:   fmt.Errorf("x5c.AuthorizeSSHSign; sshCA is disabled for x5c provisioner '%s'", p.GetName()),
			}
		},
		"fail/invalid-token": func(t *testing.T) test {
			p, err := generateX5C(nil)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: "foo",
				code:  http.StatusUnauthorized,
				err:   errors.New("x5c.AuthorizeSSHSign: x5c.authorizeToken; error parsing x5c token"),
			}
		},
		"fail/no-Step-claim": func(t *testing.T) test {
			p, err := generateX5C(nil)
			assert.FatalError(t, err)
			tok, err := generateToken("foo", p.GetName(), testAudiences.SSHSign[0], "",
				[]string{"test.smallstep.com"}, time.Now(), x5cJWK,
				withX5CHdr(x5cCerts))
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("x5c.AuthorizeSSHSign; x5c token must be an SSH provisioning token"),
			}
		},
		"fail/no-SSH-subattribute-in-claims": func(t *testing.T) test {
			p, err := generateX5C(nil)
			assert.FatalError(t, err)

			id, err := randutil.ASCII(64)
			assert.FatalError(t, err)
			now := time.Now()
			claims := &x5cPayload{
				Claims: jose.Claims{
					ID:        id,
					Subject:   "foo",
					Issuer:    p.GetName(),
					IssuedAt:  jose.NewNumericDate(now),
					NotBefore: jose.NewNumericDate(now),
					Expiry:    jose.NewNumericDate(now.Add(5 * time.Minute)),
					Audience:  []string{testAudiences.SSHSign[0]},
				},
				Step: &stepPayload{},
			}
			tok, err := generateX5CSSHToken(x5cJWK, claims, withX5CHdr(x5cCerts))
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("x5c.AuthorizeSSHSign; x5c token must be an SSH provisioning token"),
			}
		},
		"ok/with-claims": func(t *testing.T) test {
			p, err := generateX5C(nil)
			assert.FatalError(t, err)

			id, err := randutil.ASCII(64)
			assert.FatalError(t, err)
			now := time.Now()
			claims := &x5cPayload{
				Claims: jose.Claims{
					ID:        id,
					Subject:   "foo",
					Issuer:    p.GetName(),
					IssuedAt:  jose.NewNumericDate(now),
					NotBefore: jose.NewNumericDate(now),
					Expiry:    jose.NewNumericDate(now.Add(5 * time.Minute)),
					Audience:  []string{testAudiences.SSHSign[0]},
				},
				Step: &stepPayload{SSH: &SignSSHOptions{
					CertType:    SSHHostCert,
					KeyID:       "foo",
					Principals:  []string{"max", "mariano", "alan"},
					ValidAfter:  TimeDuration{d: 5 * time.Minute},
					ValidBefore: TimeDuration{d: 10 * time.Minute},
				}},
			}
			tok, err := generateX5CSSHToken(x5cJWK, claims, withX5CHdr(x5cCerts))
			assert.FatalError(t, err)
			return test{
				p:      p,
				claims: claims,
				token:  tok,
			}
		},
		"ok/without-claims": func(t *testing.T) test {
			p, err := generateX5C(nil)
			assert.FatalError(t, err)

			id, err := randutil.ASCII(64)
			assert.FatalError(t, err)
			now := time.Now()
			claims := &x5cPayload{
				Claims: jose.Claims{
					ID:        id,
					Subject:   "foo",
					Issuer:    p.GetName(),
					IssuedAt:  jose.NewNumericDate(now),
					NotBefore: jose.NewNumericDate(now),
					Expiry:    jose.NewNumericDate(now.Add(5 * time.Minute)),
					Audience:  []string{testAudiences.SSHSign[0]},
				},
				Step: &stepPayload{SSH: &SignSSHOptions{}},
			}
			tok, err := generateX5CSSHToken(x5cJWK, claims, withX5CHdr(x5cCerts))
			assert.FatalError(t, err)
			return test{
				p:      p,
				claims: claims,
				token:  tok,
			}
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tc := tt(t)
			if opts, err := tc.p.AuthorizeSSHSign(context.Background(), tc.token); err != nil {
				if assert.NotNil(t, tc.err) {
					var sc render.StatusCodedError
					if assert.True(t, errors.As(err, &sc), "error does not implement StatusCodedError interface") {
						assert.Equals(t, sc.StatusCode(), tc.code)
					}
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					if assert.NotNil(t, opts) {
						tot := 0
						firstValidator := true
						nw := now()
						for _, o := range opts {
							switch v := o.(type) {
							case Interface:
							case sshCertOptionsValidator:
								tc.claims.Step.SSH.ValidAfter.t = time.Time{}
								tc.claims.Step.SSH.ValidBefore.t = time.Time{}
								if firstValidator {
									assert.Equals(t, SignSSHOptions(v), *tc.claims.Step.SSH)
								} else {
									assert.Equals(t, SignSSHOptions(v), SignSSHOptions{KeyID: tc.claims.Subject})
								}
								firstValidator = false
							case sshCertValidAfterModifier:
								assert.Equals(t, int64(v), tc.claims.Step.SSH.ValidAfter.RelativeTime(nw).Unix())
							case sshCertValidBeforeModifier:
								assert.Equals(t, int64(v), tc.claims.Step.SSH.ValidBefore.RelativeTime(nw).Unix())
							case sshCertDefaultsModifier:
								assert.Equals(t, SignSSHOptions(v), SignSSHOptions{CertType: SSHUserCert})
							case *sshLimitDuration:
								assert.Equals(t, v.Claimer, tc.p.ctl.Claimer)
								assert.Equals(t, v.NotAfter, x5cCerts[0].NotAfter)
							case *sshCertValidityValidator:
								assert.Equals(t, v.Claimer, tc.p.ctl.Claimer)
							case *sshNamePolicyValidator:
								assert.Equals(t, nil, v.userPolicyEngine)
								assert.Equals(t, nil, v.hostPolicyEngine)
							case *sshDefaultPublicKeyValidator, *sshCertDefaultValidator, sshCertificateOptionsFunc:
							case *WebhookController:
								assert.Len(t, 0, v.webhooks)
							default:
								assert.FatalError(t, fmt.Errorf("unexpected sign option of type %T", v))
							}
							tot++
						}
						if len(tc.claims.Step.SSH.CertType) > 0 {
							assert.Equals(t, tot, 12)
						} else {
							assert.Equals(t, tot, 10)
						}
					}
				}
			}
		})
	}
}
