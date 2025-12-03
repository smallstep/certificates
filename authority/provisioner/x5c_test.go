package provisioner

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/smallstep/linkedca"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/randutil"

	"github.com/smallstep/certificates/api/render"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func assertHasPrefix(t *testing.T, s, p string) bool {
	t.Helper()
	return assert.True(t, strings.HasPrefix(s, p), "%q is not a prefix of %q", p, s)
}

func TestX5C_Getters(t *testing.T) {
	p, err := generateX5C(nil)
	require.NoError(t, err)
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
			require.NoError(t, err)
			p.Claims = &Claims{DefaultTLSDur: &Duration{0}}
			return ProvisionerValidateTest{
				p:   p,
				err: errors.New("claims: MinTLSCertDuration must be greater than 0"),
			}
		},
		"ok": func(t *testing.T) ProvisionerValidateTest {
			p, err := generateX5C(nil)
			require.NoError(t, err)
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
			require.NoError(t, err)
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
					assert.EqualError(t, tc.err, err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equal(t, *tc.p.ctl.Audiences, config.Audiences.WithFragment(tc.p.GetID()))
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
	require.NoError(t, err)
	x5cJWK, err := jose.ReadKey("./testdata/secrets/x5c-leaf.key")
	require.NoError(t, err)

	type test struct {
		p     *X5C
		token string
		code  int
		err   error
	}
	tests := map[string]func(*testing.T) test{
		"fail/bad-token": func(t *testing.T) test {
			p, err := generateX5C(nil)
			require.NoError(t, err)
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
			require.NoError(t, err)
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			require.NoError(t, err)
			p, err := generateX5C(nil)
			require.NoError(t, err)
			tok, err := generateToken("", p.Name, testAudiences.Sign[0], "",
				[]string{"test.smallstep.com"}, time.Now(), jwk,
				withX5CHdr(certs))
			require.NoError(t, err)
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
			require.NoError(t, err)
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			require.NoError(t, err)
			p, err := generateX5C(nil)
			require.NoError(t, err)
			tok, err := generateToken("", p.Name, testAudiences.Sign[0], "",
				[]string{"test.smallstep.com"}, time.Now(), jwk,
				withX5CHdr(certs))
			require.NoError(t, err)
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
			require.NoError(t, err)
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			require.NoError(t, err)
			p, err := generateX5C(nil)
			require.NoError(t, err)

			tok, err := generateToken("", p.Name, testAudiences.Sign[0], "",
				[]string{"test.smallstep.com"}, time.Now(), jwk,
				withX5CHdr(certs))
			require.NoError(t, err)
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
			require.NoError(t, err)
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			require.NoError(t, err)
			p, err := generateX5C(nil)
			require.NoError(t, err)
			tok, err := generateToken("", "foobar", testAudiences.Sign[0], "",
				[]string{"test.smallstep.com"}, time.Now(), jwk,
				withX5CHdr(certs))
			require.NoError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("x5c.authorizeToken; error parsing x5c claims"),
			}
		},
		"fail/invalid-issuer": func(t *testing.T) test {
			p, err := generateX5C(nil)
			require.NoError(t, err)
			tok, err := generateToken("", "foobar", testAudiences.Sign[0], "",
				[]string{"test.smallstep.com"}, time.Now(), x5cJWK,
				withX5CHdr(x5cCerts))
			require.NoError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("x5c.authorizeToken; invalid x5c claims"),
			}
		},
		"fail/invalid-audience": func(t *testing.T) test {
			p, err := generateX5C(nil)
			require.NoError(t, err)
			tok, err := generateToken("", p.GetName(), "foobar", "",
				[]string{"test.smallstep.com"}, time.Now(), x5cJWK,
				withX5CHdr(x5cCerts))
			require.NoError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("x5c.authorizeToken; x5c token has invalid audience claim (aud)"),
			}
		},
		"fail/empty-subject": func(t *testing.T) test {
			p, err := generateX5C(nil)
			require.NoError(t, err)
			tok, err := generateToken("", p.GetName(), testAudiences.Sign[0], "",
				[]string{"test.smallstep.com"}, time.Now(), x5cJWK,
				withX5CHdr(x5cCerts))
			require.NoError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("x5c.authorizeToken; x5c token subject cannot be empty"),
			}
		},
		"ok": func(t *testing.T) test {
			p, err := generateX5C(nil)
			require.NoError(t, err)
			tok, err := generateToken("foo", p.GetName(), testAudiences.Sign[0], "",
				[]string{"test.smallstep.com"}, time.Now(), x5cJWK,
				withX5CHdr(x5cCerts))
			require.NoError(t, err)
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
						assert.Equal(t, tc.code, sc.StatusCode())
					}
					assertHasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.NoError(t, tc.err) {
					assert.NotNil(t, claims)
					assert.NotNil(t, claims.chains)
				}
			}
		})
	}
}

func TestX5C_AuthorizeSign(t *testing.T) {
	certs, err := pemutil.ReadCertificateBundle("./testdata/certs/x5c-leaf.crt")
	require.NoError(t, err)
	jwk, err := jose.ReadKey("./testdata/secrets/x5c-leaf.key")
	require.NoError(t, err)

	type test struct {
		p           *X5C
		token       string
		code        int
		err         error
		sans        []string
		fingerprint string
	}
	tests := map[string]func(*testing.T) test{
		"fail/invalid-token": func(t *testing.T) test {
			p, err := generateX5C(nil)
			require.NoError(t, err)
			return test{
				p:     p,
				token: "foo",
				code:  http.StatusUnauthorized,
				err:   errors.New("x5c.AuthorizeSign: x5c.authorizeToken; error parsing x5c token"),
			}
		},
		"ok/empty-sans": func(t *testing.T) test {
			p, err := generateX5C(nil)
			require.NoError(t, err)
			tok, err := generateToken("foo", p.GetName(), testAudiences.Sign[0], "",
				[]string{}, time.Now(), jwk,
				withX5CHdr(certs))
			require.NoError(t, err)
			return test{
				p:     p,
				token: tok,
				sans:  []string{"foo"},
			}
		},
		"ok/multi-sans": func(t *testing.T) test {
			p, err := generateX5C(nil)
			require.NoError(t, err)
			tok, err := generateToken("foo", p.GetName(), testAudiences.Sign[0], "",
				[]string{"127.0.0.1", "foo", "max@smallstep.com"}, time.Now(), jwk,
				withX5CHdr(certs))
			require.NoError(t, err)
			return test{
				p:     p,
				token: tok,
				sans:  []string{"127.0.0.1", "foo", "max@smallstep.com"},
			}
		},
		"ok/cnf": func(t *testing.T) test {
			p, err := generateX5C(nil)
			require.NoError(t, err)

			x5c := make([]string, len(certs))
			for i, cert := range certs {
				x5c[i] = base64.StdEncoding.EncodeToString(cert.Raw)
			}
			extraHeaders := map[string]any{"x5c": x5c}
			extraClaims := map[string]any{
				"sans": []string{"127.0.0.1", "foo", "max@smallstep.com"},
				"cnf":  map[string]any{"x5rt#S256": "fingerprint"},
			}

			tok, err := generateCustomToken("foo", p.GetName(), testAudiences.Sign[0], jwk, extraHeaders, extraClaims)
			require.NoError(t, err)
			return test{
				p:           p,
				token:       tok,
				sans:        []string{"127.0.0.1", "foo", "max@smallstep.com"},
				fingerprint: "fingerprint",
			}
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tc := tt(t)
			ctx := NewContextWithMethod(context.Background(), SignIdentityMethod)
			if opts, err := tc.p.AuthorizeSign(ctx, tc.token); err != nil {
				if assert.NotNil(t, tc.err, err.Error()) {
					var sc render.StatusCodedError
					if assert.True(t, errors.As(err, &sc), "error does not implement StatusCodedError interface") {
						assert.Equal(t, tc.code, sc.StatusCode())
					}
					assertHasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					if assert.NotNil(t, opts) {
						assert.Len(t, opts, 11)
						for _, o := range opts {
							switch v := o.(type) {
							case *X5C:
							case certificateOptionsFunc:
							case *provisionerExtensionOption:
								assert.Equal(t, TypeX5C, v.Type)
								assert.Equal(t, tc.p.GetName(), v.Name)
								assert.Equal(t, "", v.CredentialID)
								assert.Len(t, v.KeyValuePairs, 0)
							case profileLimitDuration:
								assert.Equal(t, tc.p.ctl.Claimer.DefaultTLSCertDuration(), v.def)
								claims, err := tc.p.authorizeToken(tc.token, tc.p.ctl.Audiences.Sign)
								require.NoError(t, err)
								assert.Equal(t, claims.chains[0][0].NotAfter, v.notAfter)
							case commonNameValidator:
								assert.Equal(t, "foo", string(v))
							case defaultPublicKeyValidator:
							case *defaultSANsValidator:
								assert.Equal(t, tc.sans, v.sans)
								assert.Equal(t, SignIdentityMethod, MethodFromContext(v.ctx))
							case *validityValidator:
								assert.Equal(t, tc.p.ctl.Claimer.MinTLSCertDuration(), v.min)
								assert.Equal(t, tc.p.ctl.Claimer.MaxTLSCertDuration(), v.max)
							case *x509NamePolicyValidator:
								assert.Equal(t, nil, v.policyEngine)
							case *WebhookController:
								assert.Len(t, v.webhooks, 0)
								assert.Equal(t, linkedca.Webhook_X509, v.certType)
								assert.Len(t, v.options, 2)
							case csrFingerprintValidator:
								assert.Equal(t, tc.fingerprint, string(v))
							default:
								require.NoError(t, fmt.Errorf("unexpected sign option of type %T", v))
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
			require.NoError(t, err)
			return test{
				p:     p,
				token: "foo",
				code:  http.StatusUnauthorized,
				err:   errors.New("x5c.AuthorizeRevoke: x5c.authorizeToken; error parsing x5c token"),
			}
		},
		"ok": func(t *testing.T) test {
			certs, err := pemutil.ReadCertificateBundle("./testdata/certs/x5c-leaf.crt")
			require.NoError(t, err)
			serialNumber := certs[0].SerialNumber.String()
			jwk, err := jose.ReadKey("./testdata/secrets/x5c-leaf.key")
			require.NoError(t, err)

			p, err := generateX5C(nil)
			require.NoError(t, err)
			tok, err := generateToken(serialNumber, p.GetName(), testAudiences.Revoke[0], "",
				[]string{"test.smallstep.com"}, time.Now(), jwk,
				withX5CHdr(certs))
			require.NoError(t, err)
			return test{
				p:     p,
				token: tok,
			}
		},
		"ok/different-serial-number": func(t *testing.T) test {
			certs, err := pemutil.ReadCertificateBundle("./testdata/certs/x5c-leaf.crt")
			require.NoError(t, err)
			jwk, err := jose.ReadKey("./testdata/secrets/x5c-leaf.key")
			require.NoError(t, err)

			p, err := generateX5C(nil)
			require.NoError(t, err)
			tok, err := generateToken("123456789", p.GetName(), testAudiences.Revoke[0], "",
				[]string{"test.smallstep.com"}, time.Now(), jwk,
				withX5CHdr(certs))
			require.NoError(t, err)
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
						assert.Equal(t, tc.code, sc.StatusCode())
					}
					assertHasPrefix(t, err.Error(), tc.err.Error())
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
			require.NoError(t, err)
			// disable renewal
			disable := true
			p.Claims = &Claims{DisableRenewal: &disable}
			p.ctl.Claimer, err = NewClaimer(p.Claims, globalProvisionerClaims)
			require.NoError(t, err)
			return test{
				p:    p,
				code: http.StatusUnauthorized,
				err:  fmt.Errorf("renew is disabled for provisioner '%s'", p.GetName()),
			}
		},
		"ok": func(t *testing.T) test {
			p, err := generateX5C(nil)
			require.NoError(t, err)
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
						assert.Equal(t, tc.code, sc.StatusCode())
					}
					assertHasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

func TestX5C_AuthorizeSSHSign(t *testing.T) {
	x5cCerts, err := pemutil.ReadCertificateBundle("./testdata/certs/x5c-leaf.crt")
	require.NoError(t, err)
	x5cJWK, err := jose.ReadKey("./testdata/secrets/x5c-leaf.key")
	require.NoError(t, err)

	_, fn := mockNow()
	defer fn()
	type test struct {
		p           *X5C
		token       string
		claims      *x5cPayload
		fingerprint string
		count       int
		code        int
		err         error
	}
	tests := map[string]func(*testing.T) test{
		"fail/sshCA-disabled": func(t *testing.T) test {
			p, err := generateX5C(nil)
			require.NoError(t, err)
			// disable sshCA
			enable := false
			p.Claims = &Claims{EnableSSHCA: &enable}
			p.ctl.Claimer, err = NewClaimer(p.Claims, globalProvisionerClaims)
			require.NoError(t, err)
			return test{
				p:     p,
				token: "foo",
				code:  http.StatusUnauthorized,
				err:   fmt.Errorf("x5c.AuthorizeSSHSign; sshCA is disabled for x5c provisioner '%s'", p.GetName()),
			}
		},
		"fail/invalid-token": func(t *testing.T) test {
			p, err := generateX5C(nil)
			require.NoError(t, err)
			return test{
				p:     p,
				token: "foo",
				code:  http.StatusUnauthorized,
				err:   errors.New("x5c.AuthorizeSSHSign: x5c.authorizeToken; error parsing x5c token"),
			}
		},
		"fail/no-Step-claim": func(t *testing.T) test {
			p, err := generateX5C(nil)
			require.NoError(t, err)
			tok, err := generateToken("foo", p.GetName(), testAudiences.SSHSign[0], "",
				[]string{"test.smallstep.com"}, time.Now(), x5cJWK,
				withX5CHdr(x5cCerts))
			require.NoError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("x5c.AuthorizeSSHSign; x5c token must be an SSH provisioning token"),
			}
		},
		"fail/no-SSH-subattribute-in-claims": func(t *testing.T) test {
			p, err := generateX5C(nil)
			require.NoError(t, err)

			id, err := randutil.ASCII(64)
			require.NoError(t, err)
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
			require.NoError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("x5c.AuthorizeSSHSign; x5c token must be an SSH provisioning token"),
			}
		},
		"ok/with-claims": func(t *testing.T) test {
			p, err := generateX5C(nil)
			require.NoError(t, err)

			id, err := randutil.ASCII(64)
			require.NoError(t, err)
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
					CertType:    SSHUserCert,
					KeyID:       "foo",
					Principals:  []string{"max", "mariano", "alan"},
					ValidAfter:  TimeDuration{d: 5 * time.Minute},
					ValidBefore: TimeDuration{d: 10 * time.Minute},
				}},
			}
			tok, err := generateX5CSSHToken(x5cJWK, claims, withX5CHdr(x5cCerts))
			require.NoError(t, err)
			return test{
				p:      p,
				claims: claims,
				token:  tok,
				count:  12,
			}
		},
		"ok/without-claims": func(t *testing.T) test {
			p, err := generateX5C(nil)
			require.NoError(t, err)

			id, err := randutil.ASCII(64)
			require.NoError(t, err)
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
			require.NoError(t, err)
			return test{
				p:      p,
				claims: claims,
				token:  tok,
				count:  10,
			}
		},
		"ok/cnf": func(t *testing.T) test {
			p, err := generateX5C(nil)
			require.NoError(t, err)

			id, err := randutil.ASCII(64)
			require.NoError(t, err)
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
					CertType:   SSHHostCert,
					Principals: []string{"host.smallstep.com"},
				}},
				Confirmation: &cnfPayload{
					Fingerprint: "fingerprint",
				},
			}
			tok, err := generateX5CSSHToken(x5cJWK, claims, withX5CHdr(x5cCerts))
			require.NoError(t, err)
			return test{
				p:           p,
				claims:      claims,
				token:       tok,
				fingerprint: "fingerprint",
				count:       10,
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
						assert.Equal(t, tc.code, sc.StatusCode())
					}
					assertHasPrefix(t, err.Error(), tc.err.Error())
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
									assert.Equal(t, *tc.claims.Step.SSH, SignSSHOptions(v))
								} else {
									assert.Equal(t, SignSSHOptions{KeyID: tc.claims.Subject}, SignSSHOptions(v))
								}
								firstValidator = false
							case sshCertValidAfterModifier:
								assert.Equal(t, tc.claims.Step.SSH.ValidAfter.RelativeTime(nw).Unix(), int64(v))
							case sshCertValidBeforeModifier:
								assert.Equal(t, tc.claims.Step.SSH.ValidBefore.RelativeTime(nw).Unix(), int64(v))
							case *sshLimitDuration:
								assert.Equal(t, tc.p.ctl.Claimer, v.Claimer)
								assert.Equal(t, x5cCerts[0].NotAfter, v.NotAfter)
							case *sshCertValidityValidator:
								assert.Equal(t, tc.p.ctl.Claimer, v.Claimer)
							case *sshNamePolicyValidator:
								assert.Nil(t, v.userPolicyEngine)
								assert.Nil(t, v.hostPolicyEngine)
							case *sshDefaultPublicKeyValidator, *sshCertDefaultValidator, sshCertificateOptionsFunc:
							case *WebhookController:
								assert.Len(t, v.webhooks, 0)
								assert.Equal(t, linkedca.Webhook_SSH, v.certType)
								assert.Len(t, v.options, 2)
							default:
								require.NoError(t, fmt.Errorf("unexpected sign option of type %T", v))
							}
							tot++
						}
						assert.Equal(t, tc.count, tot)
					}
				}
			}
		})
	}
}
