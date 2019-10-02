package provisioner

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/jose"
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
				p:   &X5C{Name: "foo", Type: "bar", Roots: []byte("foo"), audiences: testAudiences},
				err: errors.Errorf("no x509 certificates found in roots attribute for provisioner foo"),
			}
		},
		"fail/invalid-duration": func(t *testing.T) ProvisionerValidateTest {
			p, err := generateX5C(nil)
			assert.FatalError(t, err)
			p.Claims = &Claims{DefaultTLSDur: &Duration{0}}
			return ProvisionerValidateTest{
				p:   p,
				err: errors.New("claims: DefaultTLSCertDuration must be greater than 0"),
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
					numCerts := len(p.rootPool.Subjects())
					if numCerts != 2 {
						return errors.Errorf("unexpected number of certs: want 2, but got %d", numCerts)
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
					assert.Equals(t, tc.p.audiences, config.Audiences.WithFragment(tc.p.GetID()))
					if tc.extraValid != nil {
						assert.Nil(t, tc.extraValid(tc.p))
					}
				}
			}
		})
	}
}

func TestX5C_authorizeToken(t *testing.T) {
	type test struct {
		p     *X5C
		token string
		err   error
	}
	tests := map[string]func(*testing.T) test{
		"fail/bad-token": func(t *testing.T) test {
			p, err := generateX5C(nil)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: "foo",
				err:   errors.New("error parsing token"),
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
				err:   errors.New("error verifying x5c certificate chain: x509: certificate signed by unknown authority"),
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
				err:   errors.New("error verifying x5c certificate chain: x509: certificate signed by unknown authority"),
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
				err:   errors.New("certificate used to sign x5c token cannot be used for digital signature"),
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
				err:   errors.New("error parsing claims: square/go-jose: error in cryptographic primitive"),
			}
		},
		"fail/invalid-issuer": func(t *testing.T) test {
			certs, err := pemutil.ReadCertificateBundle("./testdata/x5c-leaf.crt")
			assert.FatalError(t, err)
			jwk, err := jose.ParseKey("./testdata/x5c-leaf.key")
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
				err:   errors.New("invalid token: square/go-jose/jwt: validation failed, invalid issuer claim (iss)"),
			}
		},
		"fail/invalid-audience": func(t *testing.T) test {
			certs, err := pemutil.ReadCertificateBundle("./testdata/x5c-leaf.crt")
			assert.FatalError(t, err)
			jwk, err := jose.ParseKey("./testdata/x5c-leaf.key")
			assert.FatalError(t, err)

			p, err := generateX5C(nil)
			assert.FatalError(t, err)
			tok, err := generateToken("", p.GetName(), "foobar", "",
				[]string{"test.smallstep.com"}, time.Now(), jwk,
				withX5CHdr(certs))
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				err:   errors.New("invalid token: invalid audience claim (aud)"),
			}
		},
		"fail/empty-subject": func(t *testing.T) test {
			certs, err := pemutil.ReadCertificateBundle("./testdata/x5c-leaf.crt")
			assert.FatalError(t, err)
			jwk, err := jose.ParseKey("./testdata/x5c-leaf.key")
			assert.FatalError(t, err)

			p, err := generateX5C(nil)
			assert.FatalError(t, err)
			tok, err := generateToken("", p.GetName(), testAudiences.Sign[0], "",
				[]string{"test.smallstep.com"}, time.Now(), jwk,
				withX5CHdr(certs))
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				err:   errors.New("token subject cannot be empty"),
			}
		},
		"ok": func(t *testing.T) test {
			certs, err := pemutil.ReadCertificateBundle("./testdata/x5c-leaf.crt")
			assert.FatalError(t, err)
			jwk, err := jose.ParseKey("./testdata/x5c-leaf.key")
			assert.FatalError(t, err)

			p, err := generateX5C(nil)
			assert.FatalError(t, err)
			tok, err := generateToken("foo", p.GetName(), testAudiences.Sign[0], "",
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
			if claims, err := tc.p.authorizeToken(tc.token, testAudiences.Sign); err != nil {
				if assert.NotNil(t, tc.err) {
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

func TestX5C_AuthorizeReovke(t *testing.T) {
	type test struct {
		p     *X5C
		token string
		err   error
	}
	tests := map[string]func(*testing.T) test{
		"fail/invalid-token": func(t *testing.T) test {
			p, err := generateX5C(nil)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: "foo",
				err:   errors.New("error parsing token"),
			}
		},
		"ok": func(t *testing.T) test {
			certs, err := pemutil.ReadCertificateBundle("./testdata/x5c-leaf.crt")
			assert.FatalError(t, err)
			jwk, err := jose.ParseKey("./testdata/x5c-leaf.key")
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
			if err := tc.p.AuthorizeRevoke(tc.token); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

func TestX5C_AuthorizeRenewal(t *testing.T) {
	p1, err := generateX5C(nil)
	assert.FatalError(t, err)
	p2, err := generateX5C(nil)
	assert.FatalError(t, err)

	// disable renewal
	disable := true
	p2.Claims = &Claims{DisableRenewal: &disable}
	p2.claimer, err = NewClaimer(p2.Claims, globalProvisionerClaims)
	assert.FatalError(t, err)

	type args struct {
		cert *x509.Certificate
	}
	tests := []struct {
		name    string
		prov    *X5C
		args    args
		wantErr bool
	}{
		{"ok", p1, args{nil}, false},
		{"fail", p2, args{nil}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.prov.AuthorizeRenewal(tt.args.cert); (err != nil) != tt.wantErr {
				t.Errorf("X5C.AuthorizeRenewal() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
