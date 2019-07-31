package provisioner

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/smallstep/assert"
	"github.com/smallstep/cli/jose"
	"golang.org/x/crypto/ssh"
)

var (
	defaultDisableRenewal   = false
	globalProvisionerClaims = Claims{
		MinTLSDur:         &Duration{5 * time.Minute},
		MaxTLSDur:         &Duration{24 * time.Hour},
		DefaultTLSDur:     &Duration{24 * time.Hour},
		DisableRenewal:    &defaultDisableRenewal,
		MinUserSSHDur:     &Duration{Duration: 5 * time.Minute}, // User SSH certs
		MaxUserSSHDur:     &Duration{Duration: 24 * time.Hour},
		DefaultUserSSHDur: &Duration{Duration: 4 * time.Hour},
		MinHostSSHDur:     &Duration{Duration: 5 * time.Minute}, // Host SSH certs
		MaxHostSSHDur:     &Duration{Duration: 30 * 24 * time.Hour},
		DefaultHostSSHDur: &Duration{Duration: 30 * 24 * time.Hour},
	}
)

func TestJWK_Getters(t *testing.T) {
	p, err := generateJWK()
	assert.FatalError(t, err)
	if got := p.GetID(); got != p.Name+":"+p.Key.KeyID {
		t.Errorf("JWK.GetID() = %v, want %v:%v", got, p.Name, p.Key.KeyID)
	}
	if got := p.GetName(); got != p.Name {
		t.Errorf("JWK.GetName() = %v, want %v", got, p.Name)
	}
	if got := p.GetType(); got != TypeJWK {
		t.Errorf("JWK.GetType() = %v, want %v", got, TypeJWK)
	}
	kid, key, ok := p.GetEncryptedKey()
	if kid != p.Key.KeyID || key != p.EncryptedKey || ok == false {
		t.Errorf("JWK.GetEncryptedKey() = (%v, %v, %v), want (%v, %v, %v)",
			kid, key, ok, p.Key.KeyID, p.EncryptedKey, true)
	}
	p.EncryptedKey = ""
	kid, key, ok = p.GetEncryptedKey()
	if kid != p.Key.KeyID || key != "" || ok == true {
		t.Errorf("JWK.GetEncryptedKey() = (%v, %v, %v), want (%v, %v, %v)",
			kid, key, ok, p.Key.KeyID, "", false)
	}
}

func TestJWK_Init(t *testing.T) {
	type ProvisionerValidateTest struct {
		p   *JWK
		err error
	}
	tests := map[string]func(*testing.T) ProvisionerValidateTest{
		"fail-empty": func(t *testing.T) ProvisionerValidateTest {
			return ProvisionerValidateTest{
				p:   &JWK{},
				err: errors.New("provisioner type cannot be empty"),
			}
		},
		"fail-empty-name": func(t *testing.T) ProvisionerValidateTest {
			return ProvisionerValidateTest{
				p: &JWK{
					Type: "JWK",
				},
				err: errors.New("provisioner name cannot be empty"),
			}
		},
		"fail-empty-type": func(t *testing.T) ProvisionerValidateTest {
			return ProvisionerValidateTest{
				p:   &JWK{Name: "foo"},
				err: errors.New("provisioner type cannot be empty"),
			}
		},
		"fail-empty-key": func(t *testing.T) ProvisionerValidateTest {
			return ProvisionerValidateTest{
				p:   &JWK{Name: "foo", Type: "bar"},
				err: errors.New("provisioner key cannot be empty"),
			}
		},
		"fail-bad-claims": func(t *testing.T) ProvisionerValidateTest {
			return ProvisionerValidateTest{
				p:   &JWK{Name: "foo", Type: "bar", Key: &jose.JSONWebKey{}, audiences: testAudiences, Claims: &Claims{DefaultTLSDur: &Duration{0}}},
				err: errors.New("claims: DefaultTLSCertDuration must be greater than 0"),
			}
		},
		"ok": func(t *testing.T) ProvisionerValidateTest {
			return ProvisionerValidateTest{
				p: &JWK{Name: "foo", Type: "bar", Key: &jose.JSONWebKey{}, audiences: testAudiences},
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
				assert.Nil(t, tc.err)
			}
		})
	}
}

func TestJWK_authorizeToken(t *testing.T) {
	p1, err := generateJWK()
	assert.FatalError(t, err)
	p2, err := generateJWK()
	assert.FatalError(t, err)

	key1, err := decryptJSONWebKey(p1.EncryptedKey)
	assert.FatalError(t, err)
	key2, err := decryptJSONWebKey(p2.EncryptedKey)
	assert.FatalError(t, err)

	t1, err := generateSimpleToken(p1.Name, testAudiences.Sign[0], key1)
	assert.FatalError(t, err)
	t2, err := generateSimpleToken(p2.Name, testAudiences.Sign[1], key2)
	assert.FatalError(t, err)
	t3, err := generateToken("test.smallstep.com", p1.Name, testAudiences.Sign[0], "", []string{}, time.Now(), key1)
	assert.FatalError(t, err)

	// Invalid tokens
	parts := strings.Split(t1, ".")
	key3, err := generateJSONWebKey()
	assert.FatalError(t, err)
	// missing key
	failKey, err := generateSimpleToken(p1.Name, testAudiences.Sign[0], key3)
	assert.FatalError(t, err)
	// invalid token
	failTok := "foo." + parts[1] + "." + parts[2]
	// invalid claims
	failClaims := parts[0] + ".foo." + parts[1]
	// invalid issuer
	failIss, err := generateSimpleToken("foobar", testAudiences.Sign[0], key1)
	assert.FatalError(t, err)
	// invalid audience
	failAud, err := generateSimpleToken(p1.Name, "foobar", key1)
	assert.FatalError(t, err)
	// invalid signature
	failSig := t1[0 : len(t1)-2]
	// no subject
	failSub, err := generateToken("", p1.Name, testAudiences.Sign[0], "", []string{"test.smallstep.com"}, time.Now(), key1)
	assert.FatalError(t, err)
	// expired
	failExp, err := generateToken("subject", p1.Name, testAudiences.Sign[0], "", []string{"test.smallstep.com"}, time.Now().Add(-360*time.Second), key1)
	assert.FatalError(t, err)
	// not before
	failNbf, err := generateToken("subject", p1.Name, testAudiences.Sign[0], "", []string{"test.smallstep.com"}, time.Now().Add(360*time.Second), key1)
	assert.FatalError(t, err)

	// Remove encrypted key for p2
	p2.EncryptedKey = ""

	type args struct {
		token string
	}
	tests := []struct {
		name string
		prov *JWK
		args args
		err  error
	}{
		{"fail-token", p1, args{failTok}, errors.New("error parsing token")},
		{"fail-key", p1, args{failKey}, errors.New("error parsing claims")},
		{"fail-claims", p1, args{failClaims}, errors.New("error parsing claims")},
		{"fail-signature", p1, args{failSig}, errors.New("error parsing claims: square/go-jose: error in cryptographic primitive")},
		{"fail-issuer", p1, args{failIss}, errors.New("invalid token: square/go-jose/jwt: validation failed, invalid issuer claim (iss)")},
		{"fail-expired", p1, args{failExp}, errors.New("invalid token: square/go-jose/jwt: validation failed, token is expired (exp)")},
		{"fail-not-before", p1, args{failNbf}, errors.New("invalid token: square/go-jose/jwt: validation failed, token not valid yet (nbf)")},
		{"fail-audience", p1, args{failAud}, errors.New("invalid token: invalid audience claim (aud)")},
		{"fail-subject", p1, args{failSub}, errors.New("token subject cannot be empty")},
		{"ok", p1, args{t1}, nil},
		{"ok-no-encrypted-key", p2, args{t2}, nil},
		{"ok-no-sans", p1, args{t3}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := tt.prov.authorizeToken(tt.args.token, testAudiences.Sign); err != nil {
				if assert.NotNil(t, tt.err) {
					assert.HasPrefix(t, err.Error(), tt.err.Error())
				}
			} else {
				assert.Nil(t, tt.err)
				assert.NotNil(t, got)
			}
		})
	}
}

func TestJWK_AuthorizeRevoke(t *testing.T) {
	p1, err := generateJWK()
	assert.FatalError(t, err)
	key1, err := decryptJSONWebKey(p1.EncryptedKey)
	assert.FatalError(t, err)
	t1, err := generateSimpleToken(p1.Name, testAudiences.Revoke[0], key1)
	assert.FatalError(t, err)
	// invalid signature
	failSig := t1[0 : len(t1)-2]

	type args struct {
		token string
	}
	tests := []struct {
		name string
		prov *JWK
		args args
		err  error
	}{
		{"fail-signature", p1, args{failSig}, errors.New("error parsing claims: square/go-jose: error in cryptographic primitive")},
		{"ok", p1, args{t1}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.prov.AuthorizeRevoke(tt.args.token); err != nil {
				if assert.NotNil(t, tt.err) {
					assert.HasPrefix(t, err.Error(), tt.err.Error())
				}
			}
		})
	}
}

func TestJWK_AuthorizeSign(t *testing.T) {
	p1, err := generateJWK()
	assert.FatalError(t, err)
	key1, err := decryptJSONWebKey(p1.EncryptedKey)
	assert.FatalError(t, err)

	t1, err := generateSimpleToken(p1.Name, testAudiences.Sign[0], key1)
	assert.FatalError(t, err)

	t2, err := generateToken("subject", p1.Name, testAudiences.Sign[0], "name@smallstep.com", []string{}, time.Now(), key1)
	assert.FatalError(t, err)

	// invalid signature
	failSig := t1[0 : len(t1)-2]

	type args struct {
		token string
	}
	tests := []struct {
		name string
		prov *JWK
		args args
		err  error
	}{
		{"fail-signature", p1, args{failSig}, errors.New("error parsing claims: square/go-jose: error in cryptographic primitive")},
		{"ok-sans", p1, args{t1}, nil},
		{"ok-no-sans", p1, args{t2}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := NewContextWithMethod(context.Background(), SignMethod)
			if got, err := tt.prov.AuthorizeSign(ctx, tt.args.token); err != nil {
				if assert.NotNil(t, tt.err) {
					assert.HasPrefix(t, err.Error(), tt.err.Error())
				}
			} else {
				if assert.NotNil(t, got) {
					assert.Len(t, 6, got)

					_cnv := got[0]
					cnv, ok := _cnv.(commonNameValidator)
					assert.True(t, ok)
					assert.Equals(t, string(cnv), "subject")

					_dnv := got[1]
					dnv, ok := _dnv.(dnsNamesValidator)
					assert.True(t, ok)
					if tt.name == "ok-sans" {
						assert.Equals(t, []string(dnv), []string{"test.smallstep.com"})
					} else {
						assert.Equals(t, []string(dnv), []string{"subject"})
					}
				}
			}
		})
	}
}

func TestJWK_AuthorizeRenewal(t *testing.T) {
	p1, err := generateJWK()
	assert.FatalError(t, err)
	p2, err := generateJWK()
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
		prov    *JWK
		args    args
		wantErr bool
	}{
		{"ok", p1, args{nil}, false},
		{"fail", p2, args{nil}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.prov.AuthorizeRenewal(tt.args.cert); (err != nil) != tt.wantErr {
				t.Errorf("JWK.AuthorizeRenewal() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestJWK_AuthorizeSign_SSH(t *testing.T) {
	p1, err := generateJWK()
	assert.FatalError(t, err)
	jwk, err := decryptJSONWebKey(p1.EncryptedKey)
	assert.FatalError(t, err)

	iss, aud := p1.Name, testAudiences.Sign[0]

	t1, err := generateSimpleSSHUserToken(iss, aud, jwk)
	assert.FatalError(t, err)

	t2, err := generateSimpleSSHHostToken(iss, aud, jwk)
	assert.FatalError(t, err)

	// invalid signature
	failSig := t1[0 : len(t1)-2]

	key, err := generateJSONWebKey()
	assert.FatalError(t, err)

	signer, err := generateJSONWebKey()
	assert.FatalError(t, err)

	type args struct {
		token string
	}
	type expected struct {
		certType   uint32
		principals []string
	}
	tests := []struct {
		name     string
		prov     *JWK
		args     args
		expected expected
		err      error
	}{
		{"ok-user", p1, args{t1}, expected{ssh.UserCert, []string{"name"}}, nil},
		{"ok-host", p1, args{t2}, expected{ssh.HostCert, []string{"smallstep.com"}}, nil},
		{"fail-signature", p1, args{failSig}, expected{}, errors.New("error parsing claims: square/go-jose: error in cryptographic primitive")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := NewContextWithMethod(context.Background(), SignSSHMethod)
			if got, err := tt.prov.AuthorizeSign(ctx, tt.args.token); err != nil {
				if assert.NotNil(t, tt.err) {
					assert.HasPrefix(t, err.Error(), tt.err.Error())
				}
			} else if assert.NotNil(t, got) {
				cert, err := signSSHCertificate(key.Public().Key, SSHOptions{}, got, signer.Key.(crypto.Signer))
				assert.FatalError(t, err)
				assert.NotNil(t, cert.Signature)
				assert.Equals(t, tt.expected.certType, cert.CertType)
				assert.Equals(t, tt.expected.principals, cert.ValidPrincipals)
				if cert.CertType == ssh.UserCert {
					assert.Len(t, 5, cert.Extensions)
				} else {
					assert.Nil(t, cert.Extensions)
				}
			}
		})
	}
}

func TestJWK_AuthorizeSign_SSHOptions(t *testing.T) {
	p1, err := generateJWK()
	assert.FatalError(t, err)
	jwk, err := decryptJSONWebKey(p1.EncryptedKey)
	assert.FatalError(t, err)

	userDuration := p1.claimer.DefaultUserSSHCertDuration()
	hostDuration := p1.claimer.DefaultHostSSHCertDuration()

	now := time.Now()
	sub, iss, aud := "subject@smallstep.com", p1.Name, testAudiences.Sign[0]
	iat := now

	key, err := generateJSONWebKey()
	assert.FatalError(t, err)

	signer, err := generateJSONWebKey()
	assert.FatalError(t, err)

	type args struct {
		sub, iss, aud string
		iat           time.Time
		tokSSHOpts    *SSHOptions
		userSSHOpts   *SSHOptions
		jwk           *jose.JSONWebKey
	}
	type expected struct {
		certType    uint32
		principals  []string
		validAfter  time.Time
		validBefore time.Time
	}
	tests := []struct {
		name        string
		prov        *JWK
		args        args
		expected    expected
		wantErr     bool
		wantSignErr bool
	}{
		{"ok-user", p1, args{sub, iss, aud, iat, &SSHOptions{CertType: "user", Principals: []string{"name"}}, &SSHOptions{}, jwk}, expected{ssh.UserCert, []string{"name"}, now, now.Add(userDuration)}, false, false},
		{"ok-host", p1, args{sub, iss, aud, iat, &SSHOptions{CertType: "host", Principals: []string{"smallstep.com"}}, &SSHOptions{}, jwk}, expected{ssh.HostCert, []string{"smallstep.com"}, now, now.Add(hostDuration)}, false, false},
		{"ok-user-opts", p1, args{sub, iss, aud, iat, &SSHOptions{}, &SSHOptions{CertType: "user", Principals: []string{"name"}}, jwk}, expected{ssh.UserCert, []string{"name"}, now, now.Add(userDuration)}, false, false},
		{"ok-host-opts", p1, args{sub, iss, aud, iat, &SSHOptions{}, &SSHOptions{CertType: "host", Principals: []string{"smallstep.com"}}, jwk}, expected{ssh.HostCert, []string{"smallstep.com"}, now, now.Add(hostDuration)}, false, false},
		{"ok-user-mixed", p1, args{sub, iss, aud, iat, &SSHOptions{CertType: "user"}, &SSHOptions{Principals: []string{"name"}}, jwk}, expected{ssh.UserCert, []string{"name"}, now, now.Add(userDuration)}, false, false},
		{"ok-host-mixed", p1, args{sub, iss, aud, iat, &SSHOptions{Principals: []string{"smallstep.com"}}, &SSHOptions{CertType: "host"}, jwk}, expected{ssh.HostCert, []string{"smallstep.com"}, now, now.Add(hostDuration)}, false, false},
		{"ok-user-validAfter", p1, args{sub, iss, aud, iat, &SSHOptions{
			CertType: "user", Principals: []string{"name"},
		}, &SSHOptions{
			ValidAfter: NewTimeDuration(now.Add(-time.Hour)),
		}, jwk}, expected{ssh.UserCert, []string{"name"}, now.Add(-time.Hour), now.Add(userDuration - time.Hour)}, false, false},
		{"ok-user-validBefore", p1, args{sub, iss, aud, iat, &SSHOptions{
			CertType: "user", Principals: []string{"name"},
		}, &SSHOptions{
			ValidBefore: NewTimeDuration(now.Add(time.Hour)),
		}, jwk}, expected{ssh.UserCert, []string{"name"}, now, now.Add(time.Hour)}, false, false},
		{"ok-user-validAfter-validBefore", p1, args{sub, iss, aud, iat, &SSHOptions{
			CertType: "user", Principals: []string{"name"},
		}, &SSHOptions{
			ValidAfter: NewTimeDuration(now.Add(10 * time.Minute)), ValidBefore: NewTimeDuration(now.Add(time.Hour)),
		}, jwk}, expected{ssh.UserCert, []string{"name"}, now.Add(10 * time.Minute), now.Add(time.Hour)}, false, false},
		{"ok-user-match", p1, args{sub, iss, aud, iat, &SSHOptions{
			CertType: "user", Principals: []string{"name"}, ValidAfter: NewTimeDuration(now), ValidBefore: NewTimeDuration(now.Add(1 * time.Hour)),
		}, &SSHOptions{
			CertType: "user", Principals: []string{"name"}, ValidAfter: NewTimeDuration(now), ValidBefore: NewTimeDuration(now.Add(1 * time.Hour)),
		}, jwk}, expected{ssh.UserCert, []string{"name"}, now, now.Add(1 * time.Hour)}, false, false},
		{"fail-certType", p1, args{sub, iss, aud, iat, &SSHOptions{CertType: "user", Principals: []string{"name"}}, &SSHOptions{CertType: "host"}, jwk}, expected{}, false, true},
		{"fail-principals", p1, args{sub, iss, aud, iat, &SSHOptions{CertType: "user", Principals: []string{"name"}}, &SSHOptions{Principals: []string{"root"}}, jwk}, expected{}, false, true},
		{"fail-validAfter", p1, args{sub, iss, aud, iat, &SSHOptions{CertType: "user", Principals: []string{"name"}, ValidAfter: NewTimeDuration(now)}, &SSHOptions{ValidAfter: NewTimeDuration(now.Add(time.Hour))}, jwk}, expected{}, false, true},
		{"fail-validBefore", p1, args{sub, iss, aud, iat, &SSHOptions{CertType: "user", Principals: []string{"name"}, ValidBefore: NewTimeDuration(now.Add(time.Hour))}, &SSHOptions{ValidBefore: NewTimeDuration(now.Add(10 * time.Hour))}, jwk}, expected{}, false, true},
		{"fail-subject", p1, args{"", iss, aud, iat, &SSHOptions{CertType: "user", Principals: []string{"name"}}, &SSHOptions{}, jwk}, expected{}, true, false},
		{"fail-issuer", p1, args{sub, "invalid", aud, iat, &SSHOptions{CertType: "user", Principals: []string{"name"}}, &SSHOptions{}, jwk}, expected{}, true, false},
		{"fail-audience", p1, args{sub, iss, "invalid", iat, &SSHOptions{CertType: "user", Principals: []string{"name"}}, &SSHOptions{}, jwk}, expected{}, true, false},
		{"fail-expired", p1, args{sub, iss, aud, iat.Add(-6 * time.Minute), &SSHOptions{CertType: "user", Principals: []string{"name"}}, &SSHOptions{}, jwk}, expected{}, true, false},
		{"fail-notBefore", p1, args{sub, iss, aud, iat.Add(5 * time.Minute), &SSHOptions{CertType: "user", Principals: []string{"name"}}, &SSHOptions{}, jwk}, expected{}, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := NewContextWithMethod(context.Background(), SignSSHMethod)
			token, err := generateSSHToken(tt.args.sub, tt.args.iss, tt.args.aud, tt.args.iat, tt.args.tokSSHOpts, tt.args.jwk)
			assert.FatalError(t, err)
			if got, err := tt.prov.AuthorizeSign(ctx, token); (err != nil) != tt.wantErr {
				t.Errorf("JWK.AuthorizeSign() error = %v, wantErr %v", err, tt.wantErr)
			} else if !tt.wantErr && assert.NotNil(t, got) {
				var opts SSHOptions
				if tt.args.userSSHOpts != nil {
					opts = *tt.args.userSSHOpts
				}
				if cert, err := signSSHCertificate(key.Public().Key, opts, got, signer.Key.(crypto.Signer)); (err != nil) != tt.wantSignErr {
					t.Errorf("SignSSH error = %v, wantSignErr %v", err, tt.wantSignErr)
				} else if !tt.wantSignErr && assert.NotNil(t, cert) {
					assert.NotNil(t, cert.Signature)
					assert.NotNil(t, cert.SignatureKey)
					assert.Equals(t, tt.expected.certType, cert.CertType)
					assert.Equals(t, tt.expected.principals, cert.ValidPrincipals)
					assert.True(t, equalsUint64Delta(uint64(tt.expected.validAfter.Unix()), cert.ValidAfter, 60))
					assert.True(t, equalsUint64Delta(uint64(tt.expected.validBefore.Unix()), cert.ValidBefore, 60))
					if cert.CertType == ssh.UserCert {
						assert.Len(t, 5, cert.Extensions)
					} else {
						assert.Nil(t, cert.Extensions)
					}
				}
			}
		})
	}
}

func equalsUint64Delta(a, b uint64, delta uint64) bool {
	return math.Abs(float64(a)-float64(b)) <= float64(delta)
}
