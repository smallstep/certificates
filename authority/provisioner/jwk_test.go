package provisioner

import (
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/smallstep/assert"
	"github.com/smallstep/cli/jose"
)

var (
	defaultDisableRenewal   = false
	globalProvisionerClaims = Claims{
		MinTLSDur:      &Duration{5 * time.Minute},
		MaxTLSDur:      &Duration{24 * time.Hour},
		DefaultTLSDur:  &Duration{24 * time.Hour},
		DisableRenewal: &defaultDisableRenewal,
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
			if got, err := tt.prov.AuthorizeSign(tt.args.token); err != nil {
				if assert.NotNil(t, tt.err) {
					assert.HasPrefix(t, err.Error(), tt.err.Error())
				}
			} else {
				if assert.NotNil(t, got) {
					assert.Len(t, 7, got)

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
