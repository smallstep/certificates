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
		"fail-empty-name": func(t *testing.T) ProvisionerValidateTest {
			return ProvisionerValidateTest{
				p:   &JWK{},
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

func TestJWK_Authorize(t *testing.T) {
	p1, err := generateJWK()
	assert.FatalError(t, err)
	p2, err := generateJWK()
	assert.FatalError(t, err)

	key1, err := decryptJSONWebKey(p1.EncryptedKey)
	assert.FatalError(t, err)
	key2, err := decryptJSONWebKey(p2.EncryptedKey)
	assert.FatalError(t, err)

	t1, err := generateSimpleToken(p1.Name, testAudiences[0], key1)
	assert.FatalError(t, err)
	t2, err := generateSimpleToken(p2.Name, testAudiences[1], key2)
	assert.FatalError(t, err)
	t3, err := generateToken("test.smallstep.com", p1.Name, testAudiences[0], []string{}, key1)
	assert.FatalError(t, err)

	// Invalid tokens
	parts := strings.Split(t1, ".")
	// invalid token
	failTok := "foo." + parts[1] + "." + parts[2]
	// invalid claims
	failClaims := parts[0] + ".foo." + parts[1]
	// invalid issuer
	failIss, err := generateSimpleToken("foobar", testAudiences[0], key1)
	assert.FatalError(t, err)
	// invalid audience
	failAud, err := generateSimpleToken(p1.Name, "foobar", key1)
	assert.FatalError(t, err)
	// invalid signature
	failSig := t1[0 : len(t1)-2]
	// no subject
	failSub, err := generateToken("", p1.Name, testAudiences[0], []string{"test.smallstep.com"}, key1)
	assert.FatalError(t, err)

	// Remove encrypted key for p2
	p2.EncryptedKey = ""

	type args struct {
		token string
	}
	tests := []struct {
		name    string
		prov    *JWK
		args    args
		wantErr bool
	}{
		{"ok", p1, args{t1}, false},
		{"ok-no-encrypted-key", p2, args{t2}, false},
		{"ok-no-sans", p1, args{t3}, false},
		{"fail-token", p1, args{failTok}, true},
		{"fail-claims", p1, args{failClaims}, true},
		{"fail-issuer", p1, args{failIss}, true},
		{"fail-audience", p1, args{failAud}, true},
		{"fail-signature", p1, args{failSig}, true},
		{"fail-subject", p1, args{failSub}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.prov.Authorize(tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("JWK.Authorize() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				assert.Nil(t, got)
			} else {
				assert.NotNil(t, got)
				assert.Len(t, 6, got)
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
	p2.Claims = &Claims{
		globalClaims:   &globalProvisionerClaims,
		DisableRenewal: &disable,
	}

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

func TestJWK_AuthorizeRevoke(t *testing.T) {
	p1, err := generateJWK()
	assert.FatalError(t, err)
	key1, err := decryptJSONWebKey(p1.EncryptedKey)
	assert.FatalError(t, err)
	t1, err := generateSimpleToken(p1.Name, testAudiences[0], key1)
	assert.FatalError(t, err)

	type args struct {
		token string
	}
	tests := []struct {
		name    string
		prov    *JWK
		args    args
		wantErr bool
	}{
		{"disabled", p1, args{t1}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.prov.AuthorizeRevoke(tt.args.token); (err != nil) != tt.wantErr {
				t.Errorf("JWK.AuthorizeRevoke() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
