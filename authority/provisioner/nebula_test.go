package provisioner

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/randutil"
	"go.step.sm/crypto/x25519"
	"go.step.sm/crypto/x509util"
)

func mustNebulaPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	require.NoError(t, err)
	return p
}

func mustNebulaCA(t *testing.T) (cert.Certificate, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	tbs := &cert.TBSCertificate{
		Version:   cert.Version1,
		Curve:     cert.Curve_CURVE25519,
		Name:      "TestCA",
		Groups:    []string{"test"},
		Networks:  []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")},
		NotBefore: time.Unix(now.Unix(), 0),
		NotAfter:  time.Unix(now.Add(10*time.Minute).Unix(), 0),
		PublicKey: pub,
		IsCA:      true,
	}
	nc, err := tbs.Sign(nil, cert.Curve_CURVE25519, priv)
	require.NoError(t, err)

	return nc, priv
}

func mustExpiredNebulaCA(t *testing.T) (cert.Certificate, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	tbs := &cert.TBSCertificate{
		Version:   cert.Version1,
		Curve:     cert.Curve_CURVE25519,
		Name:      "ExpiredTestCA",
		Groups:    []string{"expired"},
		Networks:  []netip.Prefix{netip.MustParsePrefix("10.2.0.0/16")},
		NotBefore: time.Unix(now.Add(-2*time.Hour).Unix(), 0),
		NotAfter:  time.Unix(now.Add(-1*time.Hour).Unix(), 0),
		PublicKey: pub,
		IsCA:      true,
	}
	nc, err := tbs.Sign(nil, cert.Curve_CURVE25519, priv)
	require.NoError(t, err)

	return nc, priv
}

func mustNebulaP256CA(t *testing.T) (cert.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecdhPriv, err := key.ECDH()
	require.NoError(t, err)

	now := time.Now()
	tbs := &cert.TBSCertificate{
		Version:   cert.Version1,
		Curve:     cert.Curve_P256,
		Name:      "TestCA",
		Groups:    []string{"test"},
		Networks:  []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")},
		NotBefore: time.Unix(now.Unix(), 0),
		NotAfter:  time.Unix(now.Add(10*time.Minute).Unix(), 0),
		PublicKey: ecdhPriv.PublicKey().Bytes(),
		IsCA:      true,
	}

	// For P256 CAs, Sign expects the raw 32-byte scalar as the key.
	nc, err := tbs.Sign(nil, cert.Curve_P256, key.D.FillBytes(make([]byte, 32)))
	require.NoError(t, err)
	return nc, key
}

func mustNebulaCert(t *testing.T, name string, network netip.Prefix, groups []string, ca cert.Certificate, signer ed25519.PrivateKey) (cert.Certificate, crypto.Signer) {
	t.Helper()

	pub, priv, err := x25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	t1 := time.Now().Truncate(time.Second)
	tbs := &cert.TBSCertificate{
		Version:   cert.Version1,
		Curve:     cert.Curve_CURVE25519,
		Name:      name,
		Networks:  []netip.Prefix{network},
		Groups:    groups,
		NotBefore: t1,
		NotAfter:  t1.Add(5 * time.Minute),
		PublicKey: pub,
		IsCA:      false,
	}

	nc, err := tbs.Sign(ca, cert.Curve_CURVE25519, signer)
	require.NoError(t, err)

	return nc, priv
}

func mustNebulaP256Cert(t *testing.T, name string, network netip.Prefix, groups []string, ca cert.Certificate, signer *ecdsa.PrivateKey) (cert.Certificate, crypto.Signer) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecdhPriv, err := key.ECDH()
	require.NoError(t, err)

	t1 := time.Now().Truncate(time.Second)
	tbs := &cert.TBSCertificate{
		Version:   cert.Version1,
		Curve:     cert.Curve_P256,
		Name:      name,
		Networks:  []netip.Prefix{network},
		Groups:    groups,
		NotBefore: t1,
		NotAfter:  t1.Add(5 * time.Minute),
		PublicKey: ecdhPriv.PublicKey().Bytes(),
		IsCA:      false,
	}

	ecdhSigner, err := signer.ECDH()
	require.NoError(t, err)

	nc, err := tbs.Sign(ca, cert.Curve_P256, ecdhSigner.Bytes())
	require.NoError(t, err)

	return nc, key
}

func mustNebulaProvisioner(t *testing.T) (*Nebula, cert.Certificate, ed25519.PrivateKey) {
	t.Helper()

	nc, signer := mustNebulaCA(t)
	ncPem, err := nc.MarshalPEM()
	require.NoError(t, err)
	bTrue := true
	p := &Nebula{
		Type:  TypeNebula.String(),
		Name:  "nebulous",
		Roots: ncPem,
		Claims: &Claims{
			EnableSSHCA: &bTrue,
		},
	}
	err = p.Init(Config{
		Claims:    globalProvisionerClaims,
		Audiences: testAudiences,
	})
	require.NoError(t, err)

	return p, nc, signer
}

func mustNebulaP256Provisioner(t *testing.T) (*Nebula, cert.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	nc, signer := mustNebulaP256CA(t)
	ncPem, err := nc.MarshalPEM()
	require.NoError(t, err)
	bTrue := true
	p := &Nebula{
		Type:  TypeNebula.String(),
		Name:  "nebulous",
		Roots: ncPem,
		Claims: &Claims{
			EnableSSHCA: &bTrue,
		},
	}
	err = p.Init(Config{
		Claims:    globalProvisionerClaims,
		Audiences: testAudiences,
	})
	require.NoError(t, err)

	return p, nc, signer
}

func mustNebulaToken(t *testing.T, sub, iss, aud string, iat time.Time, sans []string, nc cert.Certificate, key crypto.Signer, algorithm jose.SignatureAlgorithm) string {
	t.Helper()
	ncDer, err := nc.Marshal()
	require.NoError(t, err)

	so := new(jose.SignerOptions)
	so.WithType("JWT")
	so.WithHeader(NebulaCertHeader, ncDer)

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: algorithm, Key: key}, so)
	require.NoError(t, err)

	id, err := randutil.ASCII(64)
	require.NoError(t, err)

	claims := struct {
		jose.Claims
		SANS []string `json:"sans"`
	}{
		Claims: jose.Claims{
			ID:        id,
			Subject:   sub,
			Issuer:    iss,
			IssuedAt:  jose.NewNumericDate(iat),
			NotBefore: jose.NewNumericDate(iat),
			Expiry:    jose.NewNumericDate(iat.Add(5 * time.Minute)),
			Audience:  []string{aud},
		},
		SANS: sans,
	}
	tok, err := jose.Signed(sig).Claims(claims).CompactSerialize()
	require.NoError(t, err)

	return tok
}

func mustNebulaSSHToken(t *testing.T, sub, iss, aud string, iat time.Time, opts *SignSSHOptions, nc cert.Certificate, key crypto.Signer, algorithm jose.SignatureAlgorithm) string {
	t.Helper()
	ncDer, err := nc.Marshal()
	require.NoError(t, err)

	so := new(jose.SignerOptions)
	so.WithType("JWT")
	so.WithHeader(NebulaCertHeader, ncDer)

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: algorithm, Key: key}, so)
	require.NoError(t, err)

	id, err := randutil.ASCII(64)
	require.NoError(t, err)

	claims := struct {
		jose.Claims
		Step *stepPayload `json:"step,omitempty"`
	}{
		Claims: jose.Claims{
			ID:        id,
			Subject:   sub,
			Issuer:    iss,
			IssuedAt:  jose.NewNumericDate(iat),
			NotBefore: jose.NewNumericDate(iat),
			Expiry:    jose.NewNumericDate(iat.Add(5 * time.Minute)),
			Audience:  []string{aud},
		},
	}
	if opts != nil {
		claims.Step = &stepPayload{
			SSH: opts,
		}
	}

	tok, err := jose.Signed(sig).Claims(claims).CompactSerialize()
	require.NoError(t, err)

	return tok
}

func TestNebula_Init(t *testing.T) {
	nc, _ := mustNebulaCA(t)
	ncPem, err := nc.MarshalPEM()
	require.NoError(t, err)
	expiredNC, _ := mustExpiredNebulaCA(t)
	expiredPEM, err := expiredNC.MarshalPEM()
	require.NoError(t, err)
	expiredPEM = append(expiredPEM, ncPem...) // needed so that regular error isn't triggered

	cfg := Config{
		Claims:    globalProvisionerClaims,
		Audiences: testAudiences,
	}

	type fields struct {
		Type    string
		Name    string
		Roots   []byte
		Claims  *Claims
		Options *Options
	}
	type args struct {
		config Config
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{"ok", fields{"Nebula", "Nebulous", ncPem, nil, nil}, args{cfg}, false},
		{"ok with claims", fields{"Nebula", "Nebulous", ncPem, &Claims{DefaultTLSDur: &Duration{Duration: time.Hour}}, nil}, args{cfg}, false},
		{"ok with options", fields{"Nebula", "Nebulous", ncPem, nil, &Options{X509: &X509Options{Template: x509util.DefaultLeafTemplate}}}, args{cfg}, false},
		{"fail type", fields{"", "Nebulous", ncPem, nil, nil}, args{cfg}, true},
		{"fail name", fields{"Nebula", "", ncPem, nil, nil}, args{cfg}, true},
		{"fail root", fields{"Nebula", "Nebulous", nil, nil, nil}, args{cfg}, true},
		{"fail expired root", fields{"Nebula", "Nebulous", expiredPEM, nil, nil}, args{cfg}, true},
		{"fail bad root", fields{"Nebula", "Nebulous", ncPem[:16], nil, nil}, args{cfg}, true},
		{"fail bad claims", fields{"Nebula", "Nebulous", ncPem, &Claims{
			MinTLSDur: &Duration{Duration: 0},
		}, nil}, args{cfg}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Nebula{
				Type:    tt.fields.Type,
				Name:    tt.fields.Name,
				Roots:   tt.fields.Roots,
				Claims:  tt.fields.Claims,
				Options: tt.fields.Options,
			}
			if err := p.Init(tt.args.config); (err != nil) != tt.wantErr {
				t.Errorf("Nebula.Init() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNebula_GetID(t *testing.T) {
	type fields struct {
		ID   string
		Name string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{"ok with id", fields{"1234", "nebulous"}, "1234"},
		{"ok with name", fields{"", "nebulous"}, "nebula/nebulous"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Nebula{
				ID:   tt.fields.ID,
				Name: tt.fields.Name,
			}
			if got := p.GetID(); got != tt.want {
				t.Errorf("Nebula.GetID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNebula_GetIDForToken(t *testing.T) {
	type fields struct {
		Name string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{"ok", fields{"nebulous"}, "nebula/nebulous"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Nebula{
				Name: tt.fields.Name,
			}
			if got := p.GetIDForToken(); got != tt.want {
				t.Errorf("Nebula.GetIDForToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNebula_GetTokenID(t *testing.T) {
	p, ca, signer := mustNebulaProvisioner(t)
	c1, priv := mustNebulaCert(t, "test.lan", mustNebulaPrefix(t, "10.1.0.1/16"), []string{"test"}, ca, signer)
	t1 := mustNebulaToken(t, "test.lan", p.Name, p.ctl.Audiences.Sign[0], now(), []string{"test.lan", "10.1.0.1"}, c1, priv, jose.XEdDSA)
	_, claims, err := parseToken(t1)
	require.NoError(t, err)

	type args struct {
		token string
	}
	tests := []struct {
		name    string
		p       *Nebula
		args    args
		want    string
		wantErr bool
	}{
		{"ok", p, args{t1}, claims.ID, false},
		{"fail parse", p, args{"token"}, "", true},
		{"fail claims", p, args{func() string {
			parts := strings.Split(t1, ".")

			return parts[0] + ".eyIifQ." + parts[1]
		}()}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.p.GetTokenID(tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("Nebula.GetTokenID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Nebula.GetTokenID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNebula_GetName(t *testing.T) {
	type fields struct {
		Name string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{"ok", fields{"nebulous"}, "nebulous"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Nebula{
				Name: tt.fields.Name,
			}
			if got := p.GetName(); got != tt.want {
				t.Errorf("Nebula.GetName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNebula_GetType(t *testing.T) {
	type fields struct {
		Type string
	}
	tests := []struct {
		name   string
		fields fields
		want   Type
	}{
		{"ok", fields{"Nebula"}, TypeNebula},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Nebula{
				Type: tt.fields.Type,
			}
			if got := p.GetType(); got != tt.want {
				t.Errorf("Nebula.GetType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNebula_GetEncryptedKey(t *testing.T) {
	tests := []struct {
		name    string
		p       *Nebula
		wantKid string
		wantKey string
		wantOk  bool
	}{
		{"ok", &Nebula{}, "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKid, gotKey, gotOk := tt.p.GetEncryptedKey()
			if gotKid != tt.wantKid {
				t.Errorf("Nebula.GetEncryptedKey() gotKid = %v, want %v", gotKid, tt.wantKid)
			}
			if gotKey != tt.wantKey {
				t.Errorf("Nebula.GetEncryptedKey() gotKey = %v, want %v", gotKey, tt.wantKey)
			}
			if gotOk != tt.wantOk {
				t.Errorf("Nebula.GetEncryptedKey() gotOk = %v, want %v", gotOk, tt.wantOk)
			}
		})
	}
}

func TestNebula_AuthorizeSign(t *testing.T) {
	ctx := context.TODO()
	p, ca, signer := mustNebulaProvisioner(t)
	crt, priv := mustNebulaCert(t, "test.lan", mustNebulaPrefix(t, "10.1.0.1/16"), []string{"test"}, ca, signer)
	ok := mustNebulaToken(t, "test.lan", p.Name, p.ctl.Audiences.Sign[0], now(), []string{"test.lan", "10.1.0.1"}, crt, priv, jose.XEdDSA)
	okNoSANs := mustNebulaToken(t, "test.lan", p.Name, p.ctl.Audiences.Sign[0], now(), nil, crt, priv, jose.XEdDSA)

	pBadOptions, _, _ := mustNebulaProvisioner(t)
	pBadOptions.caPool = p.caPool
	pBadOptions.Options = &Options{
		X509: &X509Options{
			TemplateData: []byte(`{""}`),
		},
	}

	type args struct {
		ctx   context.Context
		token string
	}
	tests := []struct {
		name    string
		p       *Nebula
		args    args
		wantErr bool
	}{
		{"ok", p, args{ctx, ok}, false},
		{"ok no sans", p, args{ctx, okNoSANs}, false},
		{"fail token", p, args{ctx, "token"}, true},
		{"fail template", pBadOptions, args{ctx, ok}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.p.AuthorizeSign(tt.args.ctx, tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("Nebula.AuthorizeSign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestNebula_AuthorizeSSHSign(t *testing.T) {
	ctx := context.TODO()
	// Ok provisioner
	p, ca, signer := mustNebulaProvisioner(t)
	crt, priv := mustNebulaCert(t, "test.lan", mustNebulaPrefix(t, "10.1.0.1/16"), []string{"test"}, ca, signer)
	ok := mustNebulaSSHToken(t, "test.lan", p.Name, p.ctl.Audiences.SSHSign[0], now(), &SignSSHOptions{
		CertType:   "host",
		KeyID:      "test.lan",
		Principals: []string{"test.lan", "10.1.0.1"},
	}, crt, priv, jose.XEdDSA)
	okNoOptions := mustNebulaSSHToken(t, "test.lan", p.Name, p.ctl.Audiences.SSHSign[0], now(), nil, crt, priv, jose.XEdDSA)
	okWithValidity := mustNebulaSSHToken(t, "test.lan", p.Name, p.ctl.Audiences.SSHSign[0], now(), &SignSSHOptions{
		ValidAfter:  NewTimeDuration(now().Add(1 * time.Hour)),
		ValidBefore: NewTimeDuration(now().Add(10 * time.Hour)),
	}, crt, priv, jose.XEdDSA)
	failUserCert := mustNebulaSSHToken(t, "test.lan", p.Name, p.ctl.Audiences.SSHSign[0], now(), &SignSSHOptions{
		CertType: "user",
	}, crt, priv, jose.XEdDSA)
	failPrincipals := mustNebulaSSHToken(t, "test.lan", p.Name, p.ctl.Audiences.SSHSign[0], now(), &SignSSHOptions{
		CertType:   "host",
		KeyID:      "test.lan",
		Principals: []string{"test.lan", "10.1.0.1", "foo.bar"},
	}, crt, priv, jose.XEdDSA)

	// Provisioner with SSH disabled
	var bFalse bool
	pDisabled, _, _ := mustNebulaProvisioner(t)
	pDisabled.caPool = p.caPool
	pDisabled.Claims.EnableSSHCA = &bFalse

	// Provisioner with bad templates
	pBadOptions, _, _ := mustNebulaProvisioner(t)
	pBadOptions.caPool = p.caPool
	pBadOptions.Options = &Options{
		SSH: &SSHOptions{
			TemplateData: []byte(`{""}`),
		},
	}

	type args struct {
		ctx   context.Context
		token string
	}
	tests := []struct {
		name    string
		p       *Nebula
		args    args
		wantErr bool
	}{
		{"ok", p, args{ctx, ok}, false},
		{"ok no options", p, args{ctx, okNoOptions}, false},
		{"ok with validity", p, args{ctx, okWithValidity}, false},
		{"fail token", p, args{ctx, "token"}, true},
		{"fail user", p, args{ctx, failUserCert}, true},
		{"fail principals", p, args{ctx, failPrincipals}, true},
		{"fail disabled", pDisabled, args{ctx, ok}, true},
		{"fail template", pBadOptions, args{ctx, ok}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.p.AuthorizeSSHSign(tt.args.ctx, tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("Nebula.AuthorizeSSHSign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestNebula_AuthorizeRenew(t *testing.T) {
	ctx := context.TODO()
	now := time.Now().Truncate(time.Second)

	// Ok provisioner
	p, _, _ := mustNebulaProvisioner(t)

	// Provisioner with renewal disabled
	bTrue := true
	pDisabled, _, _ := mustNebulaProvisioner(t)
	pDisabled.Claims.DisableRenewal = &bTrue

	type args struct {
		ctx context.Context
		crt *x509.Certificate
	}
	tests := []struct {
		name    string
		p       *Nebula
		args    args
		wantErr bool
	}{
		{"ok", p, args{ctx, &x509.Certificate{
			NotBefore: now,
			NotAfter:  now.Add(time.Hour),
		}}, false},
		{"fail disabled", pDisabled, args{ctx, &x509.Certificate{
			NotBefore: now,
			NotAfter:  now.Add(time.Hour),
		}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.p.AuthorizeRenew(tt.args.ctx, tt.args.crt); (err != nil) != tt.wantErr {
				t.Errorf("Nebula.AuthorizeRenew() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNebula_AuthorizeRevoke(t *testing.T) {
	ctx := context.TODO()
	// Ok provisioner
	p, ca, signer := mustNebulaProvisioner(t)
	crt, priv := mustNebulaCert(t, "test.lan", mustNebulaPrefix(t, "10.1.0.1/16"), []string{"test"}, ca, signer)
	ok := mustNebulaToken(t, "test.lan", p.Name, p.ctl.Audiences.Revoke[0], now(), nil, crt, priv, jose.XEdDSA)

	// Fail different CA
	nc, signer := mustNebulaCA(t)
	crt, priv = mustNebulaCert(t, "test.lan", mustNebulaPrefix(t, "10.1.0.1/16"), []string{"test"}, nc, signer)
	failToken := mustNebulaToken(t, "test.lan", p.Name, p.ctl.Audiences.Revoke[0], now(), nil, crt, priv, jose.XEdDSA)

	type args struct {
		ctx   context.Context
		token string
	}
	tests := []struct {
		name    string
		p       *Nebula
		args    args
		wantErr bool
	}{
		{"fail unauthorized", p, args{ctx, ok}, true},
		{"fail token", p, args{ctx, failToken}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.p.AuthorizeRevoke(tt.args.ctx, tt.args.token); (err != nil) != tt.wantErr {
				t.Errorf("Nebula.AuthorizeRevoke() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNebula_AuthorizeSSHRevoke(t *testing.T) {
	ctx := context.TODO()
	// Ok provisioner
	p, ca, signer := mustNebulaProvisioner(t)
	crt, priv := mustNebulaCert(t, "test.lan", mustNebulaPrefix(t, "10.1.0.1/16"), []string{"test"}, ca, signer)
	ok := mustNebulaSSHToken(t, "test.lan", p.Name, p.ctl.Audiences.SSHRevoke[0], now(), nil, crt, priv, jose.XEdDSA)

	// Fail different CA
	nc, signer := mustNebulaCA(t)
	crt, priv = mustNebulaCert(t, "test.lan", mustNebulaPrefix(t, "10.1.0.1/16"), []string{"test"}, nc, signer)
	failToken := mustNebulaSSHToken(t, "test.lan", p.Name, p.ctl.Audiences.SSHRevoke[0], now(), nil, crt, priv, jose.XEdDSA)

	// Provisioner with SSH disabled
	var bFalse bool
	pDisabled, _, _ := mustNebulaProvisioner(t)
	pDisabled.caPool = p.caPool
	pDisabled.Claims.EnableSSHCA = &bFalse

	type args struct {
		ctx   context.Context
		token string
	}
	tests := []struct {
		name    string
		p       *Nebula
		args    args
		wantErr bool
	}{
		{"fail unauthorized", p, args{ctx, ok}, true},
		{"fail token", p, args{ctx, failToken}, true},
		{"fail disabled", pDisabled, args{ctx, ok}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.p.AuthorizeSSHRevoke(tt.args.ctx, tt.args.token); (err != nil) != tt.wantErr {
				t.Errorf("Nebula.AuthorizeSSHRevoke() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNebula_AuthorizeSSHRenew(t *testing.T) {
	p, ca, signer := mustNebulaProvisioner(t)
	crt, priv := mustNebulaCert(t, "test.lan", mustNebulaPrefix(t, "10.1.0.1/16"), []string{"test"}, ca, signer)
	t1 := mustNebulaSSHToken(t, "test.lan", p.Name, p.ctl.Audiences.SSHRenew[0], now(), nil, crt, priv, jose.XEdDSA)

	type args struct {
		ctx   context.Context
		token string
	}
	tests := []struct {
		name    string
		p       *Nebula
		args    args
		want    *ssh.Certificate
		wantErr bool
	}{
		{"fail", p, args{context.TODO(), t1}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.p.AuthorizeSSHRenew(tt.args.ctx, tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("Nebula.AuthorizeSSHRenew() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNebula_AuthorizeSSHRekey(t *testing.T) {
	p, ca, signer := mustNebulaProvisioner(t)
	crt, priv := mustNebulaCert(t, "test.lan", mustNebulaPrefix(t, "10.1.0.1/16"), []string{"test"}, ca, signer)
	t1 := mustNebulaSSHToken(t, "test.lan", p.Name, p.ctl.Audiences.SSHRekey[0], now(), nil, crt, priv, jose.XEdDSA)

	type args struct {
		ctx   context.Context
		token string
	}
	tests := []struct {
		name    string
		p       *Nebula
		args    args
		want    *ssh.Certificate
		want1   []SignOption
		wantErr bool
	}{
		{"fail", p, args{context.TODO(), t1}, nil, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := tt.p.AuthorizeSSHRekey(tt.args.ctx, tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("Nebula.AuthorizeSSHRekey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.want1, got1)
		})
	}
}

func TestNebula_authorizeToken(t *testing.T) {
	t1 := now()
	p, ca, signer := mustNebulaProvisioner(t)
	crt, priv := mustNebulaCert(t, "test.lan", mustNebulaPrefix(t, "10.1.0.1/16"), []string{"test"}, ca, signer)
	ok := mustNebulaToken(t, "test.lan", p.Name, p.ctl.Audiences.Sign[0], t1, []string{"10.1.0.1"}, crt, priv, jose.XEdDSA)
	okNoSANs := mustNebulaToken(t, "test.lan", p.Name, p.ctl.Audiences.Sign[0], t1, nil, crt, priv, jose.XEdDSA)
	okSSH := mustNebulaSSHToken(t, "test.lan", p.Name, p.ctl.Audiences.SSHSign[0], t1, &SignSSHOptions{
		CertType:   "host",
		KeyID:      "test.lan",
		Principals: []string{"test.lan"},
	}, crt, priv, jose.XEdDSA)
	okSSHNoOptions := mustNebulaSSHToken(t, "test.lan", p.Name, p.ctl.Audiences.SSHSign[0], t1, nil, crt, priv, jose.XEdDSA)

	// Token with errors
	failNotBefore := mustNebulaToken(t, "test.lan", p.Name, p.ctl.Audiences.Sign[0], t1.Add(1*time.Hour), []string{"10.1.0.1"}, crt, priv, jose.XEdDSA)
	failIssuer := mustNebulaToken(t, "test.lan", "foo", p.ctl.Audiences.Sign[0], t1, []string{"10.1.0.1"}, crt, priv, jose.XEdDSA)
	failAudience := mustNebulaToken(t, "test.lan", p.Name, "foo", t1, []string{"10.1.0.1"}, crt, priv, jose.XEdDSA)
	failSubject := mustNebulaToken(t, "", p.Name, p.ctl.Audiences.Sign[0], t1, []string{"10.1.0.1"}, crt, priv, jose.XEdDSA)

	// Not a nebula token
	jwk, err := generateJSONWebKey()
	require.NoError(t, err)
	simpleToken, err := generateSimpleToken("iss", "aud", jwk)
	require.NoError(t, err)

	// Provisioner with a different CA
	p2, _, _ := mustNebulaProvisioner(t)

	x509Claims := jose.Claims{
		ID:        "[REPLACEME]",
		Subject:   "test.lan",
		Issuer:    p.Name,
		IssuedAt:  jose.NewNumericDate(t1),
		NotBefore: jose.NewNumericDate(t1),
		Expiry:    jose.NewNumericDate(t1.Add(5 * time.Minute)),
		Audience:  []string{p.ctl.Audiences.Sign[0]},
	}
	sshClaims := jose.Claims{
		ID:        "[REPLACEME]",
		Subject:   "test.lan",
		Issuer:    p.Name,
		IssuedAt:  jose.NewNumericDate(t1),
		NotBefore: jose.NewNumericDate(t1),
		Expiry:    jose.NewNumericDate(t1.Add(5 * time.Minute)),
		Audience:  []string{p.ctl.Audiences.SSHSign[0]},
	}

	type args struct {
		token     string
		audiences []string
	}
	tests := []struct {
		name      string
		p         *Nebula
		args      args
		wantClaims *jwtPayload
		wantErr   bool
	}{
		{"ok x509", p, args{ok, p.ctl.Audiences.Sign}, &jwtPayload{
			Claims: x509Claims,
			SANs:   []string{"10.1.0.1"},
		}, false},
		{"ok x509 no sans", p, args{okNoSANs, p.ctl.Audiences.Sign}, &jwtPayload{
			Claims: x509Claims,
		}, false},
		{"ok ssh", p, args{okSSH, p.ctl.Audiences.SSHSign}, &jwtPayload{
			Claims: sshClaims,
			Step: &stepPayload{
				SSH: &SignSSHOptions{
					CertType:   "host",
					KeyID:      "test.lan",
					Principals: []string{"test.lan"},
				},
			},
		}, false},
		{"ok ssh no principals", p, args{okSSHNoOptions, p.ctl.Audiences.SSHSign}, &jwtPayload{
			Claims: sshClaims,
		}, false},
		{"fail parse", p, args{"bad.token", p.ctl.Audiences.Sign}, nil, true},
		{"fail header", p, args{simpleToken, p.ctl.Audiences.Sign}, nil, true},
		{"fail verify", p2, args{ok, p.ctl.Audiences.Sign}, nil, true},
		{"fail claims nbf", p, args{failNotBefore, p.ctl.Audiences.Sign}, nil, true},
		{"fail claims iss", p, args{failIssuer, p.ctl.Audiences.Sign}, nil, true},
		{"fail claims aud", p, args{failAudience, p.ctl.Audiences.Sign}, nil, true},
		{"fail claims sub", p, args{failSubject, p.ctl.Audiences.Sign}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := tt.p.authorizeToken(tt.args.token, tt.args.audiences)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, got)
				assert.Nil(t, got1)
				return
			}

			if got1 != nil && tt.wantClaims != nil {
				tt.wantClaims.ID = got1.ID
			}

			assert.NoError(t, err)
			assert.NotNil(t, got)
			assert.Equal(t, tt.wantClaims, got1)
		})
	}
}

func TestNebula_authorizeToken_P256(t *testing.T) {
	t1 := now()
	p, ca, signer := mustNebulaP256Provisioner(t)
	crt, priv := mustNebulaP256Cert(t, "test.lan", mustNebulaPrefix(t, "10.1.0.1/16"), []string{"test"}, ca, signer)
	ok := mustNebulaToken(t, "test.lan", p.Name, p.ctl.Audiences.Sign[0], t1, []string{"10.1.0.1"}, crt, priv, jose.ES256)
	okNoSANs := mustNebulaToken(t, "test.lan", p.Name, p.ctl.Audiences.Sign[0], t1, nil, crt, priv, jose.ES256)
	okSSH := mustNebulaSSHToken(t, "test.lan", p.Name, p.ctl.Audiences.SSHSign[0], t1, &SignSSHOptions{
		CertType:   "host",
		KeyID:      "test.lan",
		Principals: []string{"test.lan"},
	}, crt, priv, jose.ES256)
	okSSHNoOptions := mustNebulaSSHToken(t, "test.lan", p.Name, p.ctl.Audiences.SSHSign[0], t1, nil, crt, priv, jose.ES256)

	// Token with errors
	failNotBefore := mustNebulaToken(t, "test.lan", p.Name, p.ctl.Audiences.Sign[0], t1.Add(1*time.Hour), []string{"10.1.0.1"}, crt, priv, jose.ES256)
	failIssuer := mustNebulaToken(t, "test.lan", "foo", p.ctl.Audiences.Sign[0], t1, []string{"10.1.0.1"}, crt, priv, jose.ES256)
	failAudience := mustNebulaToken(t, "test.lan", p.Name, "foo", t1, []string{"10.1.0.1"}, crt, priv, jose.ES256)
	failSubject := mustNebulaToken(t, "", p.Name, p.ctl.Audiences.Sign[0], t1, []string{"10.1.0.1"}, crt, priv, jose.ES256)

	// Not a nebula token
	jwk, err := generateJSONWebKey()
	require.NoError(t, err)
	simpleToken, err := generateSimpleToken("iss", "aud", jwk)
	require.NoError(t, err)

	// Provisioner with a different CA
	p2, _, _ := mustNebulaP256Provisioner(t)

	x509Claims := jose.Claims{
		ID:        "[REPLACEME]",
		Subject:   "test.lan",
		Issuer:    p.Name,
		IssuedAt:  jose.NewNumericDate(t1),
		NotBefore: jose.NewNumericDate(t1),
		Expiry:    jose.NewNumericDate(t1.Add(5 * time.Minute)),
		Audience:  []string{p.ctl.Audiences.Sign[0]},
	}
	sshClaims := jose.Claims{
		ID:        "[REPLACEME]",
		Subject:   "test.lan",
		Issuer:    p.Name,
		IssuedAt:  jose.NewNumericDate(t1),
		NotBefore: jose.NewNumericDate(t1),
		Expiry:    jose.NewNumericDate(t1.Add(5 * time.Minute)),
		Audience:  []string{p.ctl.Audiences.SSHSign[0]},
	}

	type args struct {
		token     string
		audiences []string
	}
	tests := []struct {
		name      string
		p         *Nebula
		args      args
		wantClaims *jwtPayload
		wantErr   bool
	}{
		{"ok x509", p, args{ok, p.ctl.Audiences.Sign}, &jwtPayload{
			Claims: x509Claims,
			SANs:   []string{"10.1.0.1"},
		}, false},
		{"ok x509 no sans", p, args{okNoSANs, p.ctl.Audiences.Sign}, &jwtPayload{
			Claims: x509Claims,
		}, false},
		{"ok ssh", p, args{okSSH, p.ctl.Audiences.SSHSign}, &jwtPayload{
			Claims: sshClaims,
			Step: &stepPayload{
				SSH: &SignSSHOptions{
					CertType:   "host",
					KeyID:      "test.lan",
					Principals: []string{"test.lan"},
				},
			},
		}, false},
		{"ok ssh no principals", p, args{okSSHNoOptions, p.ctl.Audiences.SSHSign}, &jwtPayload{
			Claims: sshClaims,
		}, false},
		{"fail parse", p, args{"bad.token", p.ctl.Audiences.Sign}, nil, true},
		{"fail header", p, args{simpleToken, p.ctl.Audiences.Sign}, nil, true},
		{"fail verify", p2, args{ok, p.ctl.Audiences.Sign}, nil, true},
		{"fail claims nbf", p, args{failNotBefore, p.ctl.Audiences.Sign}, nil, true},
		{"fail claims iss", p, args{failIssuer, p.ctl.Audiences.Sign}, nil, true},
		{"fail claims aud", p, args{failAudience, p.ctl.Audiences.Sign}, nil, true},
		{"fail claims sub", p, args{failSubject, p.ctl.Audiences.Sign}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := tt.p.authorizeToken(tt.args.token, tt.args.audiences)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, got)
				assert.Nil(t, got1)
				return
			}

			if got1 != nil && tt.wantClaims != nil {
				tt.wantClaims.ID = got1.ID
			}

			assert.NoError(t, err)
			assert.NotNil(t, got)
			assert.Equal(t, tt.wantClaims, got1)
		})
	}
}

func Test_nebulaSANsValidator_Valid(t *testing.T) {
	prefix := mustNebulaPrefix(t, "10.1.2.3/16")
	type fields struct {
		Name     string
		Networks []netip.Prefix
	}
	type args struct {
		req *x509.CertificateRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{"ok", fields{"dns.name", []netip.Prefix{prefix}}, args{&x509.CertificateRequest{
			DNSNames:    []string{"dns.name"},
			IPAddresses: []net.IP{net.IPv4(10, 1, 2, 3)},
		}}, false},
		{"ok name only", fields{"dns.name", []netip.Prefix{prefix}}, args{&x509.CertificateRequest{
			DNSNames: []string{"dns.name"},
		}}, false},
		{"ok ip only", fields{"dns.name", []netip.Prefix{prefix}}, args{&x509.CertificateRequest{
			IPAddresses: []net.IP{net.IPv4(10, 1, 2, 3)},
		}}, false},
		{"ok email name", fields{"jane@doe.org", []netip.Prefix{prefix}}, args{&x509.CertificateRequest{
			EmailAddresses: []string{"jane@doe.org"},
			IPAddresses:    []net.IP{net.IPv4(10, 1, 2, 3)},
		}}, false},
		{"ok uri name", fields{"urn:foobar", []netip.Prefix{prefix}}, args{&x509.CertificateRequest{
			URIs:        []*url.URL{{Scheme: "urn", Opaque: "foobar"}},
			IPAddresses: []net.IP{net.IPv4(10, 1, 2, 3)},
		}}, false},
		{"ok ip name", fields{"127.0.0.1", []netip.Prefix{prefix}}, args{&x509.CertificateRequest{
			IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv4(10, 1, 2, 3)},
		}}, false},
		{"ok multiple ips", fields{"dns.name", []netip.Prefix{prefix, mustNebulaPrefix(t, "10.2.2.3/8")}}, args{&x509.CertificateRequest{
			DNSNames:    []string{"dns.name"},
			IPAddresses: []net.IP{net.IPv4(10, 1, 2, 3), net.IPv4(10, 2, 2, 3)},
		}}, false},
		{"fail dns", fields{"fail.name", []netip.Prefix{prefix}}, args{&x509.CertificateRequest{
			DNSNames:    []string{"dns.name"},
			IPAddresses: []net.IP{net.IPv4(10, 1, 2, 3)},
		}}, true},
		{"fail email", fields{"fail@doe.org", []netip.Prefix{prefix}}, args{&x509.CertificateRequest{
			EmailAddresses: []string{"jane@doe.org"},
			IPAddresses:    []net.IP{net.IPv4(10, 1, 2, 3)},
		}}, true},
		{"fail uri", fields{"urn:barfoo", []netip.Prefix{prefix}}, args{&x509.CertificateRequest{
			URIs:        []*url.URL{{Scheme: "urn", Opaque: "foobar"}},
			IPAddresses: []net.IP{net.IPv4(10, 1, 2, 3)},
		}}, true},
		{"fail ip", fields{"127.0.0.1", []netip.Prefix{prefix}}, args{&x509.CertificateRequest{
			IPAddresses: []net.IP{net.IPv4(10, 1, 2, 1), net.IPv4(10, 1, 2, 3)},
		}}, true},
		{"fail nebula ip", fields{"dns.name", []netip.Prefix{prefix}}, args{&x509.CertificateRequest{
			DNSNames:    []string{"dns.name"},
			IPAddresses: []net.IP{net.IPv4(10, 2, 2, 3)},
		}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := nebulaSANsValidator{
				Name:     tt.fields.Name,
				Networks: tt.fields.Networks,
			}
			if err := v.Valid(tt.args.req); (err != nil) != tt.wantErr {
				t.Errorf("nebulaSANsValidator.Valid() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_nebulaPrincipalsValidator_Valid(t *testing.T) {
	prefix := mustNebulaPrefix(t, "10.1.2.3/16")

	type fields struct {
		Name     string
		Networks []netip.Prefix
	}
	type args struct {
		got SignSSHOptions
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{"ok", fields{"dns.name", []netip.Prefix{prefix}}, args{SignSSHOptions{
			Principals: []string{"dns.name", "10.1.2.3"},
		}}, false},
		{"ok name", fields{"dns.name", []netip.Prefix{prefix}}, args{SignSSHOptions{
			Principals: []string{"dns.name"},
		}}, false},
		{"ok ip", fields{"dns.name", []netip.Prefix{prefix}}, args{SignSSHOptions{
			Principals: []string{"10.1.2.3"},
		}}, false},
		{"fail name", fields{"dns.name", []netip.Prefix{prefix}}, args{SignSSHOptions{
			Principals: []string{"foo.name", "10.1.2.3"},
		}}, true},
		{"fail ip", fields{"dns.name", []netip.Prefix{prefix}}, args{SignSSHOptions{
			Principals: []string{"dns.name", "10.2.2.3"},
		}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := nebulaPrincipalsValidator{
				Name:     tt.fields.Name,
				Networks: tt.fields.Networks,
			}
			if err := v.Valid(tt.args.got); (err != nil) != tt.wantErr {
				t.Errorf("nebulaPrincipalsValidator.Valid() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
