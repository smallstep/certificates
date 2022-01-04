package provisioner

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/randutil"
	"go.step.sm/crypto/x25519"
	"go.step.sm/crypto/x509util"
	"golang.org/x/crypto/ssh"
)

func mustNebulaIPNet(t *testing.T, s string) *net.IPNet {
	t.Helper()
	ip, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatal(err)
	}
	if ip.To4() == nil {
		t.Fatalf("nebula only supports ipv4, have %s", s)
	}
	ipNet.IP = ip
	return ipNet
}

func mustNebulaCA(t *testing.T) (*cert.NebulaCertificate, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nc := &cert.NebulaCertificate{
		Details: cert.NebulaCertificateDetails{
			Name:   "TestCA",
			Groups: []string{"test"},
			Ips: []*net.IPNet{
				mustNebulaIPNet(t, "10.1.0.0/16"),
			},
			Subnets:   nil,
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(10 * time.Minute),
			PublicKey: pub,
			IsCA:      true,
		},
	}
	if err := nc.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return nc, priv
}

func mustNebulaCert(t *testing.T, name string, ipNet *net.IPNet, groups []string, ca *cert.NebulaCertificate, signer ed25519.PrivateKey) (*cert.NebulaCertificate, crypto.Signer) {
	t.Helper()

	pub, priv, err := x25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	issuer, err := ca.Sha256Sum()
	if err != nil {
		t.Fatal(err)
	}

	nc := &cert.NebulaCertificate{
		Details: cert.NebulaCertificateDetails{
			Name:      name,
			Ips:       []*net.IPNet{ipNet},
			Groups:    groups,
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(5 * time.Minute),
			PublicKey: pub,
			IsCA:      false,
			Issuer:    issuer,
		},
	}

	if err := nc.Sign(signer); err != nil {
		t.Fatal(err)
	}

	return nc, priv
}

func mustNebulaProvisioner(t *testing.T) (*Nebula, *cert.NebulaCertificate, ed25519.PrivateKey) {
	t.Helper()

	nc, signer := mustNebulaCA(t)
	ncPem, err := nc.MarshalToPEM()
	if err != nil {
		t.Fatal(err)
	}
	bTrue := true
	p := &Nebula{
		Type:  TypeNebula.String(),
		Name:  "nebulous",
		Roots: ncPem,
		Claims: &Claims{
			EnableSSHCA: &bTrue,
		},
	}
	if err := p.Init(Config{
		Claims:    globalProvisionerClaims,
		Audiences: testAudiences,
	}); err != nil {
		t.Fatal(err)
	}

	return p, nc, signer
}

func mustNebulaToken(t *testing.T, sub, iss, aud string, iat time.Time, sans []string, nc *cert.NebulaCertificate, key crypto.Signer) string {
	t.Helper()
	ncPEM, err := nc.MarshalToPEM()
	if err != nil {
		t.Fatal(err)
	}

	so := new(jose.SignerOptions)
	so.WithType("JWT")
	so.WithHeader(NebulaCertHeader, ncPEM)

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.XEdDSA, Key: key}, so)
	if err != nil {
		t.Fatal(err)
	}

	id, err := randutil.ASCII(64)
	if err != nil {
		t.Fatal(err)
	}

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
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func mustNebulaSSHToken(t *testing.T, sub, iss, aud string, iat time.Time, opts *SignSSHOptions, nc *cert.NebulaCertificate, key crypto.Signer) string {
	t.Helper()
	ncPEM, err := nc.MarshalToPEM()
	if err != nil {
		t.Fatal(err)
	}

	so := new(jose.SignerOptions)
	so.WithType("JWT")
	so.WithHeader(NebulaCertHeader, ncPEM)

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.XEdDSA, Key: key}, so)
	if err != nil {
		t.Fatal(err)
	}

	id, err := randutil.ASCII(64)
	if err != nil {
		t.Fatal(err)
	}

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
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestNebula_Init(t *testing.T) {
	nc, _ := mustNebulaCA(t)
	ncPem, err := nc.MarshalToPEM()
	if err != nil {
		t.Fatal(err)
	}

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
	c1, priv := mustNebulaCert(t, "test.lan", mustNebulaIPNet(t, "10.1.0.1/16"), []string{"group"}, ca, signer)
	t1 := mustNebulaToken(t, "test.lan", p.Name, p.audiences.Sign[0], now(), []string{"test.lan", "10.1.0.1"}, c1, priv)
	_, claims, err := parseToken(t1)
	if err != nil {
		t.Fatal(err)
	}

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
	crt, priv := mustNebulaCert(t, "test.lan", mustNebulaIPNet(t, "10.1.0.1/16"), []string{"test"}, ca, signer)
	ok := mustNebulaToken(t, "test.lan", p.Name, p.audiences.Sign[0], now(), []string{"test.lan", "10.1.0.1"}, crt, priv)
	okNoSANs := mustNebulaToken(t, "test.lan", p.Name, p.audiences.Sign[0], now(), nil, crt, priv)

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
	crt, priv := mustNebulaCert(t, "test.lan", mustNebulaIPNet(t, "10.1.0.1/16"), []string{"test"}, ca, signer)
	ok := mustNebulaSSHToken(t, "test.lan", p.Name, p.audiences.SSHSign[0], now(), &SignSSHOptions{
		CertType:   "host",
		KeyID:      "test.lan",
		Principals: []string{"test.lan", "10.1.0.1"},
	}, crt, priv)
	okNoOptions := mustNebulaSSHToken(t, "test.lan", p.Name, p.audiences.SSHSign[0], now(), nil, crt, priv)
	okWithValidity := mustNebulaSSHToken(t, "test.lan", p.Name, p.audiences.SSHSign[0], now(), &SignSSHOptions{
		ValidAfter:  NewTimeDuration(now().Add(1 * time.Hour)),
		ValidBefore: NewTimeDuration(now().Add(10 * time.Hour)),
	}, crt, priv)
	failUserCert := mustNebulaSSHToken(t, "test.lan", p.Name, p.audiences.SSHSign[0], now(), &SignSSHOptions{
		CertType: "user",
	}, crt, priv)
	failPrincipals := mustNebulaSSHToken(t, "test.lan", p.Name, p.audiences.SSHSign[0], now(), &SignSSHOptions{
		CertType:   "host",
		KeyID:      "test.lan",
		Principals: []string{"test.lan", "10.1.0.1", "foo.bar"},
	}, crt, priv)

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
		{"ok", p, args{ctx, &x509.Certificate{}}, false},
		{"fail disabled", pDisabled, args{ctx, &x509.Certificate{}}, true},
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
	crt, priv := mustNebulaCert(t, "test.lan", mustNebulaIPNet(t, "10.1.0.1/16"), []string{"test"}, ca, signer)
	ok := mustNebulaToken(t, "test.lan", p.Name, p.audiences.Revoke[0], now(), nil, crt, priv)

	// Fail different CA
	nc, signer := mustNebulaCA(t)
	crt, priv = mustNebulaCert(t, "test.lan", mustNebulaIPNet(t, "10.1.0.1/16"), []string{"test"}, nc, signer)
	failToken := mustNebulaToken(t, "test.lan", p.Name, p.audiences.Revoke[0], now(), nil, crt, priv)

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
	crt, priv := mustNebulaCert(t, "test.lan", mustNebulaIPNet(t, "10.1.0.1/16"), []string{"test"}, ca, signer)
	ok := mustNebulaSSHToken(t, "test.lan", p.Name, p.audiences.SSHRevoke[0], now(), nil, crt, priv)

	// Fail different CA
	nc, signer := mustNebulaCA(t)
	crt, priv = mustNebulaCert(t, "test.lan", mustNebulaIPNet(t, "10.1.0.1/16"), []string{"test"}, nc, signer)
	failToken := mustNebulaSSHToken(t, "test.lan", p.Name, p.audiences.SSHRevoke[0], now(), nil, crt, priv)

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
		{"ok", p, args{ctx, ok}, false},
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
	crt, priv := mustNebulaCert(t, "test.lan", mustNebulaIPNet(t, "10.1.0.1/16"), []string{"test"}, ca, signer)
	t1 := mustNebulaSSHToken(t, "test.lan", p.Name, p.audiences.SSHRenew[0], now(), nil, crt, priv)

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
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Nebula.AuthorizeSSHRenew() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNebula_AuthorizeSSHRekey(t *testing.T) {
	p, ca, signer := mustNebulaProvisioner(t)
	crt, priv := mustNebulaCert(t, "test.lan", mustNebulaIPNet(t, "10.1.0.1/16"), []string{"test"}, ca, signer)
	t1 := mustNebulaSSHToken(t, "test.lan", p.Name, p.audiences.SSHRekey[0], now(), nil, crt, priv)

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
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Nebula.AuthorizeSSHRekey() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("Nebula.AuthorizeSSHRekey() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
