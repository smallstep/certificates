package provisioner

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"net"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
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
	if ip = ip.To4(); ip == nil {
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
			Subnets:   []*net.IPNet{},
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

	invertedGroups := make(map[string]struct{}, len(groups))
	for _, name := range groups {
		invertedGroups[name] = struct{}{}
	}

	t1 := time.Now().Truncate(time.Second)
	nc := &cert.NebulaCertificate{
		Details: cert.NebulaCertificateDetails{
			Name:           name,
			Ips:            []*net.IPNet{ipNet},
			Subnets:        []*net.IPNet{},
			Groups:         groups,
			NotBefore:      t1,
			NotAfter:       t1.Add(5 * time.Minute),
			PublicKey:      pub,
			IsCA:           false,
			Issuer:         issuer,
			InvertedGroups: invertedGroups,
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
	ncDer, err := nc.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	so := new(jose.SignerOptions)
	so.WithType("JWT")
	so.WithHeader(NebulaCertHeader, ncDer)

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
	ncDer, err := nc.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	so := new(jose.SignerOptions)
	so.WithType("JWT")
	so.WithHeader(NebulaCertHeader, ncDer)

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
	c1, priv := mustNebulaCert(t, "test.lan", mustNebulaIPNet(t, "10.1.0.1/16"), []string{"group"}, ca, signer)
	t1 := mustNebulaToken(t, "test.lan", p.Name, p.ctl.Audiences.Sign[0], now(), []string{"test.lan", "10.1.0.1"}, c1, priv)
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
	ok := mustNebulaToken(t, "test.lan", p.Name, p.ctl.Audiences.Sign[0], now(), []string{"test.lan", "10.1.0.1"}, crt, priv)
	okNoSANs := mustNebulaToken(t, "test.lan", p.Name, p.ctl.Audiences.Sign[0], now(), nil, crt, priv)

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
	ok := mustNebulaSSHToken(t, "test.lan", p.Name, p.ctl.Audiences.SSHSign[0], now(), &SignSSHOptions{
		CertType:   "host",
		KeyID:      "test.lan",
		Principals: []string{"test.lan", "10.1.0.1"},
	}, crt, priv)
	okNoOptions := mustNebulaSSHToken(t, "test.lan", p.Name, p.ctl.Audiences.SSHSign[0], now(), nil, crt, priv)
	okWithValidity := mustNebulaSSHToken(t, "test.lan", p.Name, p.ctl.Audiences.SSHSign[0], now(), &SignSSHOptions{
		ValidAfter:  NewTimeDuration(now().Add(1 * time.Hour)),
		ValidBefore: NewTimeDuration(now().Add(10 * time.Hour)),
	}, crt, priv)
	failUserCert := mustNebulaSSHToken(t, "test.lan", p.Name, p.ctl.Audiences.SSHSign[0], now(), &SignSSHOptions{
		CertType: "user",
	}, crt, priv)
	failPrincipals := mustNebulaSSHToken(t, "test.lan", p.Name, p.ctl.Audiences.SSHSign[0], now(), &SignSSHOptions{
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
	crt, priv := mustNebulaCert(t, "test.lan", mustNebulaIPNet(t, "10.1.0.1/16"), []string{"test"}, ca, signer)
	ok := mustNebulaToken(t, "test.lan", p.Name, p.ctl.Audiences.Revoke[0], now(), nil, crt, priv)

	// Fail different CA
	nc, signer := mustNebulaCA(t)
	crt, priv = mustNebulaCert(t, "test.lan", mustNebulaIPNet(t, "10.1.0.1/16"), []string{"test"}, nc, signer)
	failToken := mustNebulaToken(t, "test.lan", p.Name, p.ctl.Audiences.Revoke[0], now(), nil, crt, priv)

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
	ok := mustNebulaSSHToken(t, "test.lan", p.Name, p.ctl.Audiences.SSHRevoke[0], now(), nil, crt, priv)

	// Fail different CA
	nc, signer := mustNebulaCA(t)
	crt, priv = mustNebulaCert(t, "test.lan", mustNebulaIPNet(t, "10.1.0.1/16"), []string{"test"}, nc, signer)
	failToken := mustNebulaSSHToken(t, "test.lan", p.Name, p.ctl.Audiences.SSHRevoke[0], now(), nil, crt, priv)

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
	t1 := mustNebulaSSHToken(t, "test.lan", p.Name, p.ctl.Audiences.SSHRenew[0], now(), nil, crt, priv)

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
	t1 := mustNebulaSSHToken(t, "test.lan", p.Name, p.ctl.Audiences.SSHRekey[0], now(), nil, crt, priv)

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

func TestNebula_authorizeToken(t *testing.T) {
	t1 := now()
	p, ca, signer := mustNebulaProvisioner(t)
	crt, priv := mustNebulaCert(t, "test.lan", mustNebulaIPNet(t, "10.1.0.1/16"), []string{"test"}, ca, signer)
	ok := mustNebulaToken(t, "test.lan", p.Name, p.ctl.Audiences.Sign[0], t1, []string{"10.1.0.1"}, crt, priv)
	okNoSANs := mustNebulaToken(t, "test.lan", p.Name, p.ctl.Audiences.Sign[0], t1, nil, crt, priv)
	okSSH := mustNebulaSSHToken(t, "test.lan", p.Name, p.ctl.Audiences.SSHSign[0], t1, &SignSSHOptions{
		CertType:   "host",
		KeyID:      "test.lan",
		Principals: []string{"test.lan"},
	}, crt, priv)
	okSSHNoOptions := mustNebulaSSHToken(t, "test.lan", p.Name, p.ctl.Audiences.SSHSign[0], t1, nil, crt, priv)

	// Token with errors
	failNotBefore := mustNebulaToken(t, "test.lan", p.Name, p.ctl.Audiences.Sign[0], t1.Add(1*time.Hour), []string{"10.1.0.1"}, crt, priv)
	failIssuer := mustNebulaToken(t, "test.lan", "foo", p.ctl.Audiences.Sign[0], t1, []string{"10.1.0.1"}, crt, priv)
	failAudience := mustNebulaToken(t, "test.lan", p.Name, "foo", t1, []string{"10.1.0.1"}, crt, priv)
	failSubject := mustNebulaToken(t, "", p.Name, p.ctl.Audiences.Sign[0], t1, []string{"10.1.0.1"}, crt, priv)

	// Not a nebula token
	jwk, err := generateJSONWebKey()
	if err != nil {
		t.Fatal(err)
	}
	simpleToken, err := generateSimpleToken("iss", "aud", jwk)
	if err != nil {
		t.Fatal(err)
	}

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
		name    string
		p       *Nebula
		args    args
		want    *cert.NebulaCertificate
		want1   *jwtPayload
		wantErr bool
	}{
		{"ok x509", p, args{ok, p.ctl.Audiences.Sign}, crt, &jwtPayload{
			Claims: x509Claims,
			SANs:   []string{"10.1.0.1"},
		}, false},
		{"ok x509 no sans", p, args{okNoSANs, p.ctl.Audiences.Sign}, crt, &jwtPayload{
			Claims: x509Claims,
		}, false},
		{"ok ssh", p, args{okSSH, p.ctl.Audiences.SSHSign}, crt, &jwtPayload{
			Claims: sshClaims,
			Step: &stepPayload{
				SSH: &SignSSHOptions{
					CertType:   "host",
					KeyID:      "test.lan",
					Principals: []string{"test.lan"},
				},
			},
		}, false},
		{"ok ssh no principals", p, args{okSSHNoOptions, p.ctl.Audiences.SSHSign}, crt, &jwtPayload{
			Claims: sshClaims,
		}, false},
		{"fail parse", p, args{"bad.token", p.ctl.Audiences.Sign}, nil, nil, true},
		{"fail header", p, args{simpleToken, p.ctl.Audiences.Sign}, nil, nil, true},
		{"fail verify", p2, args{ok, p.ctl.Audiences.Sign}, nil, nil, true},
		{"fail claims nbf", p, args{failNotBefore, p.ctl.Audiences.Sign}, nil, nil, true},
		{"fail claims iss", p, args{failIssuer, p.ctl.Audiences.Sign}, nil, nil, true},
		{"fail claims aud", p, args{failAudience, p.ctl.Audiences.Sign}, nil, nil, true},
		{"fail claims sub", p, args{failSubject, p.ctl.Audiences.Sign}, nil, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := tt.p.authorizeToken(tt.args.token, tt.args.audiences)
			if (err != nil) != tt.wantErr {
				t.Errorf("Nebula.authorizeToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Nebula.authorizeToken() got = %#v, want %#v", got, tt.want)
				t.Error(cmp.Equal(got, tt.want))
			}

			if got1 != nil && tt.want1 != nil {
				tt.want1.ID = got1.ID
			}

			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("Nebula.authorizeToken() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func Test_nebulaSANsValidator_Valid(t *testing.T) {
	ipNet := mustNebulaIPNet(t, "10.1.2.3/16")
	type fields struct {
		Name string
		IPs  []*net.IPNet
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
		{"ok", fields{"dns.name", []*net.IPNet{ipNet}}, args{&x509.CertificateRequest{
			DNSNames:    []string{"dns.name"},
			IPAddresses: []net.IP{net.IPv4(10, 1, 2, 3)},
		}}, false},
		{"ok name only", fields{"dns.name", []*net.IPNet{ipNet}}, args{&x509.CertificateRequest{
			DNSNames: []string{"dns.name"},
		}}, false},
		{"ok ip only", fields{"dns.name", []*net.IPNet{ipNet}}, args{&x509.CertificateRequest{
			IPAddresses: []net.IP{net.IPv4(10, 1, 2, 3)},
		}}, false},
		{"ok email name", fields{"jane@doe.org", []*net.IPNet{ipNet}}, args{&x509.CertificateRequest{
			EmailAddresses: []string{"jane@doe.org"},
			IPAddresses:    []net.IP{net.IPv4(10, 1, 2, 3)},
		}}, false},
		{"ok uri name", fields{"urn:foobar", []*net.IPNet{ipNet}}, args{&x509.CertificateRequest{
			URIs:        []*url.URL{{Scheme: "urn", Opaque: "foobar"}},
			IPAddresses: []net.IP{net.IPv4(10, 1, 2, 3)},
		}}, false},
		{"ok ip name", fields{"127.0.0.1", []*net.IPNet{ipNet}}, args{&x509.CertificateRequest{
			IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv4(10, 1, 2, 3)},
		}}, false},
		{"ok multiple ips", fields{"dns.name", []*net.IPNet{ipNet, mustNebulaIPNet(t, "10.2.2.3/8")}}, args{&x509.CertificateRequest{
			DNSNames:    []string{"dns.name"},
			IPAddresses: []net.IP{net.IPv4(10, 1, 2, 3), net.IPv4(10, 2, 2, 3)},
		}}, false},
		{"fail dns", fields{"fail.name", []*net.IPNet{ipNet}}, args{&x509.CertificateRequest{
			DNSNames:    []string{"dns.name"},
			IPAddresses: []net.IP{net.IPv4(10, 1, 2, 3)},
		}}, true},
		{"fail email", fields{"fail@doe.org", []*net.IPNet{ipNet}}, args{&x509.CertificateRequest{
			EmailAddresses: []string{"jane@doe.org"},
			IPAddresses:    []net.IP{net.IPv4(10, 1, 2, 3)},
		}}, true},
		{"fail uri", fields{"urn:barfoo", []*net.IPNet{ipNet}}, args{&x509.CertificateRequest{
			URIs:        []*url.URL{{Scheme: "urn", Opaque: "foobar"}},
			IPAddresses: []net.IP{net.IPv4(10, 1, 2, 3)},
		}}, true},
		{"fail ip", fields{"127.0.0.1", []*net.IPNet{ipNet}}, args{&x509.CertificateRequest{
			IPAddresses: []net.IP{net.IPv4(10, 1, 2, 1), net.IPv4(10, 1, 2, 3)},
		}}, true},
		{"fail nebula ip", fields{"dns.name", []*net.IPNet{ipNet}}, args{&x509.CertificateRequest{
			DNSNames:    []string{"dns.name"},
			IPAddresses: []net.IP{net.IPv4(10, 2, 2, 3)},
		}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := nebulaSANsValidator{
				Name: tt.fields.Name,
				IPs:  tt.fields.IPs,
			}
			if err := v.Valid(tt.args.req); (err != nil) != tt.wantErr {
				t.Errorf("nebulaSANsValidator.Valid() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_nebulaPrincipalsValidator_Valid(t *testing.T) {
	ipNet := mustNebulaIPNet(t, "10.1.2.3/16")

	type fields struct {
		Name string
		IPs  []*net.IPNet
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
		{"ok", fields{"dns.name", []*net.IPNet{ipNet}}, args{SignSSHOptions{
			Principals: []string{"dns.name", "10.1.2.3"},
		}}, false},
		{"ok name", fields{"dns.name", []*net.IPNet{ipNet}}, args{SignSSHOptions{
			Principals: []string{"dns.name"},
		}}, false},
		{"ok ip", fields{"dns.name", []*net.IPNet{ipNet}}, args{SignSSHOptions{
			Principals: []string{"10.1.2.3"},
		}}, false},
		{"fail name", fields{"dns.name", []*net.IPNet{ipNet}}, args{SignSSHOptions{
			Principals: []string{"foo.name", "10.1.2.3"},
		}}, true},
		{"fail ip", fields{"dns.name", []*net.IPNet{ipNet}}, args{SignSSHOptions{
			Principals: []string{"dns.name", "10.2.2.3"},
		}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := nebulaPrincipalsValidator{
				Name: tt.fields.Name,
				IPs:  tt.fields.IPs,
			}
			if err := v.Valid(tt.args.got); (err != nil) != tt.wantErr {
				t.Errorf("nebulaPrincipalsValidator.Valid() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
