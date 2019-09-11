package provisioner

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/smallstep/assert"
	"github.com/smallstep/cli/jose"
)

func TestAWS_Getters(t *testing.T) {
	p, err := generateAWS()
	assert.FatalError(t, err)
	aud := "aws/" + p.Name
	if got := p.GetID(); got != aud {
		t.Errorf("AWS.GetID() = %v, want %v", got, aud)
	}
	if got := p.GetName(); got != p.Name {
		t.Errorf("AWS.GetName() = %v, want %v", got, p.Name)
	}
	if got := p.GetType(); got != TypeAWS {
		t.Errorf("AWS.GetType() = %v, want %v", got, TypeAWS)
	}
	kid, key, ok := p.GetEncryptedKey()
	if kid != "" || key != "" || ok == true {
		t.Errorf("AWS.GetEncryptedKey() = (%v, %v, %v), want (%v, %v, %v)",
			kid, key, ok, "", "", false)
	}
}

func TestAWS_GetTokenID(t *testing.T) {
	p1, srv, err := generateAWSWithServer()
	assert.FatalError(t, err)
	defer srv.Close()

	p2, err := generateAWS()
	assert.FatalError(t, err)
	p2.Accounts = p1.Accounts
	p2.config = p1.config
	p2.DisableTrustOnFirstUse = true

	t1, err := p1.GetIdentityToken("foo.local", "https://ca.smallstep.com")
	assert.FatalError(t, err)
	_, claims, err := parseAWSToken(t1)
	assert.FatalError(t, err)
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s.%s", p1.GetID(), claims.document.InstanceID)))
	w1 := strings.ToLower(hex.EncodeToString(sum[:]))

	t2, err := p2.GetIdentityToken("foo.local", "https://ca.smallstep.com")
	assert.FatalError(t, err)
	sum = sha256.Sum256([]byte(t2))
	w2 := strings.ToLower(hex.EncodeToString(sum[:]))

	type args struct {
		token string
	}
	tests := []struct {
		name    string
		aws     *AWS
		args    args
		want    string
		wantErr bool
	}{
		{"ok", p1, args{t1}, w1, false},
		{"ok no TOFU", p2, args{t2}, w2, false},
		{"fail", p1, args{"bad-token"}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.aws.GetTokenID(tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("AWS.GetTokenID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("AWS.GetTokenID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAWS_GetIdentityToken(t *testing.T) {
	p1, srv, err := generateAWSWithServer()
	assert.FatalError(t, err)
	defer srv.Close()

	p2, err := generateAWS()
	assert.FatalError(t, err)
	p2.Accounts = p1.Accounts
	p2.config.identityURL = srv.URL + "/bad-document"
	p2.config.signatureURL = p1.config.signatureURL

	p3, err := generateAWS()
	assert.FatalError(t, err)
	p3.Accounts = p1.Accounts
	p3.config.signatureURL = srv.URL
	p3.config.identityURL = p1.config.identityURL

	p4, err := generateAWS()
	assert.FatalError(t, err)
	p4.Accounts = p1.Accounts
	p4.config.signatureURL = srv.URL + "/bad-signature"
	p4.config.identityURL = p1.config.identityURL

	p5, err := generateAWS()
	assert.FatalError(t, err)
	p5.Accounts = p1.Accounts
	p5.config.identityURL = "https://1234.1234.1234.1234"
	p5.config.signatureURL = p1.config.signatureURL

	p6, err := generateAWS()
	assert.FatalError(t, err)
	p6.Accounts = p1.Accounts
	p6.config.identityURL = p1.config.identityURL
	p6.config.signatureURL = "https://1234.1234.1234.1234"

	p7, err := generateAWS()
	assert.FatalError(t, err)
	p7.Accounts = p1.Accounts
	p7.config.identityURL = srv.URL + "/bad-json"
	p7.config.signatureURL = p1.config.signatureURL

	caURL := "https://ca.smallstep.com"
	u, err := url.Parse(caURL)
	assert.FatalError(t, err)

	type args struct {
		subject string
		caURL   string
	}
	tests := []struct {
		name    string
		aws     *AWS
		args    args
		wantErr bool
	}{
		{"ok", p1, args{"foo.local", caURL}, false},
		{"fail ca url", p1, args{"foo.local", "://ca.smallstep.com"}, true},
		{"fail identityURL", p2, args{"foo.local", caURL}, true},
		{"fail signatureURL", p3, args{"foo.local", caURL}, true},
		{"fail signature", p4, args{"foo.local", caURL}, true},
		{"fail read identityURL", p5, args{"foo.local", caURL}, true},
		{"fail read signatureURL", p6, args{"foo.local", caURL}, true},
		{"fail unmarshal identityURL", p7, args{"foo.local", caURL}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.aws.GetIdentityToken(tt.args.subject, tt.args.caURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("AWS.GetIdentityToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr == false {
				_, c, err := parseAWSToken(got)
				if assert.NoError(t, err) {
					assert.Equals(t, awsIssuer, c.Issuer)
					assert.Equals(t, tt.args.subject, c.Subject)
					assert.Equals(t, jose.Audience{u.ResolveReference(&url.URL{Path: "/1.0/sign", Fragment: tt.aws.GetID()}).String()}, c.Audience)
					assert.Equals(t, tt.aws.Accounts[0], c.document.AccountID)
					err = tt.aws.config.certificate.CheckSignature(
						tt.aws.config.signatureAlgorithm, c.Amazon.Document, c.Amazon.Signature)
					assert.NoError(t, err)
				}
			}
		})
	}
}

func TestAWS_Init(t *testing.T) {
	config := Config{
		Claims: globalProvisionerClaims,
	}
	badClaims := &Claims{
		DefaultTLSDur: &Duration{0},
	}
	zero := Duration{Duration: 0}

	type fields struct {
		Type                   string
		Name                   string
		Accounts               []string
		DisableCustomSANs      bool
		DisableTrustOnFirstUse bool
		InstanceAge            Duration
		Claims                 *Claims
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
		{"ok", fields{"AWS", "name", []string{"account"}, false, false, zero, nil}, args{config}, false},
		{"ok", fields{"AWS", "name", []string{"account"}, true, true, Duration{Duration: 1 * time.Minute}, nil}, args{config}, false},
		{"fail type ", fields{"", "name", []string{"account"}, false, false, zero, nil}, args{config}, true},
		{"fail name", fields{"AWS", "", []string{"account"}, false, false, zero, nil}, args{config}, true},
		{"bad instance age", fields{"AWS", "name", []string{"account"}, false, false, Duration{Duration: -1 * time.Minute}, nil}, args{config}, true},
		{"fail claims", fields{"AWS", "name", []string{"account"}, false, false, zero, badClaims}, args{config}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &AWS{
				Type:                   tt.fields.Type,
				Name:                   tt.fields.Name,
				Accounts:               tt.fields.Accounts,
				DisableCustomSANs:      tt.fields.DisableCustomSANs,
				DisableTrustOnFirstUse: tt.fields.DisableTrustOnFirstUse,
				InstanceAge:            tt.fields.InstanceAge,
				Claims:                 tt.fields.Claims,
			}
			if err := p.Init(tt.args.config); (err != nil) != tt.wantErr {
				t.Errorf("AWS.Init() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAWS_AuthorizeSign(t *testing.T) {
	p1, srv, err := generateAWSWithServer()
	assert.FatalError(t, err)
	defer srv.Close()

	p2, err := generateAWS()
	assert.FatalError(t, err)
	p2.Accounts = p1.Accounts
	p2.config = p1.config
	p2.DisableCustomSANs = true
	p2.InstanceAge = Duration{1 * time.Minute}

	p3, err := generateAWS()
	assert.FatalError(t, err)
	p3.config = p1.config

	t1, err := p1.GetIdentityToken("foo.local", "https://ca.smallstep.com")
	assert.FatalError(t, err)
	t2, err := p2.GetIdentityToken("instance-id", "https://ca.smallstep.com")
	assert.FatalError(t, err)
	assert.FatalError(t, err)
	t3, err := p3.GetIdentityToken("foo.local", "https://ca.smallstep.com")
	assert.FatalError(t, err)

	// Alternative common names with DisableCustomSANs = true
	t2PrivateIP, err := p2.GetIdentityToken("127.0.0.1", "https://ca.smallstep.com")
	assert.FatalError(t, err)
	t2Hostname, err := p2.GetIdentityToken("ip-127-0-0-1.us-west-1.compute.internal", "https://ca.smallstep.com")
	assert.FatalError(t, err)

	block, _ := pem.Decode([]byte(awsTestKey))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		t.Fatal("error decoding AWS key")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	assert.FatalError(t, err)

	badKey, err := rsa.GenerateKey(rand.Reader, 1024)
	assert.FatalError(t, err)

	t4, err := generateAWSToken(
		"instance-id", awsIssuer, p1.GetID(), p1.Accounts[0], "instance-id",
		"127.0.0.1", "us-west-1", time.Now(), key)
	assert.FatalError(t, err)
	failSubject, err := generateAWSToken(
		"bad-subject", awsIssuer, p2.GetID(), p2.Accounts[0], "instance-id",
		"127.0.0.1", "us-west-1", time.Now(), key)
	assert.FatalError(t, err)
	failIssuer, err := generateAWSToken(
		"instance-id", "bad-issuer", p1.GetID(), p1.Accounts[0], "instance-id",
		"127.0.0.1", "us-west-1", time.Now(), key)
	assert.FatalError(t, err)
	failAudience, err := generateAWSToken(
		"instance-id", awsIssuer, "bad-audience", p1.Accounts[0], "instance-id",
		"127.0.0.1", "us-west-1", time.Now(), key)
	assert.FatalError(t, err)
	failAccount, err := generateAWSToken(
		"instance-id", awsIssuer, p1.GetID(), "", "instance-id",
		"127.0.0.1", "us-west-1", time.Now(), key)
	assert.FatalError(t, err)
	failInstanceID, err := generateAWSToken(
		"instance-id", awsIssuer, p1.GetID(), p1.Accounts[0], "",
		"127.0.0.1", "us-west-1", time.Now(), key)
	assert.FatalError(t, err)
	failPrivateIP, err := generateAWSToken(
		"instance-id", awsIssuer, p1.GetID(), p1.Accounts[0], "instance-id",
		"", "us-west-1", time.Now(), key)
	assert.FatalError(t, err)
	failRegion, err := generateAWSToken(
		"instance-id", awsIssuer, p1.GetID(), p1.Accounts[0], "instance-id",
		"127.0.0.1", "", time.Now(), key)
	assert.FatalError(t, err)
	failExp, err := generateAWSToken(
		"instance-id", awsIssuer, p1.GetID(), p1.Accounts[0], "instance-id",
		"127.0.0.1", "us-west-1", time.Now().Add(-360*time.Second), key)
	assert.FatalError(t, err)
	failNbf, err := generateAWSToken(
		"instance-id", awsIssuer, p1.GetID(), p1.Accounts[0], "instance-id",
		"127.0.0.1", "us-west-1", time.Now().Add(360*time.Second), key)
	assert.FatalError(t, err)
	failKey, err := generateAWSToken(
		"instance-id", awsIssuer, p1.GetID(), p1.Accounts[0], "instance-id",
		"127.0.0.1", "us-west-1", time.Now(), badKey)
	assert.FatalError(t, err)
	failInstanceAge, err := generateAWSToken(
		"instance-id", awsIssuer, p2.GetID(), p2.Accounts[0], "instance-id",
		"127.0.0.1", "us-west-1", time.Now().Add(-1*time.Minute), key)
	assert.FatalError(t, err)

	type args struct {
		token string
	}
	tests := []struct {
		name    string
		aws     *AWS
		args    args
		wantLen int
		wantErr bool
	}{
		{"ok", p1, args{t1}, 5, false},
		{"ok", p2, args{t2}, 7, false},
		{"ok", p2, args{t2Hostname}, 7, false},
		{"ok", p2, args{t2PrivateIP}, 7, false},
		{"ok", p1, args{t4}, 5, false},
		{"fail account", p3, args{t3}, 0, true},
		{"fail token", p1, args{"token"}, 0, true},
		{"fail subject", p1, args{failSubject}, 0, true},
		{"fail issuer", p1, args{failIssuer}, 0, true},
		{"fail audience", p1, args{failAudience}, 0, true},
		{"fail account", p1, args{failAccount}, 0, true},
		{"fail instanceID", p1, args{failInstanceID}, 0, true},
		{"fail privateIP", p1, args{failPrivateIP}, 0, true},
		{"fail region", p1, args{failRegion}, 0, true},
		{"fail exp", p1, args{failExp}, 0, true},
		{"fail nbf", p1, args{failNbf}, 0, true},
		{"fail key", p1, args{failKey}, 0, true},
		{"fail instance age", p2, args{failInstanceAge}, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := NewContextWithMethod(context.Background(), SignMethod)
			got, err := tt.aws.AuthorizeSign(ctx, tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("AWS.AuthorizeSign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Len(t, tt.wantLen, got)
		})
	}
}

func TestAWS_AuthorizeSign_SSH(t *testing.T) {
	tm, fn := mockNow()
	defer fn()

	p1, srv, err := generateAWSWithServer()
	assert.FatalError(t, err)
	defer srv.Close()

	t1, err := p1.GetIdentityToken("foo.local", "https://ca.smallstep.com")
	assert.FatalError(t, err)

	key, err := generateJSONWebKey()
	assert.FatalError(t, err)

	signer, err := generateJSONWebKey()
	assert.FatalError(t, err)

	pub := key.Public().Key
	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.FatalError(t, err)
	rsa1024, err := rsa.GenerateKey(rand.Reader, 1024)
	assert.FatalError(t, err)

	hostDuration := p1.claimer.DefaultHostSSHCertDuration()
	expectedHostOptions := &SSHOptions{
		CertType: "host", Principals: []string{"127.0.0.1", "ip-127-0-0-1.us-west-1.compute.internal"},
		ValidAfter: NewTimeDuration(tm), ValidBefore: NewTimeDuration(tm.Add(hostDuration)),
	}
	expectedHostOptionsIP := &SSHOptions{
		CertType: "host", Principals: []string{"127.0.0.1"},
		ValidAfter: NewTimeDuration(tm), ValidBefore: NewTimeDuration(tm.Add(hostDuration)),
	}
	expectedHostOptionsHostname := &SSHOptions{
		CertType: "host", Principals: []string{"ip-127-0-0-1.us-west-1.compute.internal"},
		ValidAfter: NewTimeDuration(tm), ValidBefore: NewTimeDuration(tm.Add(hostDuration)),
	}

	type args struct {
		token   string
		sshOpts SSHOptions
		key     interface{}
	}
	tests := []struct {
		name        string
		aws         *AWS
		args        args
		expected    *SSHOptions
		wantErr     bool
		wantSignErr bool
	}{
		{"ok", p1, args{t1, SSHOptions{}, pub}, expectedHostOptions, false, false},
		{"ok-rsa2048", p1, args{t1, SSHOptions{}, rsa2048.Public()}, expectedHostOptions, false, false},
		{"ok-type", p1, args{t1, SSHOptions{CertType: "host"}, pub}, expectedHostOptions, false, false},
		{"ok-principals", p1, args{t1, SSHOptions{Principals: []string{"127.0.0.1", "ip-127-0-0-1.us-west-1.compute.internal"}}, pub}, expectedHostOptions, false, false},
		{"ok-principal-ip", p1, args{t1, SSHOptions{Principals: []string{"127.0.0.1"}}, pub}, expectedHostOptionsIP, false, false},
		{"ok-principal-hostname", p1, args{t1, SSHOptions{Principals: []string{"ip-127-0-0-1.us-west-1.compute.internal"}}, pub}, expectedHostOptionsHostname, false, false},
		{"ok-options", p1, args{t1, SSHOptions{CertType: "host", Principals: []string{"127.0.0.1", "ip-127-0-0-1.us-west-1.compute.internal"}}, pub}, expectedHostOptions, false, false},
		{"fail-rsa1024", p1, args{t1, SSHOptions{}, rsa1024.Public()}, expectedHostOptions, false, true},
		{"fail-type", p1, args{t1, SSHOptions{CertType: "user"}, pub}, nil, false, true},
		{"fail-principal", p1, args{t1, SSHOptions{Principals: []string{"smallstep.com"}}, pub}, nil, false, true},
		{"fail-extra-principal", p1, args{t1, SSHOptions{Principals: []string{"127.0.0.1", "ip-127-0-0-1.us-west-1.compute.internal", "smallstep.com"}}, pub}, nil, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := NewContextWithMethod(context.Background(), SignSSHMethod)
			got, err := tt.aws.AuthorizeSign(ctx, tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("AWS.AuthorizeSign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				assert.Nil(t, got)
			} else if assert.NotNil(t, got) {
				cert, err := signSSHCertificate(tt.args.key, tt.args.sshOpts, got, signer.Key.(crypto.Signer))
				if (err != nil) != tt.wantSignErr {
					t.Errorf("SignSSH error = %v, wantSignErr %v", err, tt.wantSignErr)
				} else {
					if tt.wantSignErr {
						assert.Nil(t, cert)
					} else {
						assert.NoError(t, validateSSHCertificate(cert, tt.expected))
					}
				}
			}
		})
	}
}
func TestAWS_AuthorizeRenewal(t *testing.T) {
	p1, err := generateAWS()
	assert.FatalError(t, err)
	p2, err := generateAWS()
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
		aws     *AWS
		args    args
		wantErr bool
	}{
		{"ok", p1, args{nil}, false},
		{"fail", p2, args{nil}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.aws.AuthorizeRenewal(tt.args.cert); (err != nil) != tt.wantErr {
				t.Errorf("AWS.AuthorizeRenewal() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAWS_AuthorizeRevoke(t *testing.T) {
	p1, srv, err := generateAWSWithServer()
	assert.FatalError(t, err)
	defer srv.Close()

	t1, err := p1.GetIdentityToken("foo.local", "https://ca.smallstep.com")
	assert.FatalError(t, err)

	type args struct {
		token string
	}
	tests := []struct {
		name    string
		aws     *AWS
		args    args
		wantErr bool
	}{
		{"ok", p1, args{t1}, true}, // revoke is disabled
		{"fail", p1, args{"token"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.aws.AuthorizeRevoke(tt.args.token); (err != nil) != tt.wantErr {
				t.Errorf("AWS.AuthorizeRevoke() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
