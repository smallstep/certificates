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
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"go.step.sm/crypto/jose"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/api/render"
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
	p2.config.tokenURL = p1.config.tokenURL

	p3, err := generateAWS()
	assert.FatalError(t, err)
	p3.Accounts = p1.Accounts
	p3.config.signatureURL = srv.URL
	p3.config.identityURL = p1.config.identityURL
	p3.config.tokenURL = p1.config.tokenURL

	p4, err := generateAWS()
	assert.FatalError(t, err)
	p4.Accounts = p1.Accounts
	p4.config.signatureURL = srv.URL + "/bad-signature"
	p4.config.identityURL = p1.config.identityURL
	p4.config.tokenURL = p1.config.tokenURL

	p5, err := generateAWS()
	assert.FatalError(t, err)
	p5.Accounts = p1.Accounts
	p5.config.identityURL = "https://1234.1234.1234.1234"
	p5.config.signatureURL = p1.config.signatureURL
	p5.config.tokenURL = p1.config.tokenURL

	p6, err := generateAWS()
	assert.FatalError(t, err)
	p6.Accounts = p1.Accounts
	p6.config.identityURL = p1.config.identityURL
	p6.config.signatureURL = "https://1234.1234.1234.1234"
	p6.config.tokenURL = p1.config.tokenURL

	p7, err := generateAWS()
	assert.FatalError(t, err)
	p7.Accounts = p1.Accounts
	p7.config.identityURL = srv.URL + "/bad-json"
	p7.config.signatureURL = p1.config.signatureURL
	p7.config.tokenURL = p1.config.tokenURL

	p8, err := generateAWS()
	assert.FatalError(t, err)
	p8.IMDSVersions = nil
	p8.Accounts = p1.Accounts
	p8.config = p1.config

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
		{"ok no imds", p8, args{"foo.local", caURL}, false},
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
					for _, crt := range tt.aws.config.certificates {
						err = crt.CheckSignature(tt.aws.config.signatureAlgorithm, c.Amazon.Document, c.Amazon.Signature)
						if err == nil {
							break
						}
					}
					assert.NoError(t, err)
				}
			}
		})
	}
}

func TestAWS_GetIdentityToken_V1Only(t *testing.T) {
	aws, srv, err := generateAWSWithServerV1Only()
	assert.FatalError(t, err)
	defer srv.Close()

	subject := "foo.local"
	caURL := "https://ca.smallstep.com"
	u, err := url.Parse(caURL)
	assert.Nil(t, err)

	token, err := aws.GetIdentityToken(subject, caURL)
	assert.Nil(t, err)

	_, c, err := parseAWSToken(token)
	if assert.NoError(t, err) {
		assert.Equals(t, awsIssuer, c.Issuer)
		assert.Equals(t, subject, c.Subject)
		assert.Equals(t, jose.Audience{u.ResolveReference(&url.URL{Path: "/1.0/sign", Fragment: aws.GetID()}).String()}, c.Audience)
		assert.Equals(t, aws.Accounts[0], c.document.AccountID)
		for _, crt := range aws.config.certificates {
			err = crt.CheckSignature(aws.config.signatureAlgorithm, c.Amazon.Document, c.Amazon.Signature)
			if err == nil {
				break
			}
		}
		assert.NoError(t, err)
	}
}

func TestAWS_GetIdentityToken_BadIDMS(t *testing.T) {
	aws, srv, err := generateAWSWithServer()

	aws.IMDSVersions = []string{"bad"}

	assert.FatalError(t, err)
	defer srv.Close()

	subject := "foo.local"
	caURL := "https://ca.smallstep.com"

	token, err := aws.GetIdentityToken(subject, caURL)
	assert.Equals(t, token, "")

	badIDMS := errors.New("bad: not a supported AWS Instance Metadata Service version")
	assert.HasSuffix(t, err.Error(), badIDMS.Error())
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
		IMDSVersions           []string
		IIDRoots               string
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
		{"ok", fields{"AWS", "name", []string{"account"}, false, false, zero, []string{"v1", "v2"}, "", nil}, args{config}, false},
		{"ok/v1", fields{"AWS", "name", []string{"account"}, false, false, zero, []string{"v1"}, "", nil}, args{config}, false},
		{"ok/v2", fields{"AWS", "name", []string{"account"}, false, false, zero, []string{"v2"}, "", nil}, args{config}, false},
		{"ok/empty", fields{"AWS", "name", []string{"account"}, false, false, zero, []string{}, "", nil}, args{config}, false},
		{"ok/duration", fields{"AWS", "name", []string{"account"}, true, true, Duration{Duration: 1 * time.Minute}, []string{"v1", "v2"}, "", nil}, args{config}, false},
		{"ok/cert", fields{"AWS", "name", []string{"account"}, false, false, zero, []string{"v1", "v2"}, "testdata/certs/aws.crt", nil}, args{config}, false},
		{"fail type ", fields{"", "name", []string{"account"}, false, false, zero, []string{"v1", "v2"}, "", nil}, args{config}, true},
		{"fail name", fields{"AWS", "", []string{"account"}, false, false, zero, []string{"v1", "v2"}, "", nil}, args{config}, true},
		{"bad instance age", fields{"AWS", "name", []string{"account"}, false, false, Duration{Duration: -1 * time.Minute}, []string{"v1", "v2"}, "", nil}, args{config}, true},
		{"fail/imds", fields{"AWS", "name", []string{"account"}, false, false, zero, []string{"bad"}, "", nil}, args{config}, true},
		{"fail/missing", fields{"AWS", "name", []string{"account"}, false, false, zero, []string{"bad"}, "testdata/missing.crt", nil}, args{config}, true},
		{"fail/cert", fields{"AWS", "name", []string{"account"}, false, false, zero, []string{"bad"}, "testdata/certs/rsa.csr", nil}, args{config}, true},
		{"fail claims", fields{"AWS", "name", []string{"account"}, false, false, zero, []string{"v1", "v2"}, "", badClaims}, args{config}, true},
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
				IMDSVersions:           tt.fields.IMDSVersions,
				IIDRoots:               tt.fields.IIDRoots,
				Claims:                 tt.fields.Claims,
			}
			if err := p.Init(tt.args.config); (err != nil) != tt.wantErr {
				t.Errorf("AWS.Init() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAWS_authorizeToken(t *testing.T) {
	block, _ := pem.Decode([]byte(awsTestKey))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		t.Fatal("error decoding AWS key")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	assert.FatalError(t, err)
	badKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.FatalError(t, err)

	type test struct {
		p     *AWS
		token string
		err   error
		code  int
	}
	tests := map[string]func(*testing.T) test{
		"fail/bad-token": func(t *testing.T) test {
			p, err := generateAWS()
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: "foo",
				code:  http.StatusUnauthorized,
				err:   errors.New("aws.authorizeToken; error parsing aws token"),
			}
		},
		"fail/cannot-validate-sig": func(t *testing.T) test {
			p, err := generateAWS()
			assert.FatalError(t, err)
			tok, err := generateAWSToken(
				p, "instance-id", awsIssuer, p.GetID(), p.Accounts[0], "instance-id",
				"127.0.0.1", "us-west-1", time.Now(), badKey)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("aws.authorizeToken; invalid aws token signature"),
			}
		},
		"fail/empty-account-id": func(t *testing.T) test {
			p, err := generateAWS()
			assert.FatalError(t, err)
			tok, err := generateAWSToken(
				p, "instance-id", awsIssuer, p.GetID(), "", "instance-id",
				"127.0.0.1", "us-west-1", time.Now(), key)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("aws.authorizeToken; aws identity document accountId cannot be empty"),
			}
		},
		"fail/empty-instance-id": func(t *testing.T) test {
			p, err := generateAWS()
			assert.FatalError(t, err)
			tok, err := generateAWSToken(
				p, "instance-id", awsIssuer, p.GetID(), p.Accounts[0], "",
				"127.0.0.1", "us-west-1", time.Now(), key)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("aws.authorizeToken; aws identity document instanceId cannot be empty"),
			}
		},
		"fail/empty-private-ip": func(t *testing.T) test {
			p, err := generateAWS()
			assert.FatalError(t, err)
			tok, err := generateAWSToken(
				p, "instance-id", awsIssuer, p.GetID(), p.Accounts[0], "instance-id",
				"", "us-west-1", time.Now(), key)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("aws.authorizeToken; aws identity document privateIp cannot be empty"),
			}
		},
		"fail/empty-region": func(t *testing.T) test {
			p, err := generateAWS()
			assert.FatalError(t, err)
			tok, err := generateAWSToken(
				p, "instance-id", awsIssuer, p.GetID(), p.Accounts[0], "instance-id",
				"127.0.0.1", "", time.Now(), key)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("aws.authorizeToken; aws identity document region cannot be empty"),
			}
		},
		"fail/invalid-token-issuer": func(t *testing.T) test {
			p, err := generateAWS()
			assert.FatalError(t, err)
			tok, err := generateAWSToken(
				p, "instance-id", "bad-issuer", p.GetID(), p.Accounts[0], "instance-id",
				"127.0.0.1", "us-west-1", time.Now(), key)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("aws.authorizeToken; invalid aws token"),
			}
		},
		"fail/invalid-audience": func(t *testing.T) test {
			p, err := generateAWS()
			assert.FatalError(t, err)
			tok, err := generateAWSToken(
				p, "instance-id", awsIssuer, "bad-audience", p.Accounts[0], "instance-id",
				"127.0.0.1", "us-west-1", time.Now(), key)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("aws.authorizeToken; invalid token - invalid audience claim (aud)"),
			}
		},
		"fail/invalid-subject-disabled-custom-SANs": func(t *testing.T) test {
			p, err := generateAWS()
			assert.FatalError(t, err)
			p.DisableCustomSANs = true
			tok, err := generateAWSToken(
				p, "foo", awsIssuer, p.GetID(), p.Accounts[0], "instance-id",
				"127.0.0.1", "us-west-1", time.Now(), key)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("aws.authorizeToken; invalid token - invalid subject claim (sub)"),
			}
		},
		"fail/invalid-account-id": func(t *testing.T) test {
			p, err := generateAWS()
			assert.FatalError(t, err)
			tok, err := generateAWSToken(
				p, "instance-id", awsIssuer, p.GetID(), "foo", "instance-id",
				"127.0.0.1", "us-west-1", time.Now(), key)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("aws.authorizeToken; invalid aws identity document - accountId is not valid"),
			}
		},
		"fail/instance-age": func(t *testing.T) test {
			p, err := generateAWS()
			assert.FatalError(t, err)
			p.InstanceAge = Duration{1 * time.Minute}
			tok, err := generateAWSToken(
				p, "instance-id", awsIssuer, p.GetID(), p.Accounts[0], "instance-id",
				"127.0.0.1", "us-west-1", time.Now().Add(-1*time.Minute), key)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("aws.authorizeToken; aws identity document pendingTime is too old"),
			}
		},
		"ok": func(t *testing.T) test {
			p, err := generateAWS()
			assert.FatalError(t, err)
			tok, err := generateAWSToken(
				p, "instance-id", awsIssuer, p.GetID(), p.Accounts[0], "instance-id",
				"127.0.0.1", "us-west-1", time.Now(), key)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
			}
		},
		"ok/identityCert": func(t *testing.T) test {
			p, err := generateAWS()
			p.IIDRoots = "testdata/certs/aws-test.crt"
			assert.FatalError(t, err)
			tok, err := generateAWSToken(
				p, "instance-id", awsIssuer, p.GetID(), p.Accounts[0], "instance-id",
				"127.0.0.1", "us-west-1", time.Now(), key)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
			}
		},
		"ok/identityCert2": func(t *testing.T) test {
			p, err := generateAWS()
			p.IIDRoots = "testdata/certs/aws.crt"
			assert.FatalError(t, err)
			tok, err := generateAWSToken(
				p, "instance-id", awsIssuer, p.GetID(), p.Accounts[0], "instance-id",
				"127.0.0.1", "us-west-1", time.Now(), key)
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
			if claims, err := tc.p.authorizeToken(tc.token); err != nil {
				if assert.NotNil(t, tc.err) {
					var sc render.StatusCodedError
					assert.Fatal(t, errors.As(err, &sc), "error does not implement StatusCodedError interface")
					assert.Equals(t, sc.StatusCode(), tc.code)
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) && assert.NotNil(t, claims) {
					assert.Equals(t, claims.Subject, "instance-id")
					assert.Equals(t, claims.Issuer, awsIssuer)
					assert.NotNil(t, claims.Amazon)

					aud, err := generateSignAudience("https://ca.smallstep.com", tc.p.GetID())
					assert.FatalError(t, err)
					assert.Equals(t, claims.Audience[0], aud)
				}
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

	badKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.FatalError(t, err)

	t4, err := generateAWSToken(
		p1, "instance-id", awsIssuer, p1.GetID(), p1.Accounts[0], "instance-id",
		"127.0.0.1", "us-west-1", time.Now(), key)
	assert.FatalError(t, err)
	failSubject, err := generateAWSToken(
		p2, "bad-subject", awsIssuer, p2.GetID(), p2.Accounts[0], "instance-id",
		"127.0.0.1", "us-west-1", time.Now(), key)
	assert.FatalError(t, err)
	failIssuer, err := generateAWSToken(
		p1, "instance-id", "bad-issuer", p1.GetID(), p1.Accounts[0], "instance-id",
		"127.0.0.1", "us-west-1", time.Now(), key)
	assert.FatalError(t, err)
	failAudience, err := generateAWSToken(
		p1, "instance-id", awsIssuer, "bad-audience", p1.Accounts[0], "instance-id",
		"127.0.0.1", "us-west-1", time.Now(), key)
	assert.FatalError(t, err)
	failAccount, err := generateAWSToken(
		p1, "instance-id", awsIssuer, p1.GetID(), "", "instance-id",
		"127.0.0.1", "us-west-1", time.Now(), key)
	assert.FatalError(t, err)
	failInstanceID, err := generateAWSToken(
		p1, "instance-id", awsIssuer, p1.GetID(), p1.Accounts[0], "",
		"127.0.0.1", "us-west-1", time.Now(), key)
	assert.FatalError(t, err)
	failPrivateIP, err := generateAWSToken(
		p1, "instance-id", awsIssuer, p1.GetID(), p1.Accounts[0], "instance-id",
		"", "us-west-1", time.Now(), key)
	assert.FatalError(t, err)
	failRegion, err := generateAWSToken(
		p1, "instance-id", awsIssuer, p1.GetID(), p1.Accounts[0], "instance-id",
		"127.0.0.1", "", time.Now(), key)
	assert.FatalError(t, err)
	failExp, err := generateAWSToken(
		p1, "instance-id", awsIssuer, p1.GetID(), p1.Accounts[0], "instance-id",
		"127.0.0.1", "us-west-1", time.Now().Add(-360*time.Second), key)
	assert.FatalError(t, err)
	failNbf, err := generateAWSToken(
		p1, "instance-id", awsIssuer, p1.GetID(), p1.Accounts[0], "instance-id",
		"127.0.0.1", "us-west-1", time.Now().Add(360*time.Second), key)
	assert.FatalError(t, err)
	failKey, err := generateAWSToken(
		p1, "instance-id", awsIssuer, p1.GetID(), p1.Accounts[0], "instance-id",
		"127.0.0.1", "us-west-1", time.Now(), badKey)
	assert.FatalError(t, err)
	failInstanceAge, err := generateAWSToken(
		p2, "instance-id", awsIssuer, p2.GetID(), p2.Accounts[0], "instance-id",
		"127.0.0.1", "us-west-1", time.Now().Add(-1*time.Minute), key)
	assert.FatalError(t, err)

	type args struct {
		token, cn string
	}
	tests := []struct {
		name    string
		aws     *AWS
		args    args
		wantLen int
		code    int
		wantErr bool
	}{
		{"ok", p1, args{t1, "foo.local"}, 9, http.StatusOK, false},
		{"ok", p2, args{t2, "instance-id"}, 13, http.StatusOK, false},
		{"ok", p2, args{t2Hostname, "ip-127-0-0-1.us-west-1.compute.internal"}, 13, http.StatusOK, false},
		{"ok", p2, args{t2PrivateIP, "127.0.0.1"}, 13, http.StatusOK, false},
		{"ok", p1, args{t4, "instance-id"}, 9, http.StatusOK, false},
		{"fail account", p3, args{token: t3}, 0, http.StatusUnauthorized, true},
		{"fail token", p1, args{token: "token"}, 0, http.StatusUnauthorized, true},
		{"fail subject", p1, args{token: failSubject}, 0, http.StatusUnauthorized, true},
		{"fail issuer", p1, args{token: failIssuer}, 0, http.StatusUnauthorized, true},
		{"fail audience", p1, args{token: failAudience}, 0, http.StatusUnauthorized, true},
		{"fail account", p1, args{token: failAccount}, 0, http.StatusUnauthorized, true},
		{"fail instanceID", p1, args{token: failInstanceID}, 0, http.StatusUnauthorized, true},
		{"fail privateIP", p1, args{token: failPrivateIP}, 0, http.StatusUnauthorized, true},
		{"fail region", p1, args{token: failRegion}, 0, http.StatusUnauthorized, true},
		{"fail exp", p1, args{token: failExp}, 0, http.StatusUnauthorized, true},
		{"fail nbf", p1, args{token: failNbf}, 0, http.StatusUnauthorized, true},
		{"fail key", p1, args{token: failKey}, 0, http.StatusUnauthorized, true},
		{"fail instance age", p2, args{token: failInstanceAge}, 0, http.StatusUnauthorized, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := NewContextWithMethod(context.Background(), SignMethod)
			switch got, err := tt.aws.AuthorizeSign(ctx, tt.args.token); {
			case (err != nil) != tt.wantErr:
				t.Errorf("AWS.AuthorizeSign() error = %v, wantErr %v", err, tt.wantErr)
				return
			case err != nil:
				var sc render.StatusCodedError
				assert.Fatal(t, errors.As(err, &sc), "error does not implement StatusCodedError interface")
				assert.Equals(t, sc.StatusCode(), tt.code)
			default:
				assert.Equals(t, tt.wantLen, len(got))
				for _, o := range got {
					switch v := o.(type) {
					case *AWS:
					case certificateOptionsFunc:
					case *provisionerExtensionOption:
						assert.Equals(t, v.Type, TypeAWS)
						assert.Equals(t, v.Name, tt.aws.GetName())
						assert.Equals(t, v.CredentialID, tt.aws.Accounts[0])
						assert.Len(t, 2, v.KeyValuePairs)
					case profileDefaultDuration:
						assert.Equals(t, time.Duration(v), tt.aws.ctl.Claimer.DefaultTLSCertDuration())
					case commonNameValidator:
						assert.Equals(t, string(v), tt.args.cn)
					case defaultPublicKeyValidator:
					case *validityValidator:
						assert.Equals(t, v.min, tt.aws.ctl.Claimer.MinTLSCertDuration())
						assert.Equals(t, v.max, tt.aws.ctl.Claimer.MaxTLSCertDuration())
					case ipAddressesValidator:
						assert.Equals(t, []net.IP(v), []net.IP{net.ParseIP("127.0.0.1")})
					case emailAddressesValidator:
						assert.Equals(t, v, nil)
					case urisValidator:
						assert.Equals(t, v, nil)
					case dnsNamesValidator:
						assert.Equals(t, []string(v), []string{"ip-127-0-0-1.us-west-1.compute.internal"})
					case *x509NamePolicyValidator:
						assert.Equals(t, nil, v.policyEngine)
					case *WebhookController:
						assert.Len(t, 0, v.webhooks)
					default:
						assert.FatalError(t, fmt.Errorf("unexpected sign option of type %T", v))
					}
				}
			}
		})
	}
}

func TestAWS_AuthorizeSSHSign(t *testing.T) {
	tm, fn := mockNow()
	defer fn()

	p1, srv, err := generateAWSWithServer()
	assert.FatalError(t, err)
	p1.DisableCustomSANs = true
	defer srv.Close()

	p2, err := generateAWS()
	assert.FatalError(t, err)
	p2.Accounts = p1.Accounts
	p2.config = p1.config
	p2.DisableCustomSANs = false

	p3, err := generateAWS()
	assert.FatalError(t, err)
	// disable sshCA
	disable := false
	p3.Claims = &Claims{EnableSSHCA: &disable}
	p3.ctl.Claimer, err = NewClaimer(p3.Claims, globalProvisionerClaims)
	assert.FatalError(t, err)

	t1, err := p1.GetIdentityToken("127.0.0.1", "https://ca.smallstep.com")
	assert.FatalError(t, err)

	t2, err := p2.GetIdentityToken("foo.local", "https://ca.smallstep.com")
	assert.FatalError(t, err)

	key, err := generateJSONWebKey()
	assert.FatalError(t, err)

	signer, err := generateJSONWebKey()
	assert.FatalError(t, err)

	pub := key.Public().Key
	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.FatalError(t, err)
	//nolint:gosec // tests minimum size of the key
	rsa1024, err := rsa.GenerateKey(rand.Reader, 1024)
	assert.FatalError(t, err)

	hostDuration := p1.ctl.Claimer.DefaultHostSSHCertDuration()
	expectedHostOptions := &SignSSHOptions{
		CertType: "host", Principals: []string{"127.0.0.1", "ip-127-0-0-1.us-west-1.compute.internal"},
		ValidAfter: NewTimeDuration(tm), ValidBefore: NewTimeDuration(tm.Add(hostDuration)),
	}
	expectedHostOptionsIP := &SignSSHOptions{
		CertType: "host", Principals: []string{"127.0.0.1"},
		ValidAfter: NewTimeDuration(tm), ValidBefore: NewTimeDuration(tm.Add(hostDuration)),
	}
	expectedHostOptionsHostname := &SignSSHOptions{
		CertType: "host", Principals: []string{"ip-127-0-0-1.us-west-1.compute.internal"},
		ValidAfter: NewTimeDuration(tm), ValidBefore: NewTimeDuration(tm.Add(hostDuration)),
	}
	expectedCustomOptions := &SignSSHOptions{
		CertType: "host", Principals: []string{"foo.local"},
		ValidAfter: NewTimeDuration(tm), ValidBefore: NewTimeDuration(tm.Add(hostDuration)),
	}

	type args struct {
		token   string
		sshOpts SignSSHOptions
		key     interface{}
	}
	tests := []struct {
		name        string
		aws         *AWS
		args        args
		expected    *SignSSHOptions
		code        int
		wantErr     bool
		wantSignErr bool
	}{
		{"ok", p1, args{t1, SignSSHOptions{}, pub}, expectedHostOptions, http.StatusOK, false, false},
		{"ok-rsa2048", p1, args{t1, SignSSHOptions{}, rsa2048.Public()}, expectedHostOptions, http.StatusOK, false, false},
		{"ok-type", p1, args{t1, SignSSHOptions{CertType: "host"}, pub}, expectedHostOptions, http.StatusOK, false, false},
		{"ok-principals", p1, args{t1, SignSSHOptions{Principals: []string{"127.0.0.1", "ip-127-0-0-1.us-west-1.compute.internal"}}, pub}, expectedHostOptions, http.StatusOK, false, false},
		{"ok-principal-ip", p1, args{t1, SignSSHOptions{Principals: []string{"127.0.0.1"}}, pub}, expectedHostOptionsIP, http.StatusOK, false, false},
		{"ok-principal-hostname", p1, args{t1, SignSSHOptions{Principals: []string{"ip-127-0-0-1.us-west-1.compute.internal"}}, pub}, expectedHostOptionsHostname, http.StatusOK, false, false},
		{"ok-options", p1, args{t1, SignSSHOptions{CertType: "host", Principals: []string{"127.0.0.1", "ip-127-0-0-1.us-west-1.compute.internal"}}, pub}, expectedHostOptions, http.StatusOK, false, false},
		{"ok-custom", p2, args{t2, SignSSHOptions{Principals: []string{"foo.local"}}, pub}, expectedCustomOptions, http.StatusOK, false, false},
		{"fail-rsa1024", p1, args{t1, SignSSHOptions{}, rsa1024.Public()}, expectedHostOptions, http.StatusOK, false, true},
		{"fail-type", p1, args{t1, SignSSHOptions{CertType: "user"}, pub}, nil, http.StatusOK, false, true},
		{"fail-principal", p1, args{t1, SignSSHOptions{Principals: []string{"smallstep.com"}}, pub}, nil, http.StatusOK, false, true},
		{"fail-extra-principal", p1, args{t1, SignSSHOptions{Principals: []string{"127.0.0.1", "ip-127-0-0-1.us-west-1.compute.internal", "smallstep.com"}}, pub}, nil, http.StatusOK, false, true},
		{"fail-sshCA-disabled", p3, args{"foo", SignSSHOptions{}, pub}, expectedHostOptions, http.StatusUnauthorized, true, false},
		{"fail-invalid-token", p1, args{"foo", SignSSHOptions{}, pub}, expectedHostOptions, http.StatusUnauthorized, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.aws.AuthorizeSSHSign(context.Background(), tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("AWS.AuthorizeSSHSign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				var sc render.StatusCodedError
				assert.Fatal(t, errors.As(err, &sc), "error does not implement StatusCodedError interface")
				assert.Equals(t, sc.StatusCode(), tt.code)
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

func TestAWS_AuthorizeRenew(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	p1, err := generateAWS()
	assert.FatalError(t, err)
	p2, err := generateAWS()
	assert.FatalError(t, err)

	// disable renewal
	disable := true
	p2.Claims = &Claims{DisableRenewal: &disable}
	p2.ctl.Claimer, err = NewClaimer(p2.Claims, globalProvisionerClaims)
	assert.FatalError(t, err)

	type args struct {
		cert *x509.Certificate
	}
	tests := []struct {
		name    string
		aws     *AWS
		args    args
		code    int
		wantErr bool
	}{
		{"ok", p1, args{&x509.Certificate{
			NotBefore: now,
			NotAfter:  now.Add(time.Hour),
		}}, http.StatusOK, false},
		{"fail/renew-disabled", p2, args{&x509.Certificate{
			NotBefore: now,
			NotAfter:  now.Add(time.Hour),
		}}, http.StatusUnauthorized, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.aws.AuthorizeRenew(context.Background(), tt.args.cert); (err != nil) != tt.wantErr {
				t.Errorf("AWS.AuthorizeRenew() error = %v, wantErr %v", err, tt.wantErr)
			} else if err != nil {
				var sc render.StatusCodedError
				assert.Fatal(t, errors.As(err, &sc), "error does not implement StatusCodedError interface")
				assert.Equals(t, sc.StatusCode(), tt.code)
			}
		})
	}
}
