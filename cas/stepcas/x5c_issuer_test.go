package stepcas

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net/url"
	"reflect"
	"testing"
	"time"

	"go.step.sm/crypto/jose"
)

type noneSigner []byte

func (b noneSigner) Public() crypto.PublicKey {
	return []byte(b)
}

func (b noneSigner) Sign(rnd io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return digest, nil
}

func fakeTime(t *testing.T) {
	t.Helper()
	tmp := timeNow
	t.Cleanup(func() {
		timeNow = tmp
	})
	timeNow = func() time.Time {
		return testX5CCrt.NotBefore
	}
}

func Test_x5cIssuer_SignToken(t *testing.T) {
	caURL, err := url.Parse("https://ca.smallstep.com")
	if err != nil {
		t.Fatal(err)
	}
	type fields struct {
		caURL    *url.URL
		certFile string
		keyFile  string
		issuer   string
	}
	type args struct {
		subject string
		sans    []string
		info    *raInfo
	}
	type stepClaims struct {
		RA *raInfo `json:"ra"`
	}
	type claims struct {
		Aud  []string   `json:"aud"`
		Sub  string     `json:"sub"`
		Sans []string   `json:"sans"`
		Step stepClaims `json:"step"`
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{"ok", fields{caURL, testX5CPath, testX5CKeyPath, "X5C"}, args{"doe", []string{"doe.org"}, nil}, false},
		{"ok ra", fields{caURL, testX5CPath, testX5CKeyPath, "X5C"}, args{"doe", []string{"doe.org"}, &raInfo{
			AuthorityID: "authority-id", ProvisionerID: "provisioner-id", ProvisionerType: "provisioner-type",
		}}, false},
		{"ok ra endpoint id", fields{caURL, testX5CPath, testX5CKeyPath, "X5C"}, args{"doe", []string{"doe.org"}, &raInfo{
			AuthorityID: "authority-id", EndpointID: "endpoint-id",
		}}, false},
		{"fail crt", fields{caURL, "", testX5CKeyPath, "X5C"}, args{"doe", []string{"doe.org"}, nil}, true},
		{"fail key", fields{caURL, testX5CPath, "", "X5C"}, args{"doe", []string{"doe.org"}, nil}, true},
		{"fail no signer", fields{caURL, testIssKeyPath, testIssPath, "X5C"}, args{"doe", []string{"doe.org"}, nil}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &x5cIssuer{
				caURL:    tt.fields.caURL,
				certFile: tt.fields.certFile,
				keyFile:  tt.fields.keyFile,
				issuer:   tt.fields.issuer,
			}
			got, err := i.SignToken(tt.args.subject, tt.args.sans, tt.args.info)
			if (err != nil) != tt.wantErr {
				t.Errorf("x5cIssuer.SignToken() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				jwt, err := jose.ParseSigned(got)
				if err != nil {
					t.Errorf("jose.ParseSigned() error = %v", err)
				}
				var c claims
				want := claims{
					Aud:  []string{tt.fields.caURL.String() + "/1.0/sign#x5c/X5C"},
					Sub:  tt.args.subject,
					Sans: tt.args.sans,
				}
				if tt.args.info != nil {
					want.Step.RA = tt.args.info
				}
				if err := jwt.Claims(testX5CKey.Public(), &c); err != nil {
					t.Errorf("jwt.Claims() error = %v", err)
				}
				if !reflect.DeepEqual(c, want) {
					t.Errorf("jwt.Claims() claims = %#v, want %#v", c, want)
				}
			}
		})
	}
}

func Test_x5cIssuer_RevokeToken(t *testing.T) {
	caURL, err := url.Parse("https://ca.smallstep.com")
	if err != nil {
		t.Fatal(err)
	}
	type fields struct {
		caURL    *url.URL
		certFile string
		keyFile  string
		issuer   string
	}
	type args struct {
		subject string
	}
	type claims struct {
		Aud  []string `json:"aud"`
		Sub  string   `json:"sub"`
		Sans []string `json:"sans"`
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{"ok", fields{caURL, testX5CPath, testX5CKeyPath, "X5C"}, args{"doe"}, false},
		{"fail crt", fields{caURL, "", testX5CKeyPath, "X5C"}, args{"doe"}, true},
		{"fail key", fields{caURL, testX5CPath, "", "X5C"}, args{"doe"}, true},
		{"fail no signer", fields{caURL, testIssKeyPath, testIssPath, "X5C"}, args{"doe"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &x5cIssuer{
				caURL:    tt.fields.caURL,
				certFile: tt.fields.certFile,
				keyFile:  tt.fields.keyFile,
				issuer:   tt.fields.issuer,
			}
			got, err := i.RevokeToken(tt.args.subject)
			if (err != nil) != tt.wantErr {
				t.Errorf("x5cIssuer.RevokeToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				jwt, err := jose.ParseSigned(got)
				if err != nil {
					t.Errorf("jose.ParseSigned() error = %v", err)
				}
				var c claims
				want := claims{
					Aud: []string{tt.fields.caURL.String() + "/1.0/revoke#x5c/X5C"},
					Sub: tt.args.subject,
				}
				if err := jwt.Claims(testX5CKey.Public(), &c); err != nil {
					t.Errorf("jwt.Claims() error = %v", err)
				}
				if !reflect.DeepEqual(c, want) {
					t.Errorf("jwt.Claims() claims = %#v, want %#v", c, want)
				}
			}
		})
	}
}

func Test_x5cIssuer_Lifetime(t *testing.T) {
	fakeTime(t)
	caURL, err := url.Parse("https://ca.smallstep.com")
	if err != nil {
		t.Fatal(err)
	}

	// With a leeway of 1m the max duration will be 59m.
	maxDuration := testX5CCrt.NotAfter.Sub(timeNow()) - time.Minute

	type fields struct {
		caURL    *url.URL
		certFile string
		keyFile  string
		issuer   string
	}
	type args struct {
		d time.Duration
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   time.Duration
	}{
		{"ok 0s", fields{caURL, testX5CPath, testX5CKeyPath, "X5C"}, args{0}, 0},
		{"ok 1m", fields{caURL, testX5CPath, testX5CKeyPath, "X5C"}, args{time.Minute}, time.Minute},
		{"ok max-1m", fields{caURL, testX5CPath, testX5CKeyPath, "X5C"}, args{maxDuration - time.Minute}, maxDuration - time.Minute},
		{"ok max", fields{caURL, testX5CPath, testX5CKeyPath, "X5C"}, args{maxDuration}, maxDuration},
		{"ok max+1m", fields{caURL, testX5CPath, testX5CKeyPath, "X5C"}, args{maxDuration + time.Minute}, maxDuration},
		{"ok fail", fields{caURL, testX5CPath + ".missing", testX5CKeyPath, "X5C"}, args{maxDuration + time.Minute}, maxDuration + time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &x5cIssuer{
				caURL:    tt.fields.caURL,
				certFile: tt.fields.certFile,
				keyFile:  tt.fields.keyFile,
				issuer:   tt.fields.issuer,
			}
			if got := i.Lifetime(tt.args.d); got != tt.want {
				t.Errorf("x5cIssuer.Lifetime() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_newJoseSigner(t *testing.T) {
	mustSigner := func(args ...interface{}) crypto.Signer {
		if err := args[len(args)-1]; err != nil {
			t.Fatal(err)
		}
		for _, a := range args {
			if s, ok := a.(crypto.Signer); ok {
				return s
			}
		}
		t.Fatal("signer not found")
		return nil
	}

	p224 := mustSigner(ecdsa.GenerateKey(elliptic.P224(), rand.Reader))
	p256 := mustSigner(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	p384 := mustSigner(ecdsa.GenerateKey(elliptic.P384(), rand.Reader))
	p521 := mustSigner(ecdsa.GenerateKey(elliptic.P521(), rand.Reader))
	edKey := mustSigner(ed25519.GenerateKey(rand.Reader))
	rsaKey := mustSigner(rsa.GenerateKey(rand.Reader, 2048))

	type args struct {
		key crypto.Signer
		so  *jose.SignerOptions
	}
	tests := []struct {
		name    string
		args    args
		want    []jose.Header
		wantErr bool
	}{
		{"p256", args{p256, nil}, []jose.Header{{Algorithm: "ES256"}}, false},
		{"p384", args{p384, new(jose.SignerOptions).WithType("JWT")}, []jose.Header{{Algorithm: "ES384", ExtraHeaders: map[jose.HeaderKey]interface{}{"typ": "JWT"}}}, false},
		{"p521", args{p521, new(jose.SignerOptions).WithHeader("kid", "the-kid")}, []jose.Header{{Algorithm: "ES512", KeyID: "the-kid"}}, false},
		{"ed25519", args{edKey, nil}, []jose.Header{{Algorithm: "EdDSA"}}, false},
		{"rsa", args{rsaKey, nil}, []jose.Header{{Algorithm: "RS256"}}, false},
		{"fail p224", args{p224, nil}, nil, true},
		{"fail signer", args{noneSigner{1, 2, 3}, nil}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newJoseSigner(tt.args.key, tt.args.so)
			if (err != nil) != tt.wantErr {
				t.Errorf("newJoseSigner() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				jws, err := got.Sign([]byte("{}"))
				if err != nil {
					t.Errorf("jose.Signer.Sign() err = %v", err)
				}
				jwt, err := jose.ParseSigned(jws.FullSerialize())
				if err != nil {
					t.Errorf("jose.ParseSigned() err = %v", err)
				}
				if !reflect.DeepEqual(jwt.Headers, tt.want) {
					t.Errorf("jose.Header got = %v, want = %v", jwt.Headers, tt.want)
				}
			}
		})
	}
}
