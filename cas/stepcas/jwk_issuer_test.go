package stepcas

import (
	"net/url"
	"reflect"
	"testing"
	"time"

	"go.step.sm/crypto/jose"
)

func Test_jwkIssuer_SignToken(t *testing.T) {
	caURL, err := url.Parse("https://ca.smallstep.com")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := newJWKSignerFromEncryptedKey(testKeyID, testEncryptedJWKKey, testPassword)
	if err != nil {
		t.Fatal(err)
	}

	type fields struct {
		caURL  *url.URL
		issuer string
		signer jose.Signer
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
		{"ok", fields{caURL, "ra@doe.org", signer}, args{"doe", []string{"doe.org"}, nil}, false},
		{"ok ra", fields{caURL, "ra@doe.org", signer}, args{"doe", []string{"doe.org"}, &raInfo{
			AuthorityID: "authority-id", ProvisionerID: "provisioner-id", ProvisionerType: "provisioner-type",
		}}, false},
		{"ok ra endpoint id", fields{caURL, "ra@doe.org", signer}, args{"doe", []string{"doe.org"}, &raInfo{
			AuthorityID: "authority-id", EndpointID: "endpoint-id",
		}}, false},
		{"fail", fields{caURL, "ra@doe.org", &mockErrSigner{}}, args{"doe", []string{"doe.org"}, nil}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &jwkIssuer{
				caURL:  tt.fields.caURL,
				issuer: tt.fields.issuer,
				signer: tt.fields.signer,
			}
			got, err := i.SignToken(tt.args.subject, tt.args.sans, tt.args.info)
			if (err != nil) != tt.wantErr {
				t.Errorf("jwkIssuer.SignToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				jwt, err := jose.ParseSigned(got)
				if err != nil {
					t.Errorf("jose.ParseSigned() error = %v", err)
				}
				var c claims
				want := claims{
					Aud:  []string{tt.fields.caURL.String() + "/1.0/sign"},
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

func Test_jwkIssuer_RevokeToken(t *testing.T) {
	caURL, err := url.Parse("https://ca.smallstep.com")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := newJWKSignerFromEncryptedKey(testKeyID, testEncryptedJWKKey, testPassword)
	if err != nil {
		t.Fatal(err)
	}

	type fields struct {
		caURL  *url.URL
		issuer string
		signer jose.Signer
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
		{"ok", fields{caURL, "ra@doe.org", signer}, args{"doe"}, false},
		{"ok", fields{caURL, "ra@doe.org", &mockErrSigner{}}, args{"doe"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &jwkIssuer{
				caURL:  tt.fields.caURL,
				issuer: tt.fields.issuer,
				signer: tt.fields.signer,
			}
			got, err := i.RevokeToken(tt.args.subject)
			if (err != nil) != tt.wantErr {
				t.Errorf("jwkIssuer.RevokeToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				jwt, err := jose.ParseSigned(got)
				if err != nil {
					t.Errorf("jose.ParseSigned() error = %v", err)
				}
				var c claims
				want := claims{
					Aud: []string{tt.fields.caURL.String() + "/1.0/revoke"},
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

func Test_jwkIssuer_Lifetime(t *testing.T) {
	caURL, err := url.Parse("https://ca.smallstep.com")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := newJWKSignerFromEncryptedKey(testKeyID, testEncryptedJWKKey, testPassword)
	if err != nil {
		t.Fatal(err)
	}

	type fields struct {
		caURL  *url.URL
		issuer string
		signer jose.Signer
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
		{"ok", fields{caURL, "ra@smallstep.com", signer}, args{time.Second}, time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &jwkIssuer{
				caURL:  tt.fields.caURL,
				issuer: tt.fields.issuer,
				signer: tt.fields.signer,
			}
			if got := i.Lifetime(tt.args.d); got != tt.want {
				t.Errorf("jwkIssuer.Lifetime() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_newJWKSignerFromEncryptedKey(t *testing.T) {
	encrypt := func(plaintext string) string {
		recipient := jose.Recipient{
			Algorithm:  jose.PBES2_HS256_A128KW,
			Key:        testPassword,
			PBES2Count: jose.PBKDF2Iterations,
			PBES2Salt:  []byte{0x01, 0x02},
		}

		opts := new(jose.EncrypterOptions)
		opts.WithContentType(jose.ContentType("jwk+json"))

		encrypter, err := jose.NewEncrypter(jose.DefaultEncAlgorithm, recipient, opts)
		if err != nil {
			t.Fatal(err)
		}

		jwe, err := encrypter.Encrypt([]byte(plaintext))
		if err != nil {
			t.Fatal(err)
		}
		ret, err := jwe.CompactSerialize()
		if err != nil {
			t.Fatal(err)
		}
		return ret
	}

	type args struct {
		kid      string
		key      string
		password string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"ok", args{testKeyID, testEncryptedJWKKey, testPassword}, false},
		{"fail decrypt", args{testKeyID, testEncryptedJWKKey, "bad-password"}, true},
		{"fail unmarshal", args{testKeyID, encrypt(`{not a json}`), testPassword}, true},
		{"fail not signer", args{testKeyID, encrypt(`{"kty":"oct","k":"password"}`), testPassword}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newJWKSignerFromEncryptedKey(tt.args.kid, tt.args.key, tt.args.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("newJWKSignerFromEncryptedKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
