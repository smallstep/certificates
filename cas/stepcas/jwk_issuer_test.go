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

	type fields struct {
		caURL   *url.URL
		keyFile string
		issuer  string
	}
	type args struct {
		subject string
		sans    []string
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
		{"ok", fields{caURL, testX5CKeyPath, "ra@doe.org"}, args{"doe", []string{"doe.org"}}, false},
		{"fail key", fields{caURL, "", "ra@doe.org"}, args{"doe", []string{"doe.org"}}, true},
		{"fail no signer", fields{caURL, testIssPath, "ra@doe.org"}, args{"doe", []string{"doe.org"}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &jwkIssuer{
				caURL:   tt.fields.caURL,
				keyFile: tt.fields.keyFile,
				issuer:  tt.fields.issuer,
			}
			got, err := i.SignToken(tt.args.subject, tt.args.sans)
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

	type fields struct {
		caURL   *url.URL
		keyFile string
		issuer  string
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
		{"ok", fields{caURL, testX5CKeyPath, "ra@smallstep.com"}, args{"doe"}, false},
		{"fail key", fields{caURL, "", "ra@smallstep.com"}, args{"doe"}, true},
		{"fail no signer", fields{caURL, testIssPath, "ra@smallstep.com"}, args{"doe"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &jwkIssuer{
				caURL:   tt.fields.caURL,
				keyFile: tt.fields.keyFile,
				issuer:  tt.fields.issuer,
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

	type fields struct {
		caURL   *url.URL
		keyFile string
		issuer  string
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
		{"ok", fields{caURL, testX5CKeyPath, "ra@smallstep.com"}, args{time.Second}, time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &jwkIssuer{
				caURL:   tt.fields.caURL,
				keyFile: tt.fields.keyFile,
				issuer:  tt.fields.issuer,
			}
			if got := i.Lifetime(tt.args.d); got != tt.want {
				t.Errorf("jwkIssuer.Lifetime() = %v, want %v", got, tt.want)
			}
		})
	}
}
