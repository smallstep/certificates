package provisioner

import (
	"context"
	"crypto/x509"
	"fmt"
	"reflect"
	"testing"
	"time"

	"go.step.sm/crypto/x509util"
	"go.step.sm/linkedca"
	"golang.org/x/crypto/ssh"

	"github.com/smallstep/certificates/authority/policy"
)

var trueValue = true

func mustClaimer(t *testing.T, claims *Claims, global Claims) *Claimer {
	t.Helper()
	c, err := NewClaimer(claims, global)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func mustDuration(t *testing.T, s string) *Duration {
	t.Helper()
	d, err := NewDuration(s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func mustNewPolicyEngine(t *testing.T, options *Options) *policyEngine {
	t.Helper()
	c, err := newPolicyEngine(options)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNewController(t *testing.T) {
	options := &Options{
		X509: &X509Options{
			AllowedNames: &policy.X509NameOptions{
				DNSDomains: []string{"*.local"},
			},
		},
		SSH: &SSHOptions{
			Host: &policy.SSHHostCertificateOptions{
				AllowedNames: &policy.SSHNameOptions{
					DNSDomains: []string{"*.local"},
				},
			},
			User: &policy.SSHUserCertificateOptions{
				AllowedNames: &policy.SSHNameOptions{
					EmailAddresses: []string{"@example.com"},
				},
			},
		},
	}
	type args struct {
		p       Interface
		claims  *Claims
		config  Config
		options *Options
	}
	tests := []struct {
		name    string
		args    args
		want    *Controller
		wantErr bool
	}{
		{"ok", args{&JWK{}, nil, Config{
			Claims:    globalProvisionerClaims,
			Audiences: testAudiences,
		}, nil}, &Controller{
			Interface: &JWK{},
			Audiences: &testAudiences,
			Claimer:   mustClaimer(t, nil, globalProvisionerClaims),
		}, false},
		{"ok with claims", args{&JWK{}, &Claims{
			DisableRenewal: &defaultDisableRenewal,
		}, Config{
			Claims:    globalProvisionerClaims,
			Audiences: testAudiences,
		}, nil}, &Controller{
			Interface: &JWK{},
			Audiences: &testAudiences,
			Claimer: mustClaimer(t, &Claims{
				DisableRenewal: &defaultDisableRenewal,
			}, globalProvisionerClaims),
		}, false},
		{"ok with claims and options", args{&JWK{}, &Claims{
			DisableRenewal: &defaultDisableRenewal,
		}, Config{
			Claims:    globalProvisionerClaims,
			Audiences: testAudiences,
		}, options}, &Controller{
			Interface: &JWK{},
			Audiences: &testAudiences,
			Claimer: mustClaimer(t, &Claims{
				DisableRenewal: &defaultDisableRenewal,
			}, globalProvisionerClaims),
			policy: mustNewPolicyEngine(t, options),
		}, false},
		{"fail claimer", args{&JWK{}, &Claims{
			MinTLSDur: mustDuration(t, "24h"),
			MaxTLSDur: mustDuration(t, "2h"),
		}, Config{
			Claims:    globalProvisionerClaims,
			Audiences: testAudiences,
		}, nil}, nil, true},
		{"fail options", args{&JWK{}, &Claims{
			DisableRenewal: &defaultDisableRenewal,
		}, Config{
			Claims:    globalProvisionerClaims,
			Audiences: testAudiences,
		}, &Options{
			X509: &X509Options{
				AllowedNames: &policy.X509NameOptions{
					DNSDomains: []string{"**.local"},
				},
			},
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewController(tt.args.p, tt.args.claims, tt.args.config, tt.args.options)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewController() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewController() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestController_GetIdentity(t *testing.T) {
	ctx := context.Background()
	type fields struct {
		Interface    Interface
		IdentityFunc GetIdentityFunc
	}
	type args struct {
		ctx   context.Context
		email string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *Identity
		wantErr bool
	}{
		{"ok", fields{&OIDC{}, nil}, args{ctx, "jane@doe.org"}, &Identity{
			Usernames: []string{"jane", "jane@doe.org"},
		}, false},
		{"ok custom", fields{&OIDC{}, func(ctx context.Context, p Interface, email string) (*Identity, error) {
			return &Identity{Usernames: []string{"jane"}}, nil
		}}, args{ctx, "jane@doe.org"}, &Identity{
			Usernames: []string{"jane"},
		}, false},
		{"fail provisioner", fields{&JWK{}, nil}, args{ctx, "jane@doe.org"}, nil, true},
		{"fail custom", fields{&OIDC{}, func(ctx context.Context, p Interface, email string) (*Identity, error) {
			return nil, fmt.Errorf("an error")
		}}, args{ctx, "jane@doe.org"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Controller{
				Interface:    tt.fields.Interface,
				IdentityFunc: tt.fields.IdentityFunc,
			}
			got, err := c.GetIdentity(tt.args.ctx, tt.args.email)
			if (err != nil) != tt.wantErr {
				t.Errorf("Controller.GetIdentity() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Controller.GetIdentity() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestController_AuthorizeRenew(t *testing.T) {
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)
	type fields struct {
		Interface          Interface
		Claimer            *Claimer
		AuthorizeRenewFunc AuthorizeRenewFunc
	}
	type args struct {
		ctx  context.Context
		cert *x509.Certificate
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{"ok", fields{&JWK{}, mustClaimer(t, nil, globalProvisionerClaims), nil}, args{ctx, &x509.Certificate{
			NotBefore: now,
			NotAfter:  now.Add(time.Hour),
		}}, false},
		{"ok custom", fields{&JWK{}, mustClaimer(t, nil, globalProvisionerClaims), func(ctx context.Context, p *Controller, cert *x509.Certificate) error {
			return nil
		}}, args{ctx, &x509.Certificate{
			NotBefore: now,
			NotAfter:  now.Add(time.Hour),
		}}, false},
		{"ok custom disabled", fields{&JWK{}, mustClaimer(t, &Claims{AllowRenewalAfterExpiry: &trueValue}, globalProvisionerClaims), func(ctx context.Context, p *Controller, cert *x509.Certificate) error {
			return nil
		}}, args{ctx, &x509.Certificate{
			NotBefore: now,
			NotAfter:  now.Add(time.Hour),
		}}, false},
		{"ok renew after expiry", fields{&JWK{}, mustClaimer(t, &Claims{AllowRenewalAfterExpiry: &trueValue}, globalProvisionerClaims), nil}, args{ctx, &x509.Certificate{
			NotBefore: now.Add(-time.Hour),
			NotAfter:  now.Add(-time.Minute),
		}}, false},
		{"fail disabled", fields{&JWK{}, mustClaimer(t, &Claims{DisableRenewal: &trueValue}, globalProvisionerClaims), nil}, args{ctx, &x509.Certificate{
			NotBefore: now,
			NotAfter:  now.Add(time.Hour),
		}}, true},
		{"fail not yet valid", fields{&JWK{}, mustClaimer(t, nil, globalProvisionerClaims), nil}, args{ctx, &x509.Certificate{
			NotBefore: now.Add(time.Hour),
			NotAfter:  now.Add(2 * time.Hour),
		}}, true},
		{"fail expired", fields{&JWK{}, mustClaimer(t, nil, globalProvisionerClaims), nil}, args{ctx, &x509.Certificate{
			NotBefore: now.Add(-time.Hour),
			NotAfter:  now.Add(-time.Minute),
		}}, true},
		{"fail custom", fields{&JWK{}, mustClaimer(t, nil, globalProvisionerClaims), func(ctx context.Context, p *Controller, cert *x509.Certificate) error {
			return fmt.Errorf("an error")
		}}, args{ctx, &x509.Certificate{
			NotBefore: now,
			NotAfter:  now.Add(time.Hour),
		}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Controller{
				Interface:          tt.fields.Interface,
				Claimer:            tt.fields.Claimer,
				AuthorizeRenewFunc: tt.fields.AuthorizeRenewFunc,
			}
			if err := c.AuthorizeRenew(tt.args.ctx, tt.args.cert); (err != nil) != tt.wantErr {
				t.Errorf("Controller.AuthorizeRenew() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestController_AuthorizeSSHRenew(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	type fields struct {
		Interface             Interface
		Claimer               *Claimer
		AuthorizeSSHRenewFunc AuthorizeSSHRenewFunc
	}
	type args struct {
		ctx  context.Context
		cert *ssh.Certificate
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{"ok", fields{&JWK{}, mustClaimer(t, nil, globalProvisionerClaims), nil}, args{ctx, &ssh.Certificate{
			ValidAfter:  uint64(now.Unix()),
			ValidBefore: uint64(now.Add(time.Hour).Unix()),
		}}, false},
		{"ok custom", fields{&JWK{}, mustClaimer(t, nil, globalProvisionerClaims), func(ctx context.Context, p *Controller, cert *ssh.Certificate) error {
			return nil
		}}, args{ctx, &ssh.Certificate{
			ValidAfter:  uint64(now.Unix()),
			ValidBefore: uint64(now.Add(time.Hour).Unix()),
		}}, false},
		{"ok custom disabled", fields{&JWK{}, mustClaimer(t, &Claims{AllowRenewalAfterExpiry: &trueValue}, globalProvisionerClaims), func(ctx context.Context, p *Controller, cert *ssh.Certificate) error {
			return nil
		}}, args{ctx, &ssh.Certificate{
			ValidAfter:  uint64(now.Unix()),
			ValidBefore: uint64(now.Add(time.Hour).Unix()),
		}}, false},
		{"ok renew after expiry", fields{&JWK{}, mustClaimer(t, &Claims{AllowRenewalAfterExpiry: &trueValue}, globalProvisionerClaims), nil}, args{ctx, &ssh.Certificate{
			ValidAfter:  uint64(now.Add(-time.Hour).Unix()),
			ValidBefore: uint64(now.Add(-time.Minute).Unix()),
		}}, false},
		{"fail disabled", fields{&JWK{}, mustClaimer(t, &Claims{DisableRenewal: &trueValue}, globalProvisionerClaims), nil}, args{ctx, &ssh.Certificate{
			ValidAfter:  uint64(now.Unix()),
			ValidBefore: uint64(now.Add(time.Hour).Unix()),
		}}, true},
		{"fail not yet valid", fields{&JWK{}, mustClaimer(t, nil, globalProvisionerClaims), nil}, args{ctx, &ssh.Certificate{
			ValidAfter:  uint64(now.Add(time.Hour).Unix()),
			ValidBefore: uint64(now.Add(2 * time.Hour).Unix()),
		}}, true},
		{"fail expired", fields{&JWK{}, mustClaimer(t, nil, globalProvisionerClaims), nil}, args{ctx, &ssh.Certificate{
			ValidAfter:  uint64(now.Add(-time.Hour).Unix()),
			ValidBefore: uint64(now.Add(-time.Minute).Unix()),
		}}, true},
		{"fail custom", fields{&JWK{}, mustClaimer(t, nil, globalProvisionerClaims), func(ctx context.Context, p *Controller, cert *ssh.Certificate) error {
			return fmt.Errorf("an error")
		}}, args{ctx, &ssh.Certificate{
			ValidAfter:  uint64(now.Unix()),
			ValidBefore: uint64(now.Add(time.Hour).Unix()),
		}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Controller{
				Interface:             tt.fields.Interface,
				Claimer:               tt.fields.Claimer,
				AuthorizeSSHRenewFunc: tt.fields.AuthorizeSSHRenewFunc,
			}
			if err := c.AuthorizeSSHRenew(tt.args.ctx, tt.args.cert); (err != nil) != tt.wantErr {
				t.Errorf("Controller.AuthorizeSSHRenew() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDefaultAuthorizeRenew(t *testing.T) {
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)
	type args struct {
		ctx  context.Context
		p    *Controller
		cert *x509.Certificate
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"ok", args{ctx, &Controller{
			Interface: &JWK{},
			Claimer:   mustClaimer(t, nil, globalProvisionerClaims),
		}, &x509.Certificate{
			NotBefore: now,
			NotAfter:  now.Add(time.Hour),
		}}, false},
		{"ok renew after expiry", args{ctx, &Controller{
			Interface: &JWK{},
			Claimer:   mustClaimer(t, &Claims{AllowRenewalAfterExpiry: &trueValue}, globalProvisionerClaims),
		}, &x509.Certificate{
			NotBefore: now.Add(-time.Hour),
			NotAfter:  now.Add(-time.Minute),
		}}, false},
		{"fail disabled", args{ctx, &Controller{
			Interface: &JWK{},
			Claimer:   mustClaimer(t, &Claims{DisableRenewal: &trueValue}, globalProvisionerClaims),
		}, &x509.Certificate{
			NotBefore: now,
			NotAfter:  now.Add(time.Hour),
		}}, true},
		{"fail not yet valid", args{ctx, &Controller{
			Interface: &JWK{},
			Claimer:   mustClaimer(t, &Claims{DisableRenewal: &trueValue}, globalProvisionerClaims),
		}, &x509.Certificate{
			NotBefore: now.Add(time.Hour),
			NotAfter:  now.Add(2 * time.Hour),
		}}, true},
		{"fail expired", args{ctx, &Controller{
			Interface: &JWK{},
			Claimer:   mustClaimer(t, &Claims{DisableRenewal: &trueValue}, globalProvisionerClaims),
		}, &x509.Certificate{
			NotBefore: now.Add(-time.Hour),
			NotAfter:  now.Add(-time.Minute),
		}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := DefaultAuthorizeRenew(tt.args.ctx, tt.args.p, tt.args.cert); (err != nil) != tt.wantErr {
				t.Errorf("DefaultAuthorizeRenew() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDefaultAuthorizeSSHRenew(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	type args struct {
		ctx  context.Context
		p    *Controller
		cert *ssh.Certificate
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"ok", args{ctx, &Controller{
			Interface: &JWK{},
			Claimer:   mustClaimer(t, nil, globalProvisionerClaims),
		}, &ssh.Certificate{
			ValidAfter:  uint64(now.Unix()),
			ValidBefore: uint64(now.Add(time.Hour).Unix()),
		}}, false},
		{"ok renew after expiry", args{ctx, &Controller{
			Interface: &JWK{},
			Claimer:   mustClaimer(t, &Claims{AllowRenewalAfterExpiry: &trueValue}, globalProvisionerClaims),
		}, &ssh.Certificate{
			ValidAfter:  uint64(now.Add(-time.Hour).Unix()),
			ValidBefore: uint64(now.Add(-time.Minute).Unix()),
		}}, false},
		{"fail disabled", args{ctx, &Controller{
			Interface: &JWK{},
			Claimer:   mustClaimer(t, &Claims{DisableRenewal: &trueValue}, globalProvisionerClaims),
		}, &ssh.Certificate{
			ValidAfter:  uint64(now.Unix()),
			ValidBefore: uint64(now.Add(time.Hour).Unix()),
		}}, true},
		{"fail not yet valid", args{ctx, &Controller{
			Interface: &JWK{},
			Claimer:   mustClaimer(t, &Claims{DisableRenewal: &trueValue}, globalProvisionerClaims),
		}, &ssh.Certificate{
			ValidAfter:  uint64(now.Add(time.Hour).Unix()),
			ValidBefore: uint64(now.Add(2 * time.Hour).Unix()),
		}}, true},
		{"fail expired", args{ctx, &Controller{
			Interface: &JWK{},
			Claimer:   mustClaimer(t, &Claims{DisableRenewal: &trueValue}, globalProvisionerClaims),
		}, &ssh.Certificate{
			ValidAfter:  uint64(now.Add(-time.Hour).Unix()),
			ValidBefore: uint64(now.Add(-time.Minute).Unix()),
		}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := DefaultAuthorizeSSHRenew(tt.args.ctx, tt.args.p, tt.args.cert); (err != nil) != tt.wantErr {
				t.Errorf("DefaultAuthorizeSSHRenew() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_newWebhookController(t *testing.T) {
	c := &Controller{}
	data := x509util.TemplateData{"foo": "bar"}
	ctl := c.newWebhookController(data, linkedca.Webhook_X509)
	if !reflect.DeepEqual(ctl.TemplateData, data) {
		t.Error("Failed to set templateData")
	}
	if ctl.certType != linkedca.Webhook_X509 {
		t.Error("Failed to set certType")
	}
	if ctl.client == nil {
		t.Error("Failed to set client")
	}
}
