package provisioner

import (
	"crypto/x509"
	"reflect"
	"testing"

	"github.com/smallstep/assert"
)

func TestAzure_Getters(t *testing.T) {
	p, err := generateAzure()
	assert.FatalError(t, err)
	if got := p.GetID(); got != p.TenantID {
		t.Errorf("Azure.GetID() = %v, want %v", got, p.TenantID)
	}
	if got := p.GetName(); got != p.Name {
		t.Errorf("Azure.GetName() = %v, want %v", got, p.Name)
	}
	if got := p.GetType(); got != TypeAzure {
		t.Errorf("Azure.GetType() = %v, want %v", got, TypeAzure)
	}
	kid, key, ok := p.GetEncryptedKey()
	if kid != "" || key != "" || ok == true {
		t.Errorf("Azure.GetEncryptedKey() = (%v, %v, %v), want (%v, %v, %v)",
			kid, key, ok, "", "", false)
	}
}

func TestAzure_GetTokenID(t *testing.T) {
	type fields struct {
		Type                   string
		Name                   string
		DisableCustomSANs      bool
		DisableTrustOnFirstUse bool
		Claims                 *Claims
		claimer                *Claimer
		config                 *azureConfig
	}
	type args struct {
		token string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Azure{
				Type:                   tt.fields.Type,
				Name:                   tt.fields.Name,
				DisableCustomSANs:      tt.fields.DisableCustomSANs,
				DisableTrustOnFirstUse: tt.fields.DisableTrustOnFirstUse,
				Claims:                 tt.fields.Claims,
				claimer:                tt.fields.claimer,
				config:                 tt.fields.config,
			}
			got, err := p.GetTokenID(tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("Azure.GetTokenID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Azure.GetTokenID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAzure_Init(t *testing.T) {
	az, srv, err := generateAzureWithServer()
	assert.FatalError(t, err)
	defer srv.Close()

	config := Config{
		Claims: globalProvisionerClaims,
	}
	badClaims := &Claims{
		DefaultTLSDur: &Duration{0},
	}

	type fields struct {
		Type                   string
		Name                   string
		TenantID               string
		DisableCustomSANs      bool
		DisableTrustOnFirstUse bool
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
		{"ok", fields{az.Type, az.Name, az.TenantID, false, false, nil}, args{config}, false},
		{"ok", fields{az.Type, az.Name, az.TenantID, true, false, nil}, args{config}, false},
		{"ok", fields{az.Type, az.Name, az.TenantID, false, true, nil}, args{config}, false},
		{"ok", fields{az.Type, az.Name, az.TenantID, true, true, nil}, args{config}, false},
		{"fail type", fields{"", az.Name, az.TenantID, false, false, nil}, args{config}, true},
		{"fail name", fields{az.Type, "", az.TenantID, false, false, nil}, args{config}, true},
		{"fail tenant id", fields{az.Type, az.Name, "", false, false, nil}, args{config}, true},
		{"fail claims", fields{az.Type, az.Name, az.TenantID, false, false, badClaims}, args{config}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Azure{
				Type:                   tt.fields.Type,
				Name:                   tt.fields.Name,
				TenantID:               tt.fields.TenantID,
				DisableCustomSANs:      tt.fields.DisableCustomSANs,
				DisableTrustOnFirstUse: tt.fields.DisableTrustOnFirstUse,
				Claims:                 tt.fields.Claims,
				config:                 az.config,
			}
			if err := p.Init(tt.args.config); (err != nil) != tt.wantErr {
				t.Errorf("Azure.Init() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAzure_AuthorizeSign(t *testing.T) {
	type fields struct {
		Type                   string
		Name                   string
		DisableCustomSANs      bool
		DisableTrustOnFirstUse bool
		Claims                 *Claims
		claimer                *Claimer
		config                 *azureConfig
	}
	type args struct {
		token string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []SignOption
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Azure{
				Type:                   tt.fields.Type,
				Name:                   tt.fields.Name,
				DisableCustomSANs:      tt.fields.DisableCustomSANs,
				DisableTrustOnFirstUse: tt.fields.DisableTrustOnFirstUse,
				Claims:                 tt.fields.Claims,
				claimer:                tt.fields.claimer,
				config:                 tt.fields.config,
			}
			got, err := p.AuthorizeSign(tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("Azure.AuthorizeSign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Azure.AuthorizeSign() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAzure_AuthorizeRenewal(t *testing.T) {
	p1, err := generateAzure()
	assert.FatalError(t, err)
	p2, err := generateAzure()
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
		azure   *Azure
		args    args
		wantErr bool
	}{
		{"ok", p1, args{nil}, false},
		{"fail", p2, args{nil}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.azure.AuthorizeRenewal(tt.args.cert); (err != nil) != tt.wantErr {
				t.Errorf("Azure.AuthorizeRenewal() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAzure_AuthorizeRevoke(t *testing.T) {
	type fields struct {
		Type                   string
		Name                   string
		DisableCustomSANs      bool
		DisableTrustOnFirstUse bool
		Claims                 *Claims
		claimer                *Claimer
		config                 *azureConfig
	}
	type args struct {
		token string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Azure{
				Type:                   tt.fields.Type,
				Name:                   tt.fields.Name,
				DisableCustomSANs:      tt.fields.DisableCustomSANs,
				DisableTrustOnFirstUse: tt.fields.DisableTrustOnFirstUse,
				Claims:                 tt.fields.Claims,
				claimer:                tt.fields.claimer,
				config:                 tt.fields.config,
			}
			if err := p.AuthorizeRevoke(tt.args.token); (err != nil) != tt.wantErr {
				t.Errorf("Azure.AuthorizeRevoke() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
