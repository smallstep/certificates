package config

import (
	"reflect"
	"testing"

	"github.com/smallstep/assert"
	"go.step.sm/crypto/jose"
	"golang.org/x/crypto/ssh"
)

func TestSSHPublicKey_Validate(t *testing.T) {
	key, err := jose.GenerateJWK("EC", "P-256", "", "sig", "", 0)
	assert.FatalError(t, err)

	type fields struct {
		Type      string
		Federated bool
		Key       jose.JSONWebKey
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{"user", fields{"user", true, key.Public()}, false},
		{"host", fields{"host", false, key.Public()}, false},
		{"empty", fields{"", true, key.Public()}, true},
		{"badType", fields{"bad", false, key.Public()}, true},
		{"badKey", fields{"user", false, *key}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &SSHPublicKey{
				Type:      tt.fields.Type,
				Federated: tt.fields.Federated,
				Key:       tt.fields.Key,
			}
			if err := k.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("SSHPublicKey.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSSHPublicKey_PublicKey(t *testing.T) {
	key, err := jose.GenerateJWK("EC", "P-256", "", "sig", "", 0)
	assert.FatalError(t, err)
	pub, err := ssh.NewPublicKey(key.Public().Key)
	assert.FatalError(t, err)

	type fields struct {
		publicKey ssh.PublicKey
	}
	tests := []struct {
		name   string
		fields fields
		want   ssh.PublicKey
	}{
		{"ok", fields{pub}, pub},
		{"nil", fields{nil}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &SSHPublicKey{
				publicKey: tt.fields.publicKey,
			}
			if got := k.PublicKey(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SSHPublicKey.PublicKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
