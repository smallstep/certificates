package azurekms

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
	"github.com/smallstep/certificates/kms/apiv1"
)

func Test_getKeyName(t *testing.T) {
	getBundle := func(kid string) keyvault.KeyBundle {
		return keyvault.KeyBundle{
			Key: &keyvault.JSONWebKey{
				Kid: &kid,
			},
		}
	}

	type args struct {
		vault  string
		name   string
		bundle keyvault.KeyBundle
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"ok", args{"my-vault", "my-key", getBundle("https://my-vault.vault.azure.net/keys/my-key/my-version")}, "azurekms:name=my-key;vault=my-vault?version=my-version"},
		{"ok default", args{"my-vault", "my-key", getBundle("https://my-vault.foo.net/keys/my-key/my-version")}, "azurekms:name=my-key;vault=my-vault"},
		{"ok too short", args{"my-vault", "my-key", getBundle("https://my-vault.vault.azure.net/keys/my-version")}, "azurekms:name=my-key;vault=my-vault"},
		{"ok too long", args{"my-vault", "my-key", getBundle("https://my-vault.vault.azure.net/keys/my-key/my-version/sign")}, "azurekms:name=my-key;vault=my-vault"},
		{"ok nil key", args{"my-vault", "my-key", keyvault.KeyBundle{}}, "azurekms:name=my-key;vault=my-vault"},
		{"ok nil kid", args{"my-vault", "my-key", keyvault.KeyBundle{Key: &keyvault.JSONWebKey{}}}, "azurekms:name=my-key;vault=my-vault"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getKeyName(tt.args.vault, tt.args.name, tt.args.bundle); got != tt.want {
				t.Errorf("getKeyName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseKeyName(t *testing.T) {
	var noOptions DefaultOptions
	type args struct {
		rawURI   string
		defaults DefaultOptions
	}
	tests := []struct {
		name        string
		args        args
		wantVault   string
		wantName    string
		wantVersion string
		wantHsm     bool
		wantErr     bool
	}{
		{"ok", args{"azurekms:name=my-key;vault=my-vault?version=my-version", noOptions}, "my-vault", "my-key", "my-version", false, false},
		{"ok opaque version", args{"azurekms:name=my-key;vault=my-vault;version=my-version", noOptions}, "my-vault", "my-key", "my-version", false, false},
		{"ok no version", args{"azurekms:name=my-key;vault=my-vault", noOptions}, "my-vault", "my-key", "", false, false},
		{"ok hsm", args{"azurekms:name=my-key;vault=my-vault?hsm=true", noOptions}, "my-vault", "my-key", "", true, false},
		{"ok hsm false", args{"azurekms:name=my-key;vault=my-vault?hsm=false", noOptions}, "my-vault", "my-key", "", false, false},
		{"ok default vault", args{"azurekms:name=my-key?version=my-version", DefaultOptions{Vault: "my-vault"}}, "my-vault", "my-key", "my-version", false, false},
		{"ok default hsm", args{"azurekms:name=my-key;vault=my-vault?version=my-version", DefaultOptions{Vault: "other-vault", ProtectionLevel: apiv1.HSM}}, "my-vault", "my-key", "my-version", true, false},
		{"fail scheme", args{"azure:name=my-key;vault=my-vault", noOptions}, "", "", "", false, true},
		{"fail parse uri", args{"azurekms:name=%ZZ;vault=my-vault", noOptions}, "", "", "", false, true},
		{"fail no name", args{"azurekms:vault=my-vault", noOptions}, "", "", "", false, true},
		{"fail empty name", args{"azurekms:name=;vault=my-vault", noOptions}, "", "", "", false, true},
		{"fail no vault", args{"azurekms:name=my-key", noOptions}, "", "", "", false, true},
		{"fail empty vault", args{"azurekms:name=my-key;vault=", noOptions}, "", "", "", false, true},
		{"fail empty", args{"", noOptions}, "", "", "", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotVault, gotName, gotVersion, gotHsm, err := parseKeyName(tt.args.rawURI, tt.args.defaults)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseKeyName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotVault != tt.wantVault {
				t.Errorf("parseKeyName() gotVault = %v, want %v", gotVault, tt.wantVault)
			}
			if gotName != tt.wantName {
				t.Errorf("parseKeyName() gotName = %v, want %v", gotName, tt.wantName)
			}
			if gotVersion != tt.wantVersion {
				t.Errorf("parseKeyName() gotVersion = %v, want %v", gotVersion, tt.wantVersion)
			}
			if gotHsm != tt.wantHsm {
				t.Errorf("parseKeyName() gotHsm = %v, want %v", gotHsm, tt.wantHsm)
			}
		})
	}
}
