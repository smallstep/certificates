//go:generate mockgen -package mock -mock_names=KeyVaultClient=KeyVaultClient -destination internal/mock/key_vault_client.go github.com/smallstep/certificates/kms/azurekms KeyVaultClient
package azurekms

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
	"github.com/Azure/go-autorest/autorest/date"
	"github.com/golang/mock/gomock"
	"github.com/smallstep/certificates/kms/apiv1"
	"github.com/smallstep/certificates/kms/azurekms/internal/mock"
	"go.step.sm/crypto/keyutil"
	"gopkg.in/square/go-jose.v2"
)

var errTest = fmt.Errorf("test error")

func mockNow(t *testing.T) time.Time {
	old := now
	t0 := time.Unix(1234567890, 123).UTC()
	now = func() time.Time {
		return t0
	}
	t.Cleanup(func() {
		now = old
	})
	return t0
}

func mockClient(t *testing.T) *mock.KeyVaultClient {
	t.Helper()
	ctrl := gomock.NewController(t)
	t.Cleanup(func() {
		ctrl.Finish()
	})
	return mock.NewKeyVaultClient(ctrl)
}

func createJWK(t *testing.T, pub crypto.PublicKey) *keyvault.JSONWebKey {
	t.Helper()
	b, err := json.Marshal(&jose.JSONWebKey{
		Key: pub,
	})
	if err != nil {
		t.Fatal(err)
	}
	key := new(keyvault.JSONWebKey)
	if err := json.Unmarshal(b, key); err != nil {
		t.Fatal(err)
	}
	return key
}

func Test_now(t *testing.T) {
	t0 := now()
	if loc := t0.Location(); loc != time.UTC {
		t.Errorf("now() Location = %v, want %v", loc, time.UTC)
	}
}

func TestNew(t *testing.T) {
	client := mockClient(t)
	old := createClient
	t.Cleanup(func() {
		createClient = old
	})

	type args struct {
		ctx  context.Context
		opts apiv1.Options
	}
	tests := []struct {
		name    string
		setup   func()
		args    args
		want    *KeyVault
		wantErr bool
	}{
		{"ok", func() {
			createClient = func(ctx context.Context, opts apiv1.Options) (KeyVaultClient, error) {
				return client, nil
			}
		}, args{context.Background(), apiv1.Options{}}, &KeyVault{
			baseClient: client,
		}, false},
		{"ok with vault", func() {
			createClient = func(ctx context.Context, opts apiv1.Options) (KeyVaultClient, error) {
				return client, nil
			}
		}, args{context.Background(), apiv1.Options{
			URI: "azurekms:vault=my-vault",
		}}, &KeyVault{
			baseClient: client,
			defaults: DefaultOptions{
				Vault:           "my-vault",
				ProtectionLevel: apiv1.UnspecifiedProtectionLevel,
			},
		}, false},
		{"ok with vault + hsm", func() {
			createClient = func(ctx context.Context, opts apiv1.Options) (KeyVaultClient, error) {
				return client, nil
			}
		}, args{context.Background(), apiv1.Options{
			URI: "azurekms:vault=my-vault;hsm=true",
		}}, &KeyVault{
			baseClient: client,
			defaults: DefaultOptions{
				Vault:           "my-vault",
				ProtectionLevel: apiv1.HSM,
			},
		}, false},
		{"fail", func() {
			createClient = func(ctx context.Context, opts apiv1.Options) (KeyVaultClient, error) {
				return nil, errTest
			}
		}, args{context.Background(), apiv1.Options{}}, nil, true},
		{"fail uri", func() {
			createClient = func(ctx context.Context, opts apiv1.Options) (KeyVaultClient, error) {
				return client, nil
			}
		}, args{context.Background(), apiv1.Options{
			URI: "kms:vault=my-vault;hsm=true",
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()
			got, err := New(tt.args.ctx, tt.args.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKeyVault_createClient(t *testing.T) {
	type args struct {
		ctx  context.Context
		opts apiv1.Options
	}
	tests := []struct {
		name    string
		args    args
		skip    bool
		wantErr bool
	}{
		{"ok", args{context.Background(), apiv1.Options{}}, true, false},
		{"ok with uri", args{context.Background(), apiv1.Options{
			URI: "azurekms:client-id=id;client-secret=secret;tenant-id=id",
		}}, false, false},
		{"ok with uri+aad", args{context.Background(), apiv1.Options{
			URI: "azurekms:client-id=id;client-secret=secret;tenant-id=id;aad-enpoint=https%3A%2F%2Flogin.microsoftonline.us%2F",
		}}, false, false},
		{"ok with uri no config", args{context.Background(), apiv1.Options{
			URI: "azurekms:",
		}}, true, false},
		{"fail uri", args{context.Background(), apiv1.Options{
			URI: "kms:client-id=id;client-secret=secret;tenant-id=id",
		}}, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skip {
				t.SkipNow()
			}
			_, err := createClient(tt.args.ctx, tt.args.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestKeyVault_GetPublicKey(t *testing.T) {
	key, err := keyutil.GenerateDefaultSigner()
	if err != nil {
		t.Fatal(err)
	}
	pub := key.Public()
	jwk := createJWK(t, pub)

	client := mockClient(t)
	client.EXPECT().GetKey(gomock.Any(), "https://my-vault.vault.azure.net/", "my-key", "").Return(keyvault.KeyBundle{
		Key: jwk,
	}, nil)
	client.EXPECT().GetKey(gomock.Any(), "https://my-vault.vault.azure.net/", "my-key", "my-version").Return(keyvault.KeyBundle{
		Key: jwk,
	}, nil)
	client.EXPECT().GetKey(gomock.Any(), "https://my-vault.vault.azure.net/", "not-found", "my-version").Return(keyvault.KeyBundle{}, errTest)

	type fields struct {
		baseClient KeyVaultClient
	}
	type args struct {
		req *apiv1.GetPublicKeyRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    crypto.PublicKey
		wantErr bool
	}{
		{"ok", fields{client}, args{&apiv1.GetPublicKeyRequest{
			Name: "azurekms:vault=my-vault;name=my-key",
		}}, pub, false},
		{"ok with version", fields{client}, args{&apiv1.GetPublicKeyRequest{
			Name: "azurekms:vault=my-vault;name=my-key?version=my-version",
		}}, pub, false},
		{"fail GetKey", fields{client}, args{&apiv1.GetPublicKeyRequest{
			Name: "azurekms:vault=my-vault;name=not-found?version=my-version",
		}}, nil, true},
		{"fail empty", fields{client}, args{&apiv1.GetPublicKeyRequest{
			Name: "",
		}}, nil, true},
		{"fail vault", fields{client}, args{&apiv1.GetPublicKeyRequest{
			Name: "azurekms:vault=;name=not-found?version=my-version",
		}}, nil, true},
		{"fail id", fields{client}, args{&apiv1.GetPublicKeyRequest{
			Name: "azurekms:vault=;name=?version=my-version",
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &KeyVault{
				baseClient: tt.fields.baseClient,
			}
			got, err := k.GetPublicKey(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("KeyVault.GetPublicKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("KeyVault.GetPublicKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKeyVault_CreateKey(t *testing.T) {
	ecKey, err := keyutil.GenerateDefaultSigner()
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := keyutil.GenerateSigner("RSA", "", 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecPub := ecKey.Public()
	rsaPub := rsaKey.Public()
	ecJWK := createJWK(t, ecPub)
	rsaJWK := createJWK(t, rsaPub)

	t0 := date.UnixTime(mockNow(t))
	client := mockClient(t)

	expects := []struct {
		Name    string
		Kty     keyvault.JSONWebKeyType
		KeySize *int32
		Curve   keyvault.JSONWebKeyCurveName
		Key     *keyvault.JSONWebKey
	}{
		{"P-256", keyvault.EC, nil, keyvault.P256, ecJWK},
		{"P-256 HSM", keyvault.ECHSM, nil, keyvault.P256, ecJWK},
		{"P-256 HSM (uri)", keyvault.ECHSM, nil, keyvault.P256, ecJWK},
		{"P-256 Default", keyvault.EC, nil, keyvault.P256, ecJWK},
		{"P-384", keyvault.EC, nil, keyvault.P384, ecJWK},
		{"P-521", keyvault.EC, nil, keyvault.P521, ecJWK},
		{"RSA 0", keyvault.RSA, &value3072, "", rsaJWK},
		{"RSA 0 HSM", keyvault.RSAHSM, &value3072, "", rsaJWK},
		{"RSA 0 HSM (uri)", keyvault.RSAHSM, &value3072, "", rsaJWK},
		{"RSA 2048", keyvault.RSA, &value2048, "", rsaJWK},
		{"RSA 3072", keyvault.RSA, &value3072, "", rsaJWK},
		{"RSA 4096", keyvault.RSA, &value4096, "", rsaJWK},
	}

	for _, e := range expects {
		client.EXPECT().CreateKey(gomock.Any(), "https://my-vault.vault.azure.net/", "my-key", keyvault.KeyCreateParameters{
			Kty:     e.Kty,
			KeySize: e.KeySize,
			Curve:   e.Curve,
			KeyOps: &[]keyvault.JSONWebKeyOperation{
				keyvault.Sign, keyvault.Verify,
			},
			KeyAttributes: &keyvault.KeyAttributes{
				Enabled:   &valueTrue,
				Created:   &t0,
				NotBefore: &t0,
			},
		}).Return(keyvault.KeyBundle{
			Key: e.Key,
		}, nil)
	}
	client.EXPECT().CreateKey(gomock.Any(), "https://my-vault.vault.azure.net/", "not-found", gomock.Any()).Return(keyvault.KeyBundle{}, errTest)
	client.EXPECT().CreateKey(gomock.Any(), "https://my-vault.vault.azure.net/", "not-found", gomock.Any()).Return(keyvault.KeyBundle{
		Key: nil,
	}, nil)

	type fields struct {
		baseClient KeyVaultClient
	}
	type args struct {
		req *apiv1.CreateKeyRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *apiv1.CreateKeyResponse
		wantErr bool
	}{
		{"ok P-256", fields{client}, args{&apiv1.CreateKeyRequest{
			Name:               "azurekms:vault=my-vault;name=my-key",
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
			ProtectionLevel:    apiv1.Software,
		}}, &apiv1.CreateKeyResponse{
			Name:      "azurekms:name=my-key;vault=my-vault",
			PublicKey: ecPub,
			CreateSignerRequest: apiv1.CreateSignerRequest{
				SigningKey: "azurekms:name=my-key;vault=my-vault",
			},
		}, false},
		{"ok P-256 HSM", fields{client}, args{&apiv1.CreateKeyRequest{
			Name:               "azurekms:vault=my-vault;name=my-key",
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
			ProtectionLevel:    apiv1.HSM,
		}}, &apiv1.CreateKeyResponse{
			Name:      "azurekms:name=my-key;vault=my-vault",
			PublicKey: ecPub,
			CreateSignerRequest: apiv1.CreateSignerRequest{
				SigningKey: "azurekms:name=my-key;vault=my-vault",
			},
		}, false},
		{"ok P-256 HSM (uri)", fields{client}, args{&apiv1.CreateKeyRequest{
			Name:               "azurekms:vault=my-vault;name=my-key?hsm=true",
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
		}}, &apiv1.CreateKeyResponse{
			Name:      "azurekms:name=my-key;vault=my-vault",
			PublicKey: ecPub,
			CreateSignerRequest: apiv1.CreateSignerRequest{
				SigningKey: "azurekms:name=my-key;vault=my-vault",
			},
		}, false},
		{"ok P-256 Default", fields{client}, args{&apiv1.CreateKeyRequest{
			Name: "azurekms:vault=my-vault;name=my-key",
		}}, &apiv1.CreateKeyResponse{
			Name:      "azurekms:name=my-key;vault=my-vault",
			PublicKey: ecPub,
			CreateSignerRequest: apiv1.CreateSignerRequest{
				SigningKey: "azurekms:name=my-key;vault=my-vault",
			},
		}, false},
		{"ok P-384", fields{client}, args{&apiv1.CreateKeyRequest{
			Name:               "azurekms:vault=my-vault;name=my-key",
			SignatureAlgorithm: apiv1.ECDSAWithSHA384,
		}}, &apiv1.CreateKeyResponse{
			Name:      "azurekms:name=my-key;vault=my-vault",
			PublicKey: ecPub,
			CreateSignerRequest: apiv1.CreateSignerRequest{
				SigningKey: "azurekms:name=my-key;vault=my-vault",
			},
		}, false},
		{"ok P-521", fields{client}, args{&apiv1.CreateKeyRequest{
			Name:               "azurekms:vault=my-vault;name=my-key",
			SignatureAlgorithm: apiv1.ECDSAWithSHA512,
		}}, &apiv1.CreateKeyResponse{
			Name:      "azurekms:name=my-key;vault=my-vault",
			PublicKey: ecPub,
			CreateSignerRequest: apiv1.CreateSignerRequest{
				SigningKey: "azurekms:name=my-key;vault=my-vault",
			},
		}, false},
		{"ok RSA 0", fields{client}, args{&apiv1.CreateKeyRequest{
			Name:               "azurekms:vault=my-vault;name=my-key",
			Bits:               0,
			SignatureAlgorithm: apiv1.SHA256WithRSA,
			ProtectionLevel:    apiv1.Software,
		}}, &apiv1.CreateKeyResponse{
			Name:      "azurekms:name=my-key;vault=my-vault",
			PublicKey: rsaPub,
			CreateSignerRequest: apiv1.CreateSignerRequest{
				SigningKey: "azurekms:name=my-key;vault=my-vault",
			},
		}, false},
		{"ok RSA 0 HSM", fields{client}, args{&apiv1.CreateKeyRequest{
			Name:               "azurekms:vault=my-vault;name=my-key",
			Bits:               0,
			SignatureAlgorithm: apiv1.SHA256WithRSAPSS,
			ProtectionLevel:    apiv1.HSM,
		}}, &apiv1.CreateKeyResponse{
			Name:      "azurekms:name=my-key;vault=my-vault",
			PublicKey: rsaPub,
			CreateSignerRequest: apiv1.CreateSignerRequest{
				SigningKey: "azurekms:name=my-key;vault=my-vault",
			},
		}, false},
		{"ok RSA 0 HSM (uri)", fields{client}, args{&apiv1.CreateKeyRequest{
			Name:               "azurekms:vault=my-vault;name=my-key;hsm=true",
			Bits:               0,
			SignatureAlgorithm: apiv1.SHA256WithRSAPSS,
		}}, &apiv1.CreateKeyResponse{
			Name:      "azurekms:name=my-key;vault=my-vault",
			PublicKey: rsaPub,
			CreateSignerRequest: apiv1.CreateSignerRequest{
				SigningKey: "azurekms:name=my-key;vault=my-vault",
			},
		}, false},
		{"ok RSA 2048", fields{client}, args{&apiv1.CreateKeyRequest{
			Name:               "azurekms:vault=my-vault;name=my-key",
			Bits:               2048,
			SignatureAlgorithm: apiv1.SHA384WithRSA,
		}}, &apiv1.CreateKeyResponse{
			Name:      "azurekms:name=my-key;vault=my-vault",
			PublicKey: rsaPub,
			CreateSignerRequest: apiv1.CreateSignerRequest{
				SigningKey: "azurekms:name=my-key;vault=my-vault",
			},
		}, false},
		{"ok RSA 3072", fields{client}, args{&apiv1.CreateKeyRequest{
			Name:               "azurekms:vault=my-vault;name=my-key",
			Bits:               3072,
			SignatureAlgorithm: apiv1.SHA512WithRSA,
		}}, &apiv1.CreateKeyResponse{
			Name:      "azurekms:name=my-key;vault=my-vault",
			PublicKey: rsaPub,
			CreateSignerRequest: apiv1.CreateSignerRequest{
				SigningKey: "azurekms:name=my-key;vault=my-vault",
			},
		}, false},
		{"ok RSA 4096", fields{client}, args{&apiv1.CreateKeyRequest{
			Name:               "azurekms:vault=my-vault;name=my-key",
			Bits:               4096,
			SignatureAlgorithm: apiv1.SHA512WithRSAPSS,
		}}, &apiv1.CreateKeyResponse{
			Name:      "azurekms:name=my-key;vault=my-vault",
			PublicKey: rsaPub,
			CreateSignerRequest: apiv1.CreateSignerRequest{
				SigningKey: "azurekms:name=my-key;vault=my-vault",
			},
		}, false},
		{"fail createKey", fields{client}, args{&apiv1.CreateKeyRequest{
			Name:               "azurekms:vault=my-vault;name=not-found",
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
		}}, nil, true},
		{"fail convertKey", fields{client}, args{&apiv1.CreateKeyRequest{
			Name:               "azurekms:vault=my-vault;name=not-found",
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
		}}, nil, true},
		{"fail name", fields{client}, args{&apiv1.CreateKeyRequest{
			Name: "",
		}}, nil, true},
		{"fail vault", fields{client}, args{&apiv1.CreateKeyRequest{
			Name: "azurekms:vault=;name=not-found?version=my-version",
		}}, nil, true},
		{"fail id", fields{client}, args{&apiv1.CreateKeyRequest{
			Name: "azurekms:vault=my-vault;name=?version=my-version",
		}}, nil, true},
		{"fail SignatureAlgorithm", fields{client}, args{&apiv1.CreateKeyRequest{
			Name:               "azurekms:vault=my-vault;name=not-found",
			SignatureAlgorithm: apiv1.PureEd25519,
		}}, nil, true},
		{"fail bit size", fields{client}, args{&apiv1.CreateKeyRequest{
			Name:               "azurekms:vault=my-vault;name=not-found",
			SignatureAlgorithm: apiv1.SHA384WithRSAPSS,
			Bits:               1024,
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &KeyVault{
				baseClient: tt.fields.baseClient,
			}
			got, err := k.CreateKey(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("KeyVault.CreateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("KeyVault.CreateKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKeyVault_CreateSigner(t *testing.T) {
	key, err := keyutil.GenerateDefaultSigner()
	if err != nil {
		t.Fatal(err)
	}
	pub := key.Public()
	jwk := createJWK(t, pub)

	client := mockClient(t)
	client.EXPECT().GetKey(gomock.Any(), "https://my-vault.vault.azure.net/", "my-key", "").Return(keyvault.KeyBundle{
		Key: jwk,
	}, nil)
	client.EXPECT().GetKey(gomock.Any(), "https://my-vault.vault.azure.net/", "my-key", "my-version").Return(keyvault.KeyBundle{
		Key: jwk,
	}, nil)
	client.EXPECT().GetKey(gomock.Any(), "https://my-vault.vault.azure.net/", "not-found", "my-version").Return(keyvault.KeyBundle{}, errTest)

	type fields struct {
		baseClient KeyVaultClient
	}
	type args struct {
		req *apiv1.CreateSignerRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    crypto.Signer
		wantErr bool
	}{
		{"ok", fields{client}, args{&apiv1.CreateSignerRequest{
			SigningKey: "azurekms:vault=my-vault;name=my-key",
		}}, &Signer{
			client:       client,
			vaultBaseURL: "https://my-vault.vault.azure.net/",
			name:         "my-key",
			version:      "",
			publicKey:    pub,
		}, false},
		{"ok with version", fields{client}, args{&apiv1.CreateSignerRequest{
			SigningKey: "azurekms:vault=my-vault;name=my-key;version=my-version",
		}}, &Signer{
			client:       client,
			vaultBaseURL: "https://my-vault.vault.azure.net/",
			name:         "my-key",
			version:      "my-version",
			publicKey:    pub,
		}, false},
		{"fail GetKey", fields{client}, args{&apiv1.CreateSignerRequest{
			SigningKey: "azurekms:vault=my-vault;name=not-found;version=my-version",
		}}, nil, true},
		{"fail SigningKey", fields{client}, args{&apiv1.CreateSignerRequest{
			SigningKey: "",
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &KeyVault{
				baseClient: tt.fields.baseClient,
			}
			got, err := k.CreateSigner(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("KeyVault.CreateSigner() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("KeyVault.CreateSigner() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKeyVault_Close(t *testing.T) {
	client := mockClient(t)
	type fields struct {
		baseClient KeyVaultClient
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{"ok", fields{client}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &KeyVault{
				baseClient: tt.fields.baseClient,
			}
			if err := k.Close(); (err != nil) != tt.wantErr {
				t.Errorf("KeyVault.Close() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_keyType_KeyType(t *testing.T) {
	type fields struct {
		Kty   keyvault.JSONWebKeyType
		Curve keyvault.JSONWebKeyCurveName
	}
	type args struct {
		pl apiv1.ProtectionLevel
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   keyvault.JSONWebKeyType
	}{
		{"ec", fields{keyvault.EC, keyvault.P256}, args{apiv1.UnspecifiedProtectionLevel}, keyvault.EC},
		{"ec software", fields{keyvault.EC, keyvault.P384}, args{apiv1.Software}, keyvault.EC},
		{"ec hsm", fields{keyvault.EC, keyvault.P521}, args{apiv1.HSM}, keyvault.ECHSM},
		{"rsa", fields{keyvault.RSA, keyvault.P256}, args{apiv1.UnspecifiedProtectionLevel}, keyvault.RSA},
		{"rsa software", fields{keyvault.RSA, ""}, args{apiv1.Software}, keyvault.RSA},
		{"rsa hsm", fields{keyvault.RSA, ""}, args{apiv1.HSM}, keyvault.RSAHSM},
		{"empty", fields{"FOO", ""}, args{apiv1.UnspecifiedProtectionLevel}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := keyType{
				Kty:   tt.fields.Kty,
				Curve: tt.fields.Curve,
			}
			if got := k.KeyType(tt.args.pl); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("keyType.KeyType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKeyVault_ValidateName(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"ok", args{"azurekms:name=my-key;vault=my-vault"}, false},
		{"ok hsm", args{"azurekms:name=my-key;vault=my-vault?hsm=true"}, false},
		{"fail scheme", args{"azure:name=my-key;vault=my-vault"}, true},
		{"fail parse uri", args{"azurekms:name=%ZZ;vault=my-vault"}, true},
		{"fail no name", args{"azurekms:vault=my-vault"}, true},
		{"fail no vault", args{"azurekms:name=my-key"}, true},
		{"fail empty", args{""}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &KeyVault{}
			if err := k.ValidateName(tt.args.s); (err != nil) != tt.wantErr {
				t.Errorf("KeyVault.ValidateName() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
