package azurekms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"io"
	"reflect"
	"testing"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/golang/mock/gomock"
	"github.com/smallstep/certificates/kms/apiv1"
	"go.step.sm/crypto/keyutil"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

func TestNewSigner(t *testing.T) {
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
	client.EXPECT().GetKey(gomock.Any(), "https://my-vault.vault.azure.net/", "my-key", "my-version").Return(keyvault.KeyBundle{
		Key: jwk,
	}, nil)
	client.EXPECT().GetKey(gomock.Any(), "https://my-vault.vault.azure.net/", "not-found", "my-version").Return(keyvault.KeyBundle{}, errTest)

	var noOptions DefaultOptions
	type args struct {
		client     KeyVaultClient
		signingKey string
		defaults   DefaultOptions
	}
	tests := []struct {
		name    string
		args    args
		want    crypto.Signer
		wantErr bool
	}{
		{"ok", args{client, "azurekms:vault=my-vault;name=my-key", noOptions}, &Signer{
			client:       client,
			vaultBaseURL: "https://my-vault.vault.azure.net/",
			name:         "my-key",
			version:      "",
			publicKey:    pub,
		}, false},
		{"ok with version", args{client, "azurekms:name=my-key;vault=my-vault?version=my-version", noOptions}, &Signer{
			client:       client,
			vaultBaseURL: "https://my-vault.vault.azure.net/",
			name:         "my-key",
			version:      "my-version",
			publicKey:    pub,
		}, false},
		{"ok with options", args{client, "azurekms:name=my-key?version=my-version", DefaultOptions{Vault: "my-vault", ProtectionLevel: apiv1.HSM}}, &Signer{
			client:       client,
			vaultBaseURL: "https://my-vault.vault.azure.net/",
			name:         "my-key",
			version:      "my-version",
			publicKey:    pub,
		}, false},
		{"fail GetKey", args{client, "azurekms:name=not-found;vault=my-vault?version=my-version", noOptions}, nil, true},
		{"fail vault", args{client, "azurekms:name=not-found;vault=", noOptions}, nil, true},
		{"fail id", args{client, "azurekms:name=;vault=my-vault?version=my-version", noOptions}, nil, true},
		{"fail scheme", args{client, "kms:name=not-found;vault=my-vault?version=my-version", noOptions}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewSigner(tt.args.client, tt.args.signingKey, tt.args.defaults)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSigner() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewSigner() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSigner_Public(t *testing.T) {
	key, err := keyutil.GenerateDefaultSigner()
	if err != nil {
		t.Fatal(err)
	}
	pub := key.Public()

	type fields struct {
		publicKey crypto.PublicKey
	}
	tests := []struct {
		name   string
		fields fields
		want   crypto.PublicKey
	}{
		{"ok", fields{pub}, pub},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Signer{
				publicKey: tt.fields.publicKey,
			}
			if got := s.Public(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Signer.Public() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSigner_Sign(t *testing.T) {
	sign := func(kty, crv string, bits int, opts crypto.SignerOpts) (crypto.PublicKey, []byte, string, []byte) {
		key, err := keyutil.GenerateSigner(kty, crv, bits)
		if err != nil {
			t.Fatal(err)
		}
		h := opts.HashFunc().New()
		h.Write([]byte("random-data"))
		sum := h.Sum(nil)

		var sig, resultSig []byte
		if priv, ok := key.(*ecdsa.PrivateKey); ok {
			r, s, err := ecdsa.Sign(rand.Reader, priv, sum)
			if err != nil {
				t.Fatal(err)
			}
			curveBits := priv.Params().BitSize
			keyBytes := curveBits / 8
			if curveBits%8 > 0 {
				keyBytes++
			}
			rBytes := r.Bytes()
			rBytesPadded := make([]byte, keyBytes)
			copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)

			sBytes := s.Bytes()
			sBytesPadded := make([]byte, keyBytes)
			copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)
			// nolint:gocritic
			resultSig = append(rBytesPadded, sBytesPadded...)

			var b cryptobyte.Builder
			b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1BigInt(r)
				b.AddASN1BigInt(s)
			})
			sig, err = b.Bytes()
			if err != nil {
				t.Fatal(err)
			}
		} else {
			sig, err = key.Sign(rand.Reader, sum, opts)
			if err != nil {
				t.Fatal(err)
			}
			resultSig = sig
		}

		return key.Public(), h.Sum(nil), base64.RawURLEncoding.EncodeToString(resultSig), sig
	}

	p256, p256Digest, p256ResultSig, p256Sig := sign("EC", "P-256", 0, crypto.SHA256)
	p384, p384Digest, p386ResultSig, p384Sig := sign("EC", "P-384", 0, crypto.SHA384)
	p521, p521Digest, p521ResultSig, p521Sig := sign("EC", "P-521", 0, crypto.SHA512)
	rsaSHA256, rsaSHA256Digest, rsaSHA256ResultSig, rsaSHA256Sig := sign("RSA", "", 2048, crypto.SHA256)
	rsaSHA384, rsaSHA384Digest, rsaSHA384ResultSig, rsaSHA384Sig := sign("RSA", "", 2048, crypto.SHA384)
	rsaSHA512, rsaSHA512Digest, rsaSHA512ResultSig, rsaSHA512Sig := sign("RSA", "", 2048, crypto.SHA512)
	rsaPSSSHA256, rsaPSSSHA256Digest, rsaPSSSHA256ResultSig, rsaPSSSHA256Sig := sign("RSA", "", 2048, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	})
	rsaPSSSHA384, rsaPSSSHA384Digest, rsaPSSSHA384ResultSig, rsaPSSSHA384Sig := sign("RSA", "", 2048, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA512,
	})
	rsaPSSSHA512, rsaPSSSHA512Digest, rsaPSSSHA512ResultSig, rsaPSSSHA512Sig := sign("RSA", "", 2048, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA512,
	})

	ed25519Key, err := keyutil.GenerateSigner("OKP", "Ed25519", 0)
	if err != nil {
		t.Fatal(err)
	}

	client := mockClient(t)
	expects := []struct {
		name       string
		keyVersion string
		alg        keyvault.JSONWebKeySignatureAlgorithm
		digest     []byte
		result     keyvault.KeyOperationResult
		err        error
	}{
		{"P-256", "", keyvault.ES256, p256Digest, keyvault.KeyOperationResult{
			Result: &p256ResultSig,
		}, nil},
		{"P-384", "my-version", keyvault.ES384, p384Digest, keyvault.KeyOperationResult{
			Result: &p386ResultSig,
		}, nil},
		{"P-521", "my-version", keyvault.ES512, p521Digest, keyvault.KeyOperationResult{
			Result: &p521ResultSig,
		}, nil},
		{"RSA SHA256", "", keyvault.RS256, rsaSHA256Digest, keyvault.KeyOperationResult{
			Result: &rsaSHA256ResultSig,
		}, nil},
		{"RSA SHA384", "", keyvault.RS384, rsaSHA384Digest, keyvault.KeyOperationResult{
			Result: &rsaSHA384ResultSig,
		}, nil},
		{"RSA SHA512", "", keyvault.RS512, rsaSHA512Digest, keyvault.KeyOperationResult{
			Result: &rsaSHA512ResultSig,
		}, nil},
		{"RSA-PSS SHA256", "", keyvault.PS256, rsaPSSSHA256Digest, keyvault.KeyOperationResult{
			Result: &rsaPSSSHA256ResultSig,
		}, nil},
		{"RSA-PSS SHA384", "", keyvault.PS384, rsaPSSSHA384Digest, keyvault.KeyOperationResult{
			Result: &rsaPSSSHA384ResultSig,
		}, nil},
		{"RSA-PSS SHA512", "", keyvault.PS512, rsaPSSSHA512Digest, keyvault.KeyOperationResult{
			Result: &rsaPSSSHA512ResultSig,
		}, nil},
		// Errors
		{"fail Sign", "", keyvault.RS256, rsaSHA256Digest, keyvault.KeyOperationResult{}, errTest},
		{"fail sign length", "", keyvault.ES256, p256Digest, keyvault.KeyOperationResult{
			Result: &rsaSHA256ResultSig,
		}, nil},
		{"fail base64", "", keyvault.ES256, p256Digest, keyvault.KeyOperationResult{
			Result: func() *string {
				v := "😎"
				return &v
			}(),
		}, nil},
	}
	for _, e := range expects {
		value := base64.RawURLEncoding.EncodeToString(e.digest)
		client.EXPECT().Sign(gomock.Any(), "https://my-vault.vault.azure.net/", "my-key", e.keyVersion, keyvault.KeySignParameters{
			Algorithm: e.alg,
			Value:     &value,
		}).Return(e.result, e.err)
	}

	type fields struct {
		client       KeyVaultClient
		vaultBaseURL string
		name         string
		version      string
		publicKey    crypto.PublicKey
	}
	type args struct {
		rand   io.Reader
		digest []byte
		opts   crypto.SignerOpts
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		{"ok P-256", fields{client, "https://my-vault.vault.azure.net/", "my-key", "", p256}, args{
			rand.Reader, p256Digest, crypto.SHA256,
		}, p256Sig, false},
		{"ok P-384", fields{client, "https://my-vault.vault.azure.net/", "my-key", "my-version", p384}, args{
			rand.Reader, p384Digest, crypto.SHA384,
		}, p384Sig, false},
		{"ok P-521", fields{client, "https://my-vault.vault.azure.net/", "my-key", "my-version", p521}, args{
			rand.Reader, p521Digest, crypto.SHA512,
		}, p521Sig, false},
		{"ok RSA SHA256", fields{client, "https://my-vault.vault.azure.net/", "my-key", "", rsaSHA256}, args{
			rand.Reader, rsaSHA256Digest, crypto.SHA256,
		}, rsaSHA256Sig, false},
		{"ok RSA SHA384", fields{client, "https://my-vault.vault.azure.net/", "my-key", "", rsaSHA384}, args{
			rand.Reader, rsaSHA384Digest, crypto.SHA384,
		}, rsaSHA384Sig, false},
		{"ok RSA SHA512", fields{client, "https://my-vault.vault.azure.net/", "my-key", "", rsaSHA512}, args{
			rand.Reader, rsaSHA512Digest, crypto.SHA512,
		}, rsaSHA512Sig, false},
		{"ok RSA-PSS SHA256", fields{client, "https://my-vault.vault.azure.net/", "my-key", "", rsaPSSSHA256}, args{
			rand.Reader, rsaPSSSHA256Digest, &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthAuto,
				Hash:       crypto.SHA256,
			},
		}, rsaPSSSHA256Sig, false},
		{"ok RSA-PSS SHA384", fields{client, "https://my-vault.vault.azure.net/", "my-key", "", rsaPSSSHA384}, args{
			rand.Reader, rsaPSSSHA384Digest, &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       crypto.SHA384,
			},
		}, rsaPSSSHA384Sig, false},
		{"ok RSA-PSS SHA512", fields{client, "https://my-vault.vault.azure.net/", "my-key", "", rsaPSSSHA512}, args{
			rand.Reader, rsaPSSSHA512Digest, &rsa.PSSOptions{
				SaltLength: 64,
				Hash:       crypto.SHA512,
			},
		}, rsaPSSSHA512Sig, false},
		{"fail Sign", fields{client, "https://my-vault.vault.azure.net/", "my-key", "", rsaSHA256}, args{
			rand.Reader, rsaSHA256Digest, crypto.SHA256,
		}, nil, true},
		{"fail sign length", fields{client, "https://my-vault.vault.azure.net/", "my-key", "", p256}, args{
			rand.Reader, p256Digest, crypto.SHA256,
		}, nil, true},
		{"fail base64", fields{client, "https://my-vault.vault.azure.net/", "my-key", "", p256}, args{
			rand.Reader, p256Digest, crypto.SHA256,
		}, nil, true},
		{"fail RSA-PSS salt length", fields{client, "https://my-vault.vault.azure.net/", "my-key", "", rsaPSSSHA256}, args{
			rand.Reader, rsaPSSSHA256Digest, &rsa.PSSOptions{
				SaltLength: 64,
				Hash:       crypto.SHA256,
			},
		}, nil, true},
		{"fail RSA Hash", fields{client, "https://my-vault.vault.azure.net/", "my-key", "", rsaSHA256}, args{
			rand.Reader, rsaSHA256Digest, crypto.SHA1,
		}, nil, true},
		{"fail ECDSA Hash", fields{client, "https://my-vault.vault.azure.net/", "my-key", "", p256}, args{
			rand.Reader, p256Digest, crypto.MD5,
		}, nil, true},
		{"fail Ed25519", fields{client, "https://my-vault.vault.azure.net/", "my-key", "", ed25519Key}, args{
			rand.Reader, []byte("message"), crypto.Hash(0),
		}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Signer{
				client:       tt.fields.client,
				vaultBaseURL: tt.fields.vaultBaseURL,
				name:         tt.fields.name,
				version:      tt.fields.version,
				publicKey:    tt.fields.publicKey,
			}
			got, err := s.Sign(tt.args.rand, tt.args.digest, tt.args.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("Signer.Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Signer.Sign() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSigner_Sign_signWithRetry(t *testing.T) {
	sign := func(kty, crv string, bits int, opts crypto.SignerOpts) (crypto.PublicKey, []byte, string, []byte) {
		key, err := keyutil.GenerateSigner(kty, crv, bits)
		if err != nil {
			t.Fatal(err)
		}
		h := opts.HashFunc().New()
		h.Write([]byte("random-data"))
		sum := h.Sum(nil)

		var sig, resultSig []byte
		if priv, ok := key.(*ecdsa.PrivateKey); ok {
			r, s, err := ecdsa.Sign(rand.Reader, priv, sum)
			if err != nil {
				t.Fatal(err)
			}
			curveBits := priv.Params().BitSize
			keyBytes := curveBits / 8
			if curveBits%8 > 0 {
				keyBytes++
			}
			rBytes := r.Bytes()
			rBytesPadded := make([]byte, keyBytes)
			copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)

			sBytes := s.Bytes()
			sBytesPadded := make([]byte, keyBytes)
			copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)
			// nolint:gocritic
			resultSig = append(rBytesPadded, sBytesPadded...)

			var b cryptobyte.Builder
			b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1BigInt(r)
				b.AddASN1BigInt(s)
			})
			sig, err = b.Bytes()
			if err != nil {
				t.Fatal(err)
			}
		} else {
			sig, err = key.Sign(rand.Reader, sum, opts)
			if err != nil {
				t.Fatal(err)
			}
			resultSig = sig
		}

		return key.Public(), h.Sum(nil), base64.RawURLEncoding.EncodeToString(resultSig), sig
	}

	p256, p256Digest, p256ResultSig, p256Sig := sign("EC", "P-256", 0, crypto.SHA256)
	okResult := keyvault.KeyOperationResult{
		Result: &p256ResultSig,
	}
	failResult := keyvault.KeyOperationResult{}
	retryError := autorest.DetailedError{
		Original: &azure.RequestError{
			ServiceError: &azure.ServiceError{
				InnerError: map[string]interface{}{
					"code": "KeyNotYetValid",
				},
			},
		},
	}

	client := mockClient(t)
	expects := []struct {
		name       string
		keyVersion string
		alg        keyvault.JSONWebKeySignatureAlgorithm
		digest     []byte
		result     keyvault.KeyOperationResult
		err        error
	}{
		{"ok 1", "", keyvault.ES256, p256Digest, failResult, retryError},
		{"ok 2", "", keyvault.ES256, p256Digest, failResult, retryError},
		{"ok 3", "", keyvault.ES256, p256Digest, failResult, retryError},
		{"ok 4", "", keyvault.ES256, p256Digest, okResult, nil},
		{"fail", "fail-version", keyvault.ES256, p256Digest, failResult, retryError},
		{"fail", "fail-version", keyvault.ES256, p256Digest, failResult, retryError},
		{"fail", "fail-version", keyvault.ES256, p256Digest, failResult, retryError},
		{"fail", "fail-version", keyvault.ES256, p256Digest, failResult, retryError},
	}
	for _, e := range expects {
		value := base64.RawURLEncoding.EncodeToString(e.digest)
		client.EXPECT().Sign(gomock.Any(), "https://my-vault.vault.azure.net/", "my-key", e.keyVersion, keyvault.KeySignParameters{
			Algorithm: e.alg,
			Value:     &value,
		}).Return(e.result, e.err)
	}

	type fields struct {
		client       KeyVaultClient
		vaultBaseURL string
		name         string
		version      string
		publicKey    crypto.PublicKey
	}
	type args struct {
		rand   io.Reader
		digest []byte
		opts   crypto.SignerOpts
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		{"ok", fields{client, "https://my-vault.vault.azure.net/", "my-key", "", p256}, args{
			rand.Reader, p256Digest, crypto.SHA256,
		}, p256Sig, false},
		{"fail", fields{client, "https://my-vault.vault.azure.net/", "my-key", "fail-version", p256}, args{
			rand.Reader, p256Digest, crypto.SHA256,
		}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Signer{
				client:       tt.fields.client,
				vaultBaseURL: tt.fields.vaultBaseURL,
				name:         tt.fields.name,
				version:      tt.fields.version,
				publicKey:    tt.fields.publicKey,
			}
			got, err := s.Sign(tt.args.rand, tt.args.digest, tt.args.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("Signer.Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Signer.Sign() = %v, want %v", got, tt.want)
			}
		})
	}
}
