package softkms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/smallstep/certificates/kms/apiv1"
	"go.step.sm/crypto/pemutil"
)

func TestNew(t *testing.T) {
	type args struct {
		ctx  context.Context
		opts apiv1.Options
	}
	tests := []struct {
		name    string
		args    args
		want    *SoftKMS
		wantErr bool
	}{
		{"ok", args{context.Background(), apiv1.Options{}}, &SoftKMS{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

func TestSoftKMS_Close(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"ok", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &SoftKMS{}
			if err := k.Close(); (err != nil) != tt.wantErr {
				t.Errorf("SoftKMS.Close() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSoftKMS_CreateSigner(t *testing.T) {
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemBlock, err := pemutil.Serialize(pk)
	if err != nil {
		t.Fatal(err)
	}
	pemBlockPassword, err := pemutil.Serialize(pk, pemutil.WithPassword([]byte("pass")))
	if err != nil {
		t.Fatal(err)
	}

	// Read and decode file using standard packages
	b, err := os.ReadFile("testdata/priv.pem")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b)
	block.Bytes, err = x509.DecryptPEMBlock(block, []byte("pass")) //nolint
	if err != nil {
		t.Fatal(err)
	}
	pk2, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	// Create a public PEM
	b, err = x509.MarshalPKIXPublicKey(pk.Public())
	if err != nil {
		t.Fatal(err)
	}
	pub := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: b,
	})

	type args struct {
		req *apiv1.CreateSignerRequest
	}
	tests := []struct {
		name    string
		args    args
		want    crypto.Signer
		wantErr bool
	}{
		{"signer", args{&apiv1.CreateSignerRequest{Signer: pk}}, pk, false},
		{"pem", args{&apiv1.CreateSignerRequest{SigningKeyPEM: pem.EncodeToMemory(pemBlock)}}, pk, false},
		{"pem password", args{&apiv1.CreateSignerRequest{SigningKeyPEM: pem.EncodeToMemory(pemBlockPassword), Password: []byte("pass")}}, pk, false},
		{"file", args{&apiv1.CreateSignerRequest{SigningKey: "testdata/priv.pem", Password: []byte("pass")}}, pk2, false},
		{"fail", args{&apiv1.CreateSignerRequest{}}, nil, true},
		{"fail bad pem", args{&apiv1.CreateSignerRequest{SigningKeyPEM: []byte("bad pem")}}, nil, true},
		{"fail bad password", args{&apiv1.CreateSignerRequest{SigningKey: "testdata/priv.pem", Password: []byte("bad-pass")}}, nil, true},
		{"fail not a signer", args{&apiv1.CreateSignerRequest{SigningKeyPEM: pub}}, nil, true},
		{"fail not a signer from file", args{&apiv1.CreateSignerRequest{SigningKey: "testdata/pub.pem"}}, nil, true},
		{"fail missing", args{&apiv1.CreateSignerRequest{SigningKey: "testdata/missing"}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &SoftKMS{}
			got, err := k.CreateSigner(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("SoftKMS.CreateSigner() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SoftKMS.CreateSigner() = %v, want %v", got, tt.want)
			}
		})
	}
}

func restoreGenerateKey() func() {
	oldGenerateKey := generateKey
	return func() {
		generateKey = oldGenerateKey
	}
}

func TestSoftKMS_CreateKey(t *testing.T) {
	fn := restoreGenerateKey()
	defer fn()

	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	edpub, edpriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		req *apiv1.CreateKeyRequest
	}
	type params struct {
		kty  string
		crv  string
		size int
	}
	tests := []struct {
		name        string
		args        args
		generateKey func() (interface{}, interface{}, error)
		want        *apiv1.CreateKeyResponse
		wantParams  params
		wantErr     bool
	}{
		{"p256", args{&apiv1.CreateKeyRequest{Name: "p256", SignatureAlgorithm: apiv1.ECDSAWithSHA256}}, func() (interface{}, interface{}, error) {
			return p256.Public(), p256, nil
		}, &apiv1.CreateKeyResponse{Name: "p256", PublicKey: p256.Public(), PrivateKey: p256, CreateSignerRequest: apiv1.CreateSignerRequest{Signer: p256}}, params{"EC", "P-256", 0}, false},
		{"rsa", args{&apiv1.CreateKeyRequest{Name: "rsa3072", SignatureAlgorithm: apiv1.SHA256WithRSA}}, func() (interface{}, interface{}, error) {
			return rsa2048.Public(), rsa2048, nil
		}, &apiv1.CreateKeyResponse{Name: "rsa3072", PublicKey: rsa2048.Public(), PrivateKey: rsa2048, CreateSignerRequest: apiv1.CreateSignerRequest{Signer: rsa2048}}, params{"RSA", "", 0}, false},
		{"rsa2048", args{&apiv1.CreateKeyRequest{Name: "rsa2048", SignatureAlgorithm: apiv1.SHA256WithRSA, Bits: 2048}}, func() (interface{}, interface{}, error) {
			return rsa2048.Public(), rsa2048, nil
		}, &apiv1.CreateKeyResponse{Name: "rsa2048", PublicKey: rsa2048.Public(), PrivateKey: rsa2048, CreateSignerRequest: apiv1.CreateSignerRequest{Signer: rsa2048}}, params{"RSA", "", 2048}, false},
		{"rsaPSS2048", args{&apiv1.CreateKeyRequest{Name: "rsa2048", SignatureAlgorithm: apiv1.SHA256WithRSAPSS, Bits: 2048}}, func() (interface{}, interface{}, error) {
			return rsa2048.Public(), rsa2048, nil
		}, &apiv1.CreateKeyResponse{Name: "rsa2048", PublicKey: rsa2048.Public(), PrivateKey: rsa2048, CreateSignerRequest: apiv1.CreateSignerRequest{Signer: rsa2048}}, params{"RSA", "", 2048}, false},
		{"ed25519", args{&apiv1.CreateKeyRequest{Name: "ed25519", SignatureAlgorithm: apiv1.PureEd25519}}, func() (interface{}, interface{}, error) {
			return edpub, edpriv, nil
		}, &apiv1.CreateKeyResponse{Name: "ed25519", PublicKey: edpub, PrivateKey: edpriv, CreateSignerRequest: apiv1.CreateSignerRequest{Signer: edpriv}}, params{"OKP", "Ed25519", 0}, false},
		{"default", args{&apiv1.CreateKeyRequest{Name: "default"}}, func() (interface{}, interface{}, error) {
			return p256.Public(), p256, nil
		}, &apiv1.CreateKeyResponse{Name: "default", PublicKey: p256.Public(), PrivateKey: p256, CreateSignerRequest: apiv1.CreateSignerRequest{Signer: p256}}, params{"EC", "P-256", 0}, false},
		{"fail algorithm", args{&apiv1.CreateKeyRequest{Name: "fail", SignatureAlgorithm: apiv1.SignatureAlgorithm(100)}}, func() (interface{}, interface{}, error) {
			return p256.Public(), p256, nil
		}, nil, params{}, true},
		{"fail generate key", args{&apiv1.CreateKeyRequest{Name: "fail", SignatureAlgorithm: apiv1.ECDSAWithSHA256}}, func() (interface{}, interface{}, error) {
			return nil, nil, fmt.Errorf("an error")
		}, nil, params{"EC", "P-256", 0}, true},
		{"fail no signer", args{&apiv1.CreateKeyRequest{Name: "fail", SignatureAlgorithm: apiv1.ECDSAWithSHA256}}, func() (interface{}, interface{}, error) {
			return 1, 2, nil
		}, nil, params{"EC", "P-256", 0}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &SoftKMS{}
			generateKey = func(kty, crv string, size int) (interface{}, interface{}, error) {
				if tt.wantParams.kty != kty {
					t.Errorf("GenerateKey() kty = %s, want %s", kty, tt.wantParams.kty)
				}
				if tt.wantParams.crv != crv {
					t.Errorf("GenerateKey() crv = %s, want %s", crv, tt.wantParams.crv)
				}
				if tt.wantParams.size != size {
					t.Errorf("GenerateKey() size = %d, want %d", size, tt.wantParams.size)
				}
				return tt.generateKey()
			}

			got, err := k.CreateKey(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("SoftKMS.CreateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SoftKMS.CreateKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSoftKMS_GetPublicKey(t *testing.T) {
	b, err := os.ReadFile("testdata/pub.pem")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		req *apiv1.GetPublicKeyRequest
	}
	tests := []struct {
		name    string
		args    args
		want    crypto.PublicKey
		wantErr bool
	}{
		{"key", args{&apiv1.GetPublicKeyRequest{Name: "testdata/pub.pem"}}, pub, false},
		{"cert", args{&apiv1.GetPublicKeyRequest{Name: "testdata/cert.crt"}}, pub, false},
		{"fail not exists", args{&apiv1.GetPublicKeyRequest{Name: "testdata/missing"}}, nil, true},
		{"fail type", args{&apiv1.GetPublicKeyRequest{Name: "testdata/cert.key"}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &SoftKMS{}
			got, err := k.GetPublicKey(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("SoftKMS.GetPublicKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SoftKMS.GetPublicKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_generateKey(t *testing.T) {
	type args struct {
		kty  string
		crv  string
		size int
	}
	tests := []struct {
		name      string
		args      args
		wantType  interface{}
		wantType1 interface{}
		wantErr   bool
	}{
		{"rsa2048", args{"RSA", "", 0}, &rsa.PublicKey{}, &rsa.PrivateKey{}, false},
		{"rsa2048", args{"RSA", "", 2048}, &rsa.PublicKey{}, &rsa.PrivateKey{}, false},
		{"p256", args{"EC", "P-256", 0}, &ecdsa.PublicKey{}, &ecdsa.PrivateKey{}, false},
		{"ed25519", args{"OKP", "Ed25519", 0}, ed25519.PublicKey{}, ed25519.PrivateKey{}, false},
		{"fail kty", args{"FOO", "", 0}, nil, nil, true},
		{"fail crv", args{"EC", "P-123", 0}, nil, nil, true},
		{"fail size", args{"RSA", "", 1}, nil, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := generateKey(tt.args.kty, tt.args.crv, tt.args.size)
			if (err != nil) != tt.wantErr {
				t.Errorf("generateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if reflect.TypeOf(got) != reflect.TypeOf(tt.wantType) {
				t.Errorf("generateKey() got = %T, want %T", got, tt.wantType)
			}
			if reflect.TypeOf(got1) != reflect.TypeOf(tt.wantType1) {
				t.Errorf("generateKey() got1 = %T, want %T", got1, tt.wantType1)
			}
		})
	}
}

func TestSoftKMS_CreateDecrypter(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemBlock, err := pemutil.Serialize(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	pemBlockPassword, err := pemutil.Serialize(privateKey, pemutil.WithPassword([]byte("pass")))
	if err != nil {
		t.Fatal(err)
	}
	ecdsaPK, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaPemBlock, err := pemutil.Serialize(ecdsaPK)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("testdata/rsa.priv.pem")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b)
	block.Bytes, err = x509.DecryptPEMBlock(block, []byte("pass")) //nolint
	if err != nil {
		t.Fatal(err)
	}
	keyFromFile, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	type args struct {
		req *apiv1.CreateDecrypterRequest
	}
	tests := []struct {
		name    string
		args    args
		want    crypto.Decrypter
		wantErr bool
	}{
		{"decrypter", args{&apiv1.CreateDecrypterRequest{Decrypter: privateKey}}, privateKey, false},
		{"file", args{&apiv1.CreateDecrypterRequest{DecryptionKey: "testdata/rsa.priv.pem", Password: []byte("pass")}}, keyFromFile, false},
		{"pem", args{&apiv1.CreateDecrypterRequest{DecryptionKeyPEM: pem.EncodeToMemory(pemBlock)}}, privateKey, false},
		{"pem password", args{&apiv1.CreateDecrypterRequest{DecryptionKeyPEM: pem.EncodeToMemory(pemBlockPassword), Password: []byte("pass")}}, privateKey, false},
		{"fail none", args{&apiv1.CreateDecrypterRequest{}}, nil, true},
		{"fail missing", args{&apiv1.CreateDecrypterRequest{DecryptionKey: "testdata/missing"}}, nil, true},
		{"fail bad pem", args{&apiv1.CreateDecrypterRequest{DecryptionKeyPEM: []byte("bad pem")}}, nil, true},
		{"fail bad password", args{&apiv1.CreateDecrypterRequest{DecryptionKeyPEM: pem.EncodeToMemory(pemBlockPassword), Password: []byte("bad-pass")}}, nil, true},
		{"fail not a decrypter (ecdsa key)", args{&apiv1.CreateDecrypterRequest{DecryptionKeyPEM: pem.EncodeToMemory(ecdsaPemBlock)}}, nil, true},
		{"fail not a decrypter from file", args{&apiv1.CreateDecrypterRequest{DecryptionKey: "testdata/rsa.pub.pem"}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &SoftKMS{}
			got, err := k.CreateDecrypter(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("SoftKMS.CreateDecrypter(), error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SoftKMS.CreateDecrypter() = %v, want %v", got, tt.want)
			}
		})
	}
}
