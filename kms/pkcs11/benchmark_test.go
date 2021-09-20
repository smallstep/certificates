//go:build cgo
// +build cgo

package pkcs11

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/smallstep/certificates/kms/apiv1"
)

func benchmarkSign(b *testing.B, signer crypto.Signer, opts crypto.SignerOpts) {
	hash := opts.HashFunc()
	h := hash.New()
	h.Write([]byte("buggy-coheir-RUBRIC-rabbet-liberal-eaglet-khartoum-stagger"))
	digest := h.Sum(nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		signer.Sign(rand.Reader, digest, opts)
	}
	b.StopTimer()
}

func BenchmarkSignRSA(b *testing.B) {
	k := setupPKCS11(b)
	signer, err := k.CreateSigner(&apiv1.CreateSignerRequest{
		SigningKey: "pkcs11:id=7371;object=rsa-key",
	})
	if err != nil {
		b.Fatalf("PKCS11.CreateSigner() error = %v", err)
	}
	benchmarkSign(b, signer, crypto.SHA256)
}

func BenchmarkSignRSAPSS(b *testing.B) {
	k := setupPKCS11(b)
	signer, err := k.CreateSigner(&apiv1.CreateSignerRequest{
		SigningKey: "pkcs11:id=7372;object=rsa-pss-key",
	})
	if err != nil {
		b.Fatalf("PKCS11.CreateSigner() error = %v", err)
	}
	benchmarkSign(b, signer, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	})
}

func BenchmarkSignP256(b *testing.B) {
	k := setupPKCS11(b)
	signer, err := k.CreateSigner(&apiv1.CreateSignerRequest{
		SigningKey: "pkcs11:id=7373;object=ecdsa-p256-key",
	})
	if err != nil {
		b.Fatalf("PKCS11.CreateSigner() error = %v", err)
	}
	benchmarkSign(b, signer, crypto.SHA256)
}

func BenchmarkSignP384(b *testing.B) {
	k := setupPKCS11(b)
	signer, err := k.CreateSigner(&apiv1.CreateSignerRequest{
		SigningKey: "pkcs11:id=7374;object=ecdsa-p384-key",
	})
	if err != nil {
		b.Fatalf("PKCS11.CreateSigner() error = %v", err)
	}
	benchmarkSign(b, signer, crypto.SHA384)
}

func BenchmarkSignP521(b *testing.B) {
	k := setupPKCS11(b)
	signer, err := k.CreateSigner(&apiv1.CreateSignerRequest{
		SigningKey: "pkcs11:id=7375;object=ecdsa-p521-key",
	})
	if err != nil {
		b.Fatalf("PKCS11.CreateSigner() error = %v", err)
	}
	benchmarkSign(b, signer, crypto.SHA512)
}
