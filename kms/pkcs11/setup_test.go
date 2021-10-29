//go:build cgo
// +build cgo

package pkcs11

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/kms/apiv1"
)

var (
	testModule        = ""
	testObject        = "pkcs11:id=7370;object=test-name"
	testObjectAlt     = "pkcs11:id=7377;object=alt-test-name"
	testObjectByID    = "pkcs11:id=7370"
	testObjectByLabel = "pkcs11:object=test-name"
	testKeys          = []struct {
		Name               string
		SignatureAlgorithm apiv1.SignatureAlgorithm
		Bits               int
	}{
		{"pkcs11:id=7371;object=rsa-key", apiv1.SHA256WithRSA, 2048},
		{"pkcs11:id=7372;object=rsa-pss-key", apiv1.SHA256WithRSAPSS, DefaultRSASize},
		{"pkcs11:id=7373;object=ecdsa-p256-key", apiv1.ECDSAWithSHA256, 0},
		{"pkcs11:id=7374;object=ecdsa-p384-key", apiv1.ECDSAWithSHA384, 0},
		{"pkcs11:id=7375;object=ecdsa-p521-key", apiv1.ECDSAWithSHA512, 0},
	}

	testCerts = []struct {
		Name         string
		Key          string
		Certificates []*x509.Certificate
	}{
		{"pkcs11:id=7376;object=test-root", "pkcs11:id=7373;object=ecdsa-p256-key", nil},
	}
)

type TBTesting interface {
	Helper()
	Cleanup(f func())
	Log(args ...interface{})
	Errorf(format string, args ...interface{})
	Fatalf(format string, args ...interface{})
	Skipf(format string, args ...interface{})
}

func generateCertificate(pub crypto.PublicKey, signer crypto.Signer) (*x509.Certificate, error) {
	now := time.Now()
	template := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "Test Root Certificate"},
		Issuer:       pkix.Name{CommonName: "Test Root Certificate"},
		IsCA:         true,
		MaxPathLen:   1,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		NotBefore:    now,
		NotAfter:     now.Add(time.Hour),
		SerialNumber: big.NewInt(100),
	}

	b, err := x509.CreateCertificate(rand.Reader, template, template, pub, signer)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(b)
}

func setup(t TBTesting, k *PKCS11) {
	t.Log("Running using", testModule)
	for _, tk := range testKeys {
		_, err := k.CreateKey(&apiv1.CreateKeyRequest{
			Name:               tk.Name,
			SignatureAlgorithm: tk.SignatureAlgorithm,
			Bits:               tk.Bits,
		})
		if err != nil && !errors.Is(errors.Cause(err), apiv1.ErrAlreadyExists{
			Message: tk.Name + " already exists",
		}) {
			t.Errorf("PKCS11.GetPublicKey() error = %v", err)
		}
	}

	for i, c := range testCerts {
		signer, err := k.CreateSigner(&apiv1.CreateSignerRequest{
			SigningKey: c.Key,
		})
		if err != nil {
			t.Errorf("PKCS11.CreateSigner() error = %v", err)
			continue
		}
		cert, err := generateCertificate(signer.Public(), signer)
		if err != nil {
			t.Errorf("x509.CreateCertificate() error = %v", err)
			continue
		}
		if err := k.StoreCertificate(&apiv1.StoreCertificateRequest{
			Name:        c.Name,
			Certificate: cert,
		}); err != nil && !errors.Is(errors.Cause(err), apiv1.ErrAlreadyExists{
			Message: c.Name + " already exists",
		}) {
			t.Errorf("PKCS1.StoreCertificate() error = %v", err)
			continue
		}
		testCerts[i].Certificates = append(testCerts[i].Certificates, cert)
	}
}

func teardown(t TBTesting, k *PKCS11) {
	testObjects := []string{testObject, testObjectByID, testObjectByLabel}
	for _, name := range testObjects {
		if err := k.DeleteKey(name); err != nil {
			t.Errorf("PKCS11.DeleteKey() error = %v", err)
		}
		if err := k.DeleteCertificate(name); err != nil {
			t.Errorf("PKCS11.DeleteCertificate() error = %v", err)
		}
	}
	for _, tk := range testKeys {
		if err := k.DeleteKey(tk.Name); err != nil {
			t.Errorf("PKCS11.DeleteKey() error = %v", err)
		}
	}
	for _, tc := range testCerts {
		if err := k.DeleteCertificate(tc.Name); err != nil {
			t.Errorf("PKCS11.DeleteCertificate() error = %v", err)
		}
	}
}

func setupPKCS11(t TBTesting) *PKCS11 {
	t.Helper()
	k := mustPKCS11(t)
	t.Cleanup(func() {
		k.Close()
	})
	return k
}
