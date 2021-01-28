// +build cgo

package pkcs11

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/pkg/errors"

	"github.com/ThalesIgnite/crypto11"
	"github.com/smallstep/certificates/kms/apiv1"
)

var (
	softHSM2Once sync.Once
	yubiHSM2Once sync.Once
)

var (
	testKeys = []struct {
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
		{"pkcs11:id=7370;object=root", "pkcs11:id=7373;object=ecdsa-p256-key", nil},
	}
)

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

func setup(t *testing.T, k *PKCS11) {
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
		}); err != nil {
			t.Errorf("PKCS1.StoreCertificate() error = %v", err)
			continue
		}
		testCerts[i].Certificates = append(testCerts[i].Certificates, cert)
	}
}

func teardown(t *testing.T, k *PKCS11) {
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

type setupFunc func(t *testing.T) *PKCS11

func setupFuncs(t *testing.T) (setupFunc, setupFunc) {
	var sh2, yh2 *PKCS11
	t.Cleanup(func() {
		if sh2 != nil {
			sh2.Close()
		}
		if yh2 != nil {
			yh2.Close()
		}
	})
	setupSoftHSM2 := func(t *testing.T) *PKCS11 {
		if sh2 != nil {
			return sh2
		}
		sh2 = softHSM2(t)
		return sh2
	}
	setupYubiHSM2 := func(t *testing.T) *PKCS11 {
		if yh2 != nil {
			return yh2
		}
		yh2 = yubiHSM2(t)
		return yh2
	}
	return setupSoftHSM2, setupYubiHSM2
}

// softHSM2 configures a *PKCS11 KMS to be used with softHSM2. To initialize
// this tests, we should run:
//   softhsm2-util --init-token --free \
//   --token pkcs11-test --label pkcs11-test \
//   --so-pin password --pin password
//
// To delete we should run:
// 	softhsm2-util --delete-token --token pkcs11-test
func softHSM2(t *testing.T) *PKCS11 {
	t.Helper()
	if runtime.GOARCH != "amd64" {
		t.Skipf("softHSM2 test skipped on %s:%s", runtime.GOOS, runtime.GOARCH)
	}

	var path string
	switch runtime.GOOS {
	case "darwin":
		path = "/usr/local/lib/softhsm/libsofthsm2.so"
	case "linux":
		path = "/usr/lib/softhsm/libsofthsm2.so"
	default:
		t.Skipf("softHSM2 test skipped on %s", runtime.GOOS)
		return nil
	}
	p11, err := crypto11.Configure(&crypto11.Config{
		Path:       path,
		TokenLabel: "pkcs11-test",
		Pin:        "password",
	})
	if err != nil {
		t.Skipf("softHSM test skipped on %s: %v", runtime.GOOS, err)
	}

	k := &PKCS11{
		p11: p11,
	}

	// Setup
	softHSM2Once.Do(func() {
		teardown(t, k)
		setup(t, k)
	})

	return k
}

// yubiHSM2 configures a *PKCS11 KMS to be used with YubiHSM2. To initialize
// this tests, we should run:
// 	yubihsm-connector -d
func yubiHSM2(t *testing.T) *PKCS11 {
	t.Helper()
	if runtime.GOARCH != "amd64" {
		t.Skipf("yubiHSM2 test skipped on %s:%s", runtime.GOOS, runtime.GOARCH)
	}

	var path string
	switch runtime.GOOS {
	case "darwin":
		path = "/usr/local/lib/pkcs11/yubihsm_pkcs11.dylib"
	case "linux":
		path = "/usr/lib/x86_64-linux-gnu/pkcs11/yubihsm_pkcs11.so"
	default:
		t.Skipf("yubiHSM2 test skipped on %s", runtime.GOOS)
		return nil
	}
	p11, err := crypto11.Configure(&crypto11.Config{
		Path:       path,
		TokenLabel: "YubiHSM",
		Pin:        "0001password",
	})
	if err != nil {
		t.Skipf("yubiHSM2 test skipped on %s: %v", runtime.GOOS, err)
	}

	k := &PKCS11{
		p11: p11,
	}

	// Setup
	yubiHSM2Once.Do(func() {
		teardown(t, k)
		setup(t, k)
	})

	return k
}
