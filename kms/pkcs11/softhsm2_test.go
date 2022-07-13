//go:build cgo && softhsm2
// +build cgo,softhsm2

package pkcs11

import (
	"runtime"
	"sync"

	"github.com/ThalesIgnite/crypto11"
)

var softHSM2Once sync.Once

// mustPKCS11 configures a *PKCS11 KMS to be used with SoftHSM2. To initialize
// these tests, we should run:
//
//	softhsm2-util --init-token --free \
//	--token pkcs11-test --label pkcs11-test \
//	--so-pin password --pin password
//
// To delete we should run:
//
//	softhsm2-util --delete-token --token pkcs11-test
func mustPKCS11(t TBTesting) *PKCS11 {
	t.Helper()
	testModule = "SoftHSM2"
	if runtime.GOARCH != "amd64" {
		t.Fatalf("softHSM2 test skipped on %s:%s", runtime.GOOS, runtime.GOARCH)
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
		t.Fatalf("failed to configure softHSM2 on %s: %v", runtime.GOOS, err)
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
