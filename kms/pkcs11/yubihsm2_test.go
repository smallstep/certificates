//go:build cgo && yubihsm2
// +build cgo,yubihsm2

package pkcs11

import (
	"runtime"
	"sync"

	"github.com/ThalesIgnite/crypto11"
)

var yubiHSM2Once sync.Once

// mustPKCS11 configures a *PKCS11 KMS to be used with YubiHSM2. To initialize
// these tests, we should run:
//
//	yubihsm-connector -d
func mustPKCS11(t TBTesting) *PKCS11 {
	t.Helper()
	testModule = "YubiHSM2"
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
		t.Fatalf("failed to configure YubiHSM2 on %s: %v", runtime.GOOS, err)
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
