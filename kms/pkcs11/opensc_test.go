//go:build opensc
// +build opensc

package pkcs11

import (
	"runtime"
	"sync"

	"github.com/ThalesIgnite/crypto11"
)

var softHSM2Once sync.Once

// mustPKCS11 configures a *PKCS11 KMS to be used with OpenSC, using for example
// a Nitrokey HSM. To initialize these tests we should run:
//
//	sc-hsm-tool --initialize --so-pin 3537363231383830 --pin 123456
//
// Or:
//
//	pkcs11-tool --module /usr/local/lib/opensc-pkcs11.so \
//	--init-token --init-pin \
//	--so-pin=3537363231383830 --new-pin=123456 --pin=123456 \
//	--label="pkcs11-test"
func mustPKCS11(t TBTesting) *PKCS11 {
	t.Helper()
	testModule = "OpenSC"
	if runtime.GOARCH != "amd64" {
		t.Fatalf("opensc test skipped on %s:%s", runtime.GOOS, runtime.GOARCH)
	}

	var path string
	switch runtime.GOOS {
	case "darwin":
		path = "/usr/local/lib/opensc-pkcs11.so"
	case "linux":
		path = "/usr/local/lib/opensc-pkcs11.so"
	default:
		t.Skipf("opensc test skipped on %s", runtime.GOOS)
		return nil
	}
	var zero int
	p11, err := crypto11.Configure(&crypto11.Config{
		Path:       path,
		SlotNumber: &zero,
		Pin:        "123456",
	})
	if err != nil {
		t.Fatalf("failed to configure opensc on %s: %v", runtime.GOOS, err)
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
