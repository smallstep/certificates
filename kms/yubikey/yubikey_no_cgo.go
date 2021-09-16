//go:build !cgo
// +build !cgo

package yubikey

import (
	"context"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/kms/apiv1"
)

func init() {
	apiv1.Register(apiv1.YubiKey, func(ctx context.Context, opts apiv1.Options) (apiv1.KeyManager, error) {
		name := filepath.Base(os.Args[0])
		return nil, errors.Errorf("unsupported kms type 'yubikey': %s is compiled without cgo support", name)
	})
}
