// +build !cgo

package pkcs11

import (
	"context"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/kms/apiv1"
)

func init() {
	apiv1.Register(apiv1.PKCS11, func(ctx context.Context, opts apiv1.Options) (apiv1.KeyManager, error) {
		name := filepath.Base(os.Args[0])
		return nil, errors.Errorf("unsupported kms type 'pkcs11': %s is compiled without cgo support", name)
	})
}
