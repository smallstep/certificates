package androidkey

import (
	"context"
	"crypto/x509"
)

type CRLChecker interface {
	IsRevoked(ctx context.Context, cert *x509.Certificate) (bool, error)
}
