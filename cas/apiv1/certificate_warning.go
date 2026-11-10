package apiv1

import (
	"context"
	"time"
)

// LimitingCertificate identifies the CA certificate that bounded issuance.
type LimitingCertificate struct {
	Subject     string    `json:"subject"`
	Fingerprint string    `json:"fingerprint"`
	NotAfter    time.Time `json:"notAfter"`
}

// CertificateWarning describes a successful issuance with reduced validity.
// RequestedNotAfter is the resolved expiry before issuer limiting, including
// templates, defaults, and renewal arithmetic. Dates use UTC second precision.
type CertificateWarning struct {
	Code                string              `json:"code"`
	Message             string              `json:"message"`
	RequestedNotAfter   time.Time           `json:"requestedNotAfter"`
	EffectiveNotAfter   time.Time           `json:"effectiveNotAfter"`
	LimitingCertificate LimitingCertificate `json:"limitingCertificate"`
}

type certificateWarningHandlerKey struct{}

// WithCertificateWarningHandler replaces the warning handler in the context.
// Delivery is synchronous; this function neither composes handlers nor logs.
func WithCertificateWarningHandler(ctx context.Context, handler func(CertificateWarning)) context.Context {
	return context.WithValue(ctx, certificateWarningHandlerKey{}, handler)
}

// CertificateWarningHandlerFromContext returns the handler, if configured.
func CertificateWarningHandlerFromContext(ctx context.Context) func(CertificateWarning) {
	handler, _ := ctx.Value(certificateWarningHandlerKey{}).(func(CertificateWarning))
	return handler
}
