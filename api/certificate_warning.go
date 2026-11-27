package api

import (
	"context"

	"github.com/smallstep/certificates/cas/apiv1"
	"github.com/smallstep/certificates/logging"
)

func collectCertificateWarnings(ctx context.Context) (context.Context, *[]apiv1.CertificateWarning) {
	parentCtx := ctx
	var warnings []apiv1.CertificateWarning
	ctx = apiv1.WithCertificateWarningHandler(ctx, func(warning apiv1.CertificateWarning) {
		warnings = append(warnings, warning)
		logging.LogCertificateWarning(parentCtx, warning)
	})
	return ctx, &warnings
}
