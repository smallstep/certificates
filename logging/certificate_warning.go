package logging

import (
	"context"
	"log"

	"github.com/smallstep/certificates/cas/apiv1"
)

// LogCertificateWarning delivers an issuance warning to the request handler, or
// logs it using the standard logger when no handler is configured.
func LogCertificateWarning(ctx context.Context, warning apiv1.CertificateWarning) {
	if handler := apiv1.CertificateWarningHandlerFromContext(ctx); handler != nil {
		handler(warning)
		return
	}
	log.Printf("WARNING: %q [%q]", warning.Message, warning.Code)
}
