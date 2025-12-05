package api

import (
	"context"
	"crypto/x509"
)

// ChallengeValidatorRequest is the container for the CSR to be validated
type ChallengeValidatorRequest struct{
	csr *x509.CertificateRequest
}

// ChallengeValidator returns an error if the provided CSR's challenge is invalid,
// otherwise returns nil
type ChallengeValidator interface {
	Validate(context.Context, *ChallengeValidatorRequest) (error)
}
