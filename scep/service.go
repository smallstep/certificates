package scep

import "crypto"

// Service is a (temporary?) wrapper for signer/decrypters
type Service struct {
	Signer    crypto.Signer
	Decrypter crypto.Decrypter
}
