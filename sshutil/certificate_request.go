package sshutil

import "golang.org/x/crypto/ssh"

// CertificateRequests simulates a certificate request for SSH. SSH does not
// have a concept of certificate requests, but the CA accepts the key and some
// other parameters in the requests that are part of the certificate. This
// struct will hold these parameters.
//
// CertificateRequests object will be used in the templates to set parameters
// passed with the API instead of the validated ones.
type CertificateRequest struct {
	Key        ssh.PublicKey
	Type       CertType
	KeyID      string
	Principals []string
}
