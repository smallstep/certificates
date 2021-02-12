package scep

import (
	database "github.com/smallstep/certificates/db"
)

const (
	opnGetCACert    = "GetCACert"
	opnGetCACaps    = "GetCACaps"
	opnPKIOperation = "PKIOperation"
)

// New returns a new Authority that implements the SCEP interface.
func New(signAuth SignAuthority, ops AuthorityOptions) (*Authority, error) {
	if _, ok := ops.DB.(*database.SimpleDB); !ok {
		// TODO: see ACME implementation
	}
	return &Authority{
		//certificates: ops.Certificates,
		backdate: ops.Backdate,
		db:       ops.DB,
		signAuth: signAuth,
	}, nil
}

// SCEPRequest is a SCEP server request.
type SCEPRequest struct {
	Operation string
	Message   []byte
}

// SCEPResponse is a SCEP server response.
type SCEPResponse struct {
	Operation string
	CACertNum int
	Data      []byte
	Err       error
}
