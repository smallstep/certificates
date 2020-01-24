package authority

import (
	"crypto/x509"

	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/errs"
)

// GetEncryptedKey returns the JWE key corresponding to the given kid argument.
func (a *Authority) GetEncryptedKey(kid string) (string, error) {
	key, ok := a.provisioners.LoadEncryptedKey(kid)
	if !ok {
		return "", errs.NotFound("encrypted key with kid %s was not found", kid)
	}
	return key, nil
}

// GetProvisioners returns a map listing each provisioner and the JWK Key Set
// with their public keys.
func (a *Authority) GetProvisioners(cursor string, limit int) (provisioner.List, string, error) {
	provisioners, nextCursor := a.provisioners.Find(cursor, limit)
	return provisioners, nextCursor, nil
}

// LoadProvisionerByCertificate returns an interface to the provisioner that
// provisioned the certificate.
func (a *Authority) LoadProvisionerByCertificate(crt *x509.Certificate) (provisioner.Interface, error) {
	p, ok := a.provisioners.LoadByCertificate(crt)
	if !ok {
		return nil, errs.NotFound("provisioner not found")
	}
	return p, nil
}

// LoadProvisionerByID returns an interface to the provisioner with the given ID.
func (a *Authority) LoadProvisionerByID(id string) (provisioner.Interface, error) {
	p, ok := a.provisioners.Load(id)
	if !ok {
		return nil, errs.NotFound("provisioner not found")
	}
	return p, nil
}
