package authority

import (
	"net/http"

	"github.com/pkg/errors"
	"github.com/smallstep/ca-component/provisioner"
)

// GetEncryptedKey returns the JWE key corresponding to the given kid argument.
func (a *Authority) GetEncryptedKey(kid string) (string, error) {
	val, ok := a.encryptedKeyIndex.Load(kid)
	if !ok {
		return "", &apiError{errors.Errorf("encrypted key with kid %s was not found", kid),
			http.StatusNotFound, context{}}
	}

	key, ok := val.(string)
	if !ok {
		return "", &apiError{errors.Errorf("stored value is not a string"),
			http.StatusInternalServerError, context{}}
	}
	return key, nil
}

// GetProvisioners returns a map listing each provisioner and the JWK Key Set
// with their public keys.
func (a *Authority) GetProvisioners() ([]*provisioner.Provisioner, error) {
	return a.config.AuthorityConfig.Provisioners, nil
}
