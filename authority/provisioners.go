package authority

import (
	"log"
	"net/http"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/jose"
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
func (a *Authority) GetProvisioners() (map[string]*jose.JSONWebKeySet, error) {
	pks := map[string]*jose.JSONWebKeySet{}
	a.provisionerIDIndex.Range(func(key, val interface{}) bool {
		p, ok := val.(*Provisioner)
		if !ok {
			log.Printf("authority.GetProvisioners: expected type *Provisioner, but got %T\n", val)
			return true
		}
		ks, found := pks[p.Issuer]
		if found {
			ks.Keys = append(ks.Keys, *p.Key)
		} else {
			ks = new(jose.JSONWebKeySet)
			ks.Keys = []jose.JSONWebKey{*p.Key}
			pks[p.Issuer] = ks
		}
		return true
	})
	return pks, nil

}
