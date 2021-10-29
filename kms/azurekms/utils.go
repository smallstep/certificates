package azurekms

import (
	"context"
	"crypto"
	"encoding/json"
	"net/url"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
	"github.com/pkg/errors"
	"github.com/smallstep/certificates/kms/apiv1"
	"github.com/smallstep/certificates/kms/uri"
	"go.step.sm/crypto/jose"
)

// defaultContext returns the default context used in requests to azure.
func defaultContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 15*time.Second)
}

// getKeyName returns the uri of the key vault key.
func getKeyName(vault, name string, bundle keyvault.KeyBundle) string {
	if bundle.Key != nil && bundle.Key.Kid != nil {
		sm := keyIDRegexp.FindAllStringSubmatch(*bundle.Key.Kid, 1)
		if len(sm) == 1 && len(sm[0]) == 4 {
			m := sm[0]
			u := uri.New(Scheme, url.Values{
				"vault": []string{m[1]},
				"name":  []string{m[2]},
			})
			u.RawQuery = url.Values{"version": []string{m[3]}}.Encode()
			return u.String()
		}
	}
	// Fallback to URI without id.
	return uri.New(Scheme, url.Values{
		"vault": []string{vault},
		"name":  []string{name},
	}).String()
}

// parseKeyName returns the key vault, name and version from URIs like:
//
//   - azurekms:vault=key-vault;name=key-name
//   - azurekms:vault=key-vault;name=key-name?version=key-id
//   - azurekms:vault=key-vault;name=key-name?version=key-id&hsm=true
//
// The key-id defines the version of the key, if it is not passed the latest
// version will be used.
//
// HSM can also be passed to define the protection level if this is not given in
// CreateQuery.
func parseKeyName(rawURI string, defaults DefaultOptions) (vault, name, version string, hsm bool, err error) {
	var u *uri.URI

	u, err = uri.ParseWithScheme(Scheme, rawURI)
	if err != nil {
		return
	}
	if name = u.Get("name"); name == "" {
		err = errors.Errorf("key uri %s is not valid: name is missing", rawURI)
		return
	}
	if vault = u.Get("vault"); vault == "" {
		if defaults.Vault == "" {
			name = ""
			err = errors.Errorf("key uri %s is not valid: vault is missing", rawURI)
			return
		}
		vault = defaults.Vault
	}
	if u.Get("hsm") == "" {
		hsm = (defaults.ProtectionLevel == apiv1.HSM)
	} else {
		hsm = u.GetBool("hsm")
	}

	version = u.Get("version")

	return
}

func vaultBaseURL(vault string) string {
	return "https://" + vault + ".vault.azure.net/"
}

func convertKey(key *keyvault.JSONWebKey) (crypto.PublicKey, error) {
	b, err := json.Marshal(key)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling key")
	}
	var jwk jose.JSONWebKey
	if err := jwk.UnmarshalJSON(b); err != nil {
		return nil, errors.Wrap(err, "error unmarshaling key")
	}
	return jwk.Key, nil
}
