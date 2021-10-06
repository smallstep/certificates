package azurekms

import (
	"context"
	"crypto"
	"encoding/json"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
	"github.com/pkg/errors"
	"github.com/smallstep/certificates/kms/uri"
	"go.step.sm/crypto/jose"
)

// defaultContext returns the default context used in requests to azure.
func defaultContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 15*time.Second)
}

// parseKeyName returns the key vault, name and version for urls like
// azurekms:vault=key-vault;id=key-name?version=key-version. If version is not
// passed the latest version will be used.
func parseKeyName(rawURI string) (vault, name, version string, err error) {
	var u *uri.URI

	u, err = uri.ParseWithScheme("azurekms", rawURI)
	if err != nil {
		return
	}

	if vault = u.Get("vault"); vault == "" {
		err = errors.Errorf("key uri %s is not valid: vault is missing", rawURI)
		return
	}
	if name = u.Get("id"); name == "" {
		err = errors.Errorf("key uri %s is not valid: id is missing", rawURI)
		return
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
