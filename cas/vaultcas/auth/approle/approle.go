package approle

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/api/auth/approle"
)

// AuthOptions defines the configuration options added using the
// VaultOptions.AuthOptions field when AuthType is approle
type AuthOptions struct {
	RoleID          string `json:"roleID,omitempty"`
	SecretID        string `json:"secretID,omitempty"`
	SecretIDFile    string `json:"secretIDFile,omitempty"`
	SecretIDEnv     string `json:"secretIDEnv,omitempty"`
	IsWrappingToken bool   `json:"isWrappingToken,omitempty"`
}

func NewApproleAuthMethod(mountPath string, options json.RawMessage) (*approle.AppRoleAuth, error) {
	var opts *AuthOptions

	err := json.Unmarshal(options, &opts)
	if err != nil {
		return nil, fmt.Errorf("error decoding AppRole auth options: %w", err)
	}

	var approleAuth *approle.AppRoleAuth

	var loginOptions []approle.LoginOption
	if mountPath != "" {
		loginOptions = append(loginOptions, approle.WithMountPath(mountPath))
	}
	if opts.IsWrappingToken {
		loginOptions = append(loginOptions, approle.WithWrappingToken())
	}

	if opts.RoleID == "" {
		return nil, errors.New("you must set roleID")
	}

	var sid approle.SecretID
	switch {
	case opts.SecretID != "" && opts.SecretIDFile == "" && opts.SecretIDEnv == "":
		sid = approle.SecretID{
			FromString: opts.SecretID,
		}
	case opts.SecretIDFile != "" && opts.SecretID == "" && opts.SecretIDEnv == "":
		sid = approle.SecretID{
			FromFile: opts.SecretIDFile,
		}
	case opts.SecretIDEnv != "" && opts.SecretIDFile == "" && opts.SecretID == "":
		sid = approle.SecretID{
			FromEnv: opts.SecretIDEnv,
		}
	default:
		return nil, errors.New("you must set one of secretID, secretIDFile or secretIDEnv")
	}

	approleAuth, err = approle.NewAppRoleAuth(opts.RoleID, &sid, loginOptions...)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize Kubernetes auth method: %w", err)
	}

	return approleAuth, nil
}
