package kubernetes

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/api/auth/kubernetes"
)

// AuthOptions defines the configuration options added using the
// VaultOptions.AuthOptions field when AuthType is kubernetes
type AuthOptions struct {
	Role      string `json:"role,omitempty"`
	TokenPath string `json:"tokenPath,omitempty"`
}

func NewKubernetesAuthMethod(mountPath string, options json.RawMessage) (*kubernetes.KubernetesAuth, error) {
	var opts *AuthOptions

	err := json.Unmarshal(options, &opts)
	if err != nil {
		return nil, fmt.Errorf("error decoding Kubernetes auth options: %w", err)
	}

	var kubernetesAuth *kubernetes.KubernetesAuth

	var loginOptions []kubernetes.LoginOption
	if mountPath != "" {
		loginOptions = append(loginOptions, kubernetes.WithMountPath(mountPath))
	}
	if opts.TokenPath != "" {
		loginOptions = append(loginOptions, kubernetes.WithServiceAccountTokenPath(opts.TokenPath))
	}

	if opts.Role == "" {
		return nil, errors.New("you must set role")
	}

	kubernetesAuth, err = kubernetes.NewKubernetesAuth(
		opts.Role,
		loginOptions...,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize Kubernetes auth method: %w", err)
	}

	return kubernetesAuth, nil
}
