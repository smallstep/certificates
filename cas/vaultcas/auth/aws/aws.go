package aws

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/vault/api/auth/aws"
)

// AuthOptions defines the configuration options added using the
// VaultOptions.AuthOptions field when AuthType is aws.
// This maps directly to Vault's AWS Login options,
// see: https://developer.hashicorp.com/vault/api-docs/auth/aws#login
type AuthOptions struct {
	Role        string `json:"role,omitempty"`
	Region      string `json:"region,omitempty"`
	AwsAuthType string `json:"awsAuthType,omitempty"`

	// options specific to 'iam' auth type
	IamServerIDHeader string `json:"iamServerIdHeader"`

	// options specific to 'ec2' auth type
	SignatureType string `json:"signatureType,omitempty"`
	Nonce         string `json:"nonce,omitempty"`
}

func NewAwsAuthMethod(mountPath string, options json.RawMessage) (*aws.AWSAuth, error) {
	var opts *AuthOptions

	err := json.Unmarshal(options, &opts)
	if err != nil {
		return nil, fmt.Errorf("error decoding AWS auth options: %w", err)
	}

	var awsAuth *aws.AWSAuth

	var loginOptions []aws.LoginOption
	if mountPath != "" {
		loginOptions = append(loginOptions, aws.WithMountPath(mountPath))
	}
	if opts.Role != "" {
		loginOptions = append(loginOptions, aws.WithRole(opts.Role))
	}
	if opts.Region != "" {
		loginOptions = append(loginOptions, aws.WithRegion(opts.Region))
	}

	switch opts.AwsAuthType {
	case "iam":
		loginOptions = append(loginOptions, aws.WithIAMAuth())

		if opts.IamServerIDHeader != "" {
			loginOptions = append(loginOptions, aws.WithIAMServerIDHeader(opts.IamServerIDHeader))
		}
	case "ec2":
		loginOptions = append(loginOptions, aws.WithEC2Auth())

		switch opts.SignatureType {
		case "pkcs7":
			loginOptions = append(loginOptions, aws.WithPKCS7Signature())
		case "identity":
			loginOptions = append(loginOptions, aws.WithIdentitySignature())
		case "rsa2048":
			loginOptions = append(loginOptions, aws.WithRSA2048Signature())
		case "":
			// no-op
		default:
			return nil, fmt.Errorf("unknown SignatureType type %q; valid options are 'pkcs7', 'identity' and 'rsa2048'", opts.SignatureType)
		}

		if opts.Nonce != "" {
			loginOptions = append(loginOptions, aws.WithNonce(opts.Nonce))
		}
	default:
		return nil, fmt.Errorf("unknown awsAuthType %q; valid options are 'iam' and 'ec2'", opts.AwsAuthType)
	}

	awsAuth, err = aws.NewAWSAuth(loginOptions...)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize AWS auth method: %w", err)
	}

	return awsAuth, nil
}
