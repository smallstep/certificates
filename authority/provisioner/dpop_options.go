package provisioner

type DPOPOptions struct {
	// ValidationExecPath is the name of the executable to call for DPOP
	// validation.
	ValidationExecPath string `json:"validation-exec-path,omitempty"`
	// Backend signing key for DPoP access token
	SigningKey string `json:"key"`
	// URI template acme client must call to fetch the DPoP challenge proof (an access token from wire-server)
	DpopTarget string `json:"dpop-target"`
	// URI template acme client must call to fetch the OIDC challenge proof (an Id token)
	OidcTarget string `json:"oidc-target"`
}

func (o *DPOPOptions) GetValidationExecPath() string {
	if o == nil {
		return "rusty-jwt-cli"
	}
	return o.ValidationExecPath
}

func (o *DPOPOptions) GetSigningKey() string {
	if o == nil {
		return ""
	}
	return o.SigningKey
}
