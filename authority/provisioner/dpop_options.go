package provisioner

import (
	"bytes"
	"errors"
	"fmt"
	"text/template"
)

type DPOPOptions struct {
	// ValidationExecPath is the name of the executable to call for DPOP
	// validation.
	ValidationExecPath string `json:"validation-exec-path,omitempty"`
	// Backend signing key for DPoP access token
	SigningKey string `json:"key"`
	// URI template acme client must call to fetch the DPoP challenge proof (an access token from wire-server)
	DpopTarget string `json:"dpop-target"`
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

func (o *DPOPOptions) GetDPOPTarget() string {
	if o == nil {
		return ""
	}
	return o.DpopTarget
}

func (o *DPOPOptions) GetTarget(deviceID string) (string, error) {
	if o == nil {
		return "", errors.New("misconfigured target template configuration")
	}
	targetTemplate := o.GetDPOPTarget()
	tmpl, err := template.New("DeviceID").Parse(targetTemplate)
	if err != nil {
		return "", fmt.Errorf("failed parsing dpop template: %w", err)
	}
	buf := new(bytes.Buffer)
	if err = tmpl.Execute(buf, struct{ DeviceID string }{DeviceID: deviceID}); err != nil {
		return "", fmt.Errorf("failed executing dpop template: %w", err)
	}
	return buf.String(), nil
}
