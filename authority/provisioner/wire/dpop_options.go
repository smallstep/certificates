package wire

import (
	"bytes"
	"errors"
	"fmt"
	"text/template"
)

type DPOPOptions struct {
	// Public part of the  signing key for DPoP access token
	SigningKey string `json:"key"`
	// URI template acme client must call to fetch the DPoP challenge proof (an access token from wire-server)
	Target string `json:"target"`
}

func (o *DPOPOptions) GetSigningKey() string {
	if o == nil {
		return ""
	}
	return o.SigningKey
}

func (o *DPOPOptions) GetTarget() string {
	if o == nil {
		return ""
	}
	return o.Target
}

func (o *DPOPOptions) EvaluateTarget(deviceID string) (string, error) {
	if o == nil {
		return "", errors.New("misconfigured target template configuration")
	}
	targetTemplate := o.GetTarget()
	tmpl, err := template.New("DeviceId").Parse(targetTemplate)
	if err != nil {
		return "", fmt.Errorf("failed parsing dpop template: %w", err)
	}
	buf := new(bytes.Buffer)
	if err = tmpl.Execute(buf, struct{ DeviceId string }{DeviceId: deviceID}); err != nil { //nolint:revive,stylecheck // TODO(hs): this requires changes in configuration
		return "", fmt.Errorf("failed executing dpop template: %w", err)
	}
	return buf.String(), nil
}
