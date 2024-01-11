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
	tmpl, err := template.New("DeviceID").Parse(o.GetTarget())
	if err != nil {
		return "", fmt.Errorf("failed parsing dpop template: %w", err)
	}
	buf := new(bytes.Buffer)
	if err = tmpl.Execute(buf, struct{ DeviceID string }{DeviceID: deviceID}); err != nil {
		return "", fmt.Errorf("failed executing dpop template: %w", err)
	}
	return buf.String(), nil
}

func (o *DPOPOptions) validate() error {
	if _, err := template.New("DeviceID").Parse(o.GetTarget()); err != nil {
		return fmt.Errorf("failed parsing template: %w", err)
	}
	return nil
}
