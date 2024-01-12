package wire

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"text/template"

	"go.step.sm/crypto/pemutil"
)

type DPOPOptions struct {
	// Public part of the  signing key for DPoP access token
	SigningKey []byte `json:"key"`
	// URI template for the URI the ACME client must call to fetch the DPoP challenge proof (an access token from wire-server)
	Target string `json:"target"`
}

func (o *DPOPOptions) GetSigningKey() crypto.PublicKey {
	if o == nil {
		return nil
	}
	k, err := pemutil.Parse(o.SigningKey) // TODO(hs): do this once?
	if err != nil {
		return nil
	}

	return k
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
	if _, err := pemutil.Parse(o.SigningKey); err != nil {
		return fmt.Errorf("failed parsing key: %w", err)
	}
	if _, err := template.New("DeviceID").Parse(o.GetTarget()); err != nil {
		return fmt.Errorf("failed parsing template: %w", err)
	}
	return nil
}
