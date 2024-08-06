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
	// Public part of the  signing key for DPoP access token in PEM format
	SigningKey []byte `json:"key"`
	// URI template for the URI the ACME client must call to fetch the DPoP challenge proof (an access token from wire-server)
	Target string `json:"target"`

	signingKey crypto.PublicKey
	target     *template.Template
}

func (o *DPOPOptions) GetSigningKey() crypto.PublicKey {
	return o.signingKey
}

func (o *DPOPOptions) EvaluateTarget(deviceID string) (string, error) {
	if deviceID == "" {
		return "", errors.New("deviceID must not be empty")
	}
	buf := new(bytes.Buffer)
	if err := o.target.Execute(buf, struct{ DeviceID string }{DeviceID: deviceID}); err != nil {
		return "", fmt.Errorf("failed executing DPoP template: %w", err)
	}
	return buf.String(), nil
}

func (o *DPOPOptions) validateAndInitialize() (err error) {
	o.signingKey, err = pemutil.Parse(o.SigningKey)
	if err != nil {
		return fmt.Errorf("failed parsing key: %w", err)
	}
	o.target, err = template.New("DeviceID").Parse(o.Target)
	if err != nil {
		return fmt.Errorf("failed parsing DPoP template: %w", err)
	}

	return nil
}
