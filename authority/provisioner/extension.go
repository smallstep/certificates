package provisioner

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
)

var (
	// StepOIDRoot is the root OID for smallstep.
	StepOIDRoot = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64}

	// StepOIDProvisioner is the OID for the provisioner extension.
	StepOIDProvisioner = append(asn1.ObjectIdentifier(nil), append(StepOIDRoot, 1)...)
)

// Extension is the Go representation of the provisioner extension.
type Extension struct {
	Type          Type
	Name          string
	CredentialID  string
	KeyValuePairs []string
}

type extensionASN1 struct {
	Type          int
	Name          []byte
	CredentialID  []byte
	KeyValuePairs []string `asn1:"optional,omitempty"`
}

// Marshal marshals the extension using encoding/asn1.
func (e *Extension) Marshal() ([]byte, error) {
	return asn1.Marshal(extensionASN1{
		Type:          int(e.Type),
		Name:          []byte(e.Name),
		CredentialID:  []byte(e.CredentialID),
		KeyValuePairs: e.KeyValuePairs,
	})
}

// ToExtension returns the pkix.Extension representation of the provisioner
// extension.
func (e *Extension) ToExtension() (pkix.Extension, error) {
	b, err := e.Marshal()
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{
		Id:    StepOIDProvisioner,
		Value: b,
	}, nil
}

// GetProvisionerExtension goes through all the certificate extensions and
// returns the provisioner extension (1.3.6.1.4.1.37476.9000.64.1).
func GetProvisionerExtension(cert *x509.Certificate) (*Extension, bool) {
	for _, e := range cert.Extensions {
		if e.Id.Equal(StepOIDProvisioner) {
			var provisioner extensionASN1
			if _, err := asn1.Unmarshal(e.Value, &provisioner); err != nil {
				return nil, false
			}
			return &Extension{
				Type:          Type(provisioner.Type),
				Name:          string(provisioner.Name),
				CredentialID:  string(provisioner.CredentialID),
				KeyValuePairs: provisioner.KeyValuePairs,
			}, true
		}
	}
	return nil, false
}
