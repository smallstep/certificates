package wire

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOptions_Validate(t *testing.T) {
	key := []byte(`-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA5c+4NKZSNQcR1T8qN6SjwgdPZQ0Ge12Ylx/YeGAJ35k=
-----END PUBLIC KEY-----`)

	type fields struct {
		OIDC *OIDCOptions
		DPOP *DPOPOptions
	}
	tests := []struct {
		name        string
		fields      fields
		expectedErr error
	}{
		{
			name: "ok",
			fields: fields{
				OIDC: &OIDCOptions{
					Provider: &Provider{
						IssuerURL: "https://example.com",
					},
					Config: &Config{},
				},
				DPOP: &DPOPOptions{
					SigningKey: key,
				},
			},
			expectedErr: nil,
		},
		{
			name: "fail/no-oidc-options",
			fields: fields{
				OIDC: nil,
				DPOP: &DPOPOptions{},
			},
			expectedErr: errors.New("no OIDC options available"),
		},
		{
			name: "fail/empty-issuer-url",
			fields: fields{
				OIDC: &OIDCOptions{
					Provider: &Provider{
						IssuerURL: "",
					},
					Config: &Config{},
				},
				DPOP: &DPOPOptions{},
			},
			expectedErr: errors.New("failed initializing OIDC options: either OIDC discovery or issuer URL must be set"),
		},
		{
			name: "fail/invalid-issuer-url",
			fields: fields{
				OIDC: &OIDCOptions{
					Provider: &Provider{
						IssuerURL: "\x00",
					},
					Config: &Config{},
				},
				DPOP: &DPOPOptions{},
			},
			expectedErr: errors.New(`failed initializing OIDC options: failed creationg OIDC provider config: failed parsing issuer URL: parse "\x00": net/url: invalid control character in URL`),
		},
		{
			name: "fail/issuer-url-template",
			fields: fields{
				OIDC: &OIDCOptions{
					Provider: &Provider{
						IssuerURL: "https://issuer.example.com/{{}",
					},
					Config: &Config{},
				},
				DPOP: &DPOPOptions{},
			},
			expectedErr: errors.New(`failed initializing OIDC options: failed parsing OIDC template: template: DeviceID:1: unexpected "}" in command`),
		},
		{
			name: "fail/invalid-transform-template",
			fields: fields{
				OIDC: &OIDCOptions{
					Provider: &Provider{
						IssuerURL: "https://example.com",
					},
					Config:            &Config{},
					TransformTemplate: "{{}",
				},
				DPOP: &DPOPOptions{
					SigningKey: key,
				},
			},
			expectedErr: errors.New(`failed initializing OIDC options: failed parsing OIDC transformation template: template: transform:1: unexpected "}" in command`),
		},
		{
			name: "fail/no-dpop-options",
			fields: fields{
				OIDC: &OIDCOptions{
					Provider: &Provider{
						IssuerURL: "https://example.com",
					},
					Config: &Config{},
				},
				DPOP: nil,
			},
			expectedErr: errors.New("no DPoP options available"),
		},
		{
			name: "fail/invalid-key",
			fields: fields{
				OIDC: &OIDCOptions{
					Provider: &Provider{
						IssuerURL: "https://example.com",
					},
					Config: &Config{},
				},
				DPOP: &DPOPOptions{
					SigningKey: []byte{0x00},
					Target:     "",
				},
			},
			expectedErr: errors.New(`failed initializing DPoP options: failed parsing key: error decoding PEM: not a valid PEM encoded block`),
		},
		{
			name: "fail/target-template",
			fields: fields{
				OIDC: &OIDCOptions{
					Provider: &Provider{
						IssuerURL: "https://example.com",
					},
					Config: &Config{},
				},
				DPOP: &DPOPOptions{
					SigningKey: key,
					Target:     "{{}",
				},
			},
			expectedErr: errors.New(`failed initializing DPoP options: failed parsing DPoP template: template: DeviceID:1: unexpected "}" in command`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &Options{
				OIDC: tt.fields.OIDC,
				DPOP: tt.fields.DPOP,
			}
			err := o.Validate()
			if tt.expectedErr != nil {
				assert.EqualError(t, err, tt.expectedErr.Error())
				return
			}

			assert.NoError(t, err)
		})
	}
}
