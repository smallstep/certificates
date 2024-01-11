package wire

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOptions_Validate(t *testing.T) {
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
				DPOP: &DPOPOptions{},
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
			expectedErr: errors.New("failed validating OIDC options: issuer URL must not be empty"),
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
			expectedErr: errors.New(`failed validating OIDC options: failed parsing issuer URL: parse "\x00": net/url: invalid control character in URL`),
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
			expectedErr: errors.New(`failed validating OIDC options: failed parsing template: template: DeviceID:1: unexpected "}" in command`),
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
			name: "fail/target-template",
			fields: fields{
				OIDC: &OIDCOptions{
					Provider: &Provider{
						IssuerURL: "https://example.com",
					},
					Config: &Config{},
				},
				DPOP: &DPOPOptions{
					Target: "{{}",
				},
			},
			expectedErr: errors.New(`failed validating DPoP options: failed parsing template: template: DeviceID:1: unexpected "}" in command`),
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
