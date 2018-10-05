package authority

import (
	"testing"

	"github.com/smallstep/assert"
	stepJOSE "github.com/smallstep/cli/jose"
)

func testAuthority(t *testing.T) *Authority {
	maxjwk, err := stepJOSE.ParseKey("testdata/secrets/max_pub.jwk")
	assert.FatalError(t, err)
	clijwk, err := stepJOSE.ParseKey("testdata/secrets/step_cli_key_pub.jwk")
	assert.FatalError(t, err)
	p := []*Provisioner{
		{
			Issuer: "Max",
			Type:   "JWK",
			Key:    maxjwk,
		},
		{
			Issuer: "step-cli",
			Type:   "JWK",
			Key:    clijwk,
		},
	}
	c := &Config{
		Address:          "127.0.0.1",
		Root:             "testdata/secrets/root_ca.crt",
		IntermediateCert: "testdata/secrets/intermediate_ca.crt",
		IntermediateKey:  "testdata/secrets/intermediate_ca_key",
		DNSNames:         []string{"test.smallstep.com"},
		Password:         "pass",
		AuthorityConfig: &AuthConfig{
			Provisioners: p,
		},
	}
	a, err := New(c)
	assert.FatalError(t, err)
	return a
}
