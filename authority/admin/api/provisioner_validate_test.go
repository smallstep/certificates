package api

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/smallstep/assert"
	"github.com/smallstep/linkedca"
	"go.step.sm/crypto/jose"

	"github.com/smallstep/certificates/authority/admin"
)

// testJWKPublicKey returns a marshaled valid public JWK.
func testJWKPublicKey(t *testing.T) []byte {
	t.Helper()
	jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "test-kid", 0)
	assert.FatalError(t, err)
	b, err := json.Marshal(jwk.Public())
	assert.FatalError(t, err)
	return b
}

func Test_validateProvisioner(t *testing.T) {
	type test struct {
		prov   *linkedca.Provisioner
		errMsg string // empty means expect nil error
	}
	tests := map[string]func(t *testing.T) test{
		"ok/jwk": func(t *testing.T) test {
			return test{prov: &linkedca.Provisioner{
				Name: "jwk-prov", Type: linkedca.Provisioner_JWK,
				Details: &linkedca.ProvisionerDetails{Data: &linkedca.ProvisionerDetails_JWK{
					JWK: &linkedca.JWKProvisioner{PublicKey: testJWKPublicKey(t)},
				}},
			}}
		},
		"ok/sshpop-no-fields": func(t *testing.T) test {
			return test{prov: &linkedca.Provisioner{
				Name: "sshpop-prov", Type: linkedca.Provisioner_SSHPOP,
				Details: &linkedca.ProvisionerDetails{Data: &linkedca.ProvisionerDetails_SSHPOP{
					SSHPOP: &linkedca.SSHPOPProvisioner{},
				}},
			}}
		},
		"ok/aws-empty-instance-age": func(t *testing.T) test {
			return test{prov: &linkedca.Provisioner{
				Name: "aws-prov", Type: linkedca.Provisioner_AWS,
				Details: &linkedca.ProvisionerDetails{Data: &linkedca.ProvisionerDetails_AWS{
					AWS: &linkedca.AWSProvisioner{Accounts: []string{"123456789012"}},
				}},
			}}
		},
		"fail/empty-name": func(t *testing.T) test {
			return test{prov: &linkedca.Provisioner{
				Type: linkedca.Provisioner_ACME,
				Details: &linkedca.ProvisionerDetails{Data: &linkedca.ProvisionerDetails_ACME{
					ACME: &linkedca.ACMEProvisioner{},
				}},
			}, errMsg: "provisioner name is required"}
		},
		"fail/noop-type": func(t *testing.T) test {
			return test{prov: &linkedca.Provisioner{
				Name: "prov",
				Details: &linkedca.ProvisionerDetails{Data: &linkedca.ProvisionerDetails_ACME{
					ACME: &linkedca.ACMEProvisioner{},
				}},
			}, errMsg: "provisioner type is required"}
		},
		"fail/missing-details": func(t *testing.T) test {
			return test{prov: &linkedca.Provisioner{
				Name: "prov", Type: linkedca.Provisioner_ACME,
			}, errMsg: "provisioner details are required"}
		},
		"fail/type-details-mismatch": func(t *testing.T) test {
			return test{prov: &linkedca.Provisioner{
				Name: "prov", Type: linkedca.Provisioner_JWK,
				Details: &linkedca.ProvisionerDetails{Data: &linkedca.ProvisionerDetails_SCEP{
					SCEP: &linkedca.SCEPProvisioner{},
				}},
			}, errMsg: "provisioner details (SCEP) do not match provisioner type (JWK)"}
		},
		"fail/jwk-missing-public-key": func(t *testing.T) test {
			return test{prov: &linkedca.Provisioner{
				Name: "prov", Type: linkedca.Provisioner_JWK,
				Details: &linkedca.ProvisionerDetails{Data: &linkedca.ProvisionerDetails_JWK{
					JWK: &linkedca.JWKProvisioner{},
				}},
			}, errMsg: "jwk.publicKey is required"}
		},
		"fail/jwk-invalid-public-key": func(t *testing.T) test {
			return test{prov: &linkedca.Provisioner{
				Name: "prov", Type: linkedca.Provisioner_JWK,
				Details: &linkedca.ProvisionerDetails{Data: &linkedca.ProvisionerDetails_JWK{
					JWK: &linkedca.JWKProvisioner{PublicKey: []byte("not-json")},
				}},
			}, errMsg: "jwk.publicKey is not a valid JWK"}
		},
		"fail/oidc-missing-client-id": func(t *testing.T) test {
			return test{prov: &linkedca.Provisioner{
				Name: "prov", Type: linkedca.Provisioner_OIDC,
				Details: &linkedca.ProvisionerDetails{Data: &linkedca.ProvisionerDetails_OIDC{
					OIDC: &linkedca.OIDCProvisioner{ConfigurationEndpoint: "https://example.com"},
				}},
			}, errMsg: "oidc.clientId is required"}
		},
		"fail/oidc-missing-endpoint": func(t *testing.T) test {
			return test{prov: &linkedca.Provisioner{
				Name: "prov", Type: linkedca.Provisioner_OIDC,
				Details: &linkedca.ProvisionerDetails{Data: &linkedca.ProvisionerDetails_OIDC{
					OIDC: &linkedca.OIDCProvisioner{ClientId: "client"},
				}},
			}, errMsg: "oidc.configurationEndpoint is required"}
		},
		"fail/oidc-invalid-endpoint-url": func(t *testing.T) test {
			return test{prov: &linkedca.Provisioner{
				Name: "prov", Type: linkedca.Provisioner_OIDC,
				Details: &linkedca.ProvisionerDetails{Data: &linkedca.ProvisionerDetails_OIDC{
					OIDC: &linkedca.OIDCProvisioner{ClientId: "client", ConfigurationEndpoint: "://invalid"},
				}},
			}, errMsg: "oidc.configurationEndpoint is not a valid URL"}
		},
		"fail/aws-invalid-instance-age": func(t *testing.T) test {
			return test{prov: &linkedca.Provisioner{
				Name: "prov", Type: linkedca.Provisioner_AWS,
				Details: &linkedca.ProvisionerDetails{Data: &linkedca.ProvisionerDetails_AWS{
					AWS: &linkedca.AWSProvisioner{InstanceAge: "bogus"},
				}},
			}, errMsg: "aws.instanceAge is invalid"}
		},
		"fail/gcp-invalid-instance-age": func(t *testing.T) test {
			return test{prov: &linkedca.Provisioner{
				Name: "prov", Type: linkedca.Provisioner_GCP,
				Details: &linkedca.ProvisionerDetails{Data: &linkedca.ProvisionerDetails_GCP{
					GCP: &linkedca.GCPProvisioner{InstanceAge: "bogus"},
				}},
			}, errMsg: "gcp.instanceAge is invalid"}
		},
		"fail/azure-missing-tenant-id": func(t *testing.T) test {
			return test{prov: &linkedca.Provisioner{
				Name: "prov", Type: linkedca.Provisioner_AZURE,
				Details: &linkedca.ProvisionerDetails{Data: &linkedca.ProvisionerDetails_Azure{
					Azure: &linkedca.AzureProvisioner{},
				}},
			}, errMsg: "azure.tenantId is required"}
		},
		"fail/x5c-missing-roots": func(t *testing.T) test {
			return test{prov: &linkedca.Provisioner{
				Name: "prov", Type: linkedca.Provisioner_X5C,
				Details: &linkedca.ProvisionerDetails{Data: &linkedca.ProvisionerDetails_X5C{
					X5C: &linkedca.X5CProvisioner{},
				}},
			}, errMsg: "x5c.roots is required"}
		},
		"fail/k8ssa-missing-public-keys": func(t *testing.T) test {
			return test{prov: &linkedca.Provisioner{
				Name: "prov", Type: linkedca.Provisioner_K8SSA,
				Details: &linkedca.ProvisionerDetails{Data: &linkedca.ProvisionerDetails_K8SSA{
					K8SSA: &linkedca.K8SSAProvisioner{PublicKeys: [][]byte{[]byte("")}},
				}},
			}, errMsg: "k8sSA.publicKeys is required"}
		},
		"fail/nebula-missing-roots": func(t *testing.T) test {
			return test{prov: &linkedca.Provisioner{
				Name: "prov", Type: linkedca.Provisioner_NEBULA,
				Details: &linkedca.ProvisionerDetails{Data: &linkedca.ProvisionerDetails_Nebula{
					Nebula: &linkedca.NebulaProvisioner{},
				}},
			}, errMsg: "nebula.roots is required"}
		},
	}
	for name, prep := range tests {
		tc := prep(t)
		t.Run(name, func(t *testing.T) {
			err := validateProvisioner(tc.prov)
			if tc.errMsg == "" {
				assert.FatalError(t, err)
				return
			}
			var adminErr *admin.Error
			if !errors.As(err, &adminErr) {
				t.Fatalf("expected *admin.Error, got %T: %v", err, err)
			}
			assert.Equals(t, admin.ErrorBadRequestType.String(), adminErr.Type)
			assert.Equals(t, 400, adminErr.Status)
			assert.Equals(t, tc.errMsg, adminErr.Err.Error())
		})
	}
}
