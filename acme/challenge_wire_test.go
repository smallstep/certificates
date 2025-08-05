package acme

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/smallstep/certificates/acme/wire"
	"github.com/smallstep/certificates/authority/provisioner"
	wireprovisioner "github.com/smallstep/certificates/authority/provisioner/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/pemutil"
)

func Test_wireDPOP01Validate(t *testing.T) {
	fakeKey := `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA5c+4NKZSNQcR1T8qN6SjwgdPZQ0Ge12Ylx/YeGAJ35k=
-----END PUBLIC KEY-----`
	type test struct {
		ch          *Challenge
		jwk         *jose.JSONWebKey
		db          WireDB
		payload     []byte
		ctx         context.Context
		expectedErr *Error
	}
	tests := map[string]func(t *testing.T) test{
		"fail/no-provisioner": func(t *testing.T) test {
			return test{
				ctx: context.Background(),
				db:  &MockWireDB{},
				expectedErr: &Error{
					Type:   "urn:ietf:params:acme:error:serverInternal",
					Detail: "The server experienced an internal error",
					Status: 500,
					Err:    errors.New("missing provisioner"),
				},
			}
		},
		"fail/no-linker": func(t *testing.T) test {
			ctx := NewProvisionerContext(context.Background(), newWireProvisionerWithOptions(t, &provisioner.Options{
				Wire: &wireprovisioner.Options{
					OIDC: &wireprovisioner.OIDCOptions{
						Provider: &wireprovisioner.Provider{
							IssuerURL:  "https://issuer.example.com",
							Algorithms: []string{"ES256"},
						},
						Config: &wireprovisioner.Config{
							ClientID:            "test",
							SignatureAlgorithms: []string{"ES256"},
							Now:                 time.Now,
						},
						TransformTemplate: "",
					},
					DPOP: &wireprovisioner.DPOPOptions{
						SigningKey: []byte(fakeKey),
					},
				},
			}))
			return test{
				ctx: ctx,
				db:  &MockWireDB{},
				expectedErr: &Error{
					Type:   "urn:ietf:params:acme:error:serverInternal",
					Detail: "The server experienced an internal error",
					Status: 500,
					Err:    errors.New("missing linker"),
				},
			}
		},
		"fail/unmarshal": func(t *testing.T) test {
			ctx := NewProvisionerContext(context.Background(), newWireProvisionerWithOptions(t, &provisioner.Options{
				Wire: &wireprovisioner.Options{
					OIDC: &wireprovisioner.OIDCOptions{
						Provider: &wireprovisioner.Provider{
							IssuerURL:  "https://issuer.example.com",
							Algorithms: []string{"ES256"},
						},
						Config: &wireprovisioner.Config{
							ClientID:            "test",
							SignatureAlgorithms: []string{"ES256"},
							Now:                 time.Now,
						},
						TransformTemplate: "",
					},
					DPOP: &wireprovisioner.DPOPOptions{
						SigningKey: []byte(fakeKey),
					},
				},
			}))
			ctx = NewLinkerContext(ctx, NewLinker("ca.example.com", "acme"))
			return test{
				ctx:     ctx,
				payload: []byte("?!"),
				ch: &Challenge{
					ID:              "chID",
					AuthorizationID: "azID",
					AccountID:       "accID",
					Token:           "token",
					Type:            "wire-dpop-01",
					Status:          StatusPending,
					Value:           "1234",
				},
				db: &MockWireDB{},
				expectedErr: &Error{
					Type:   "urn:ietf:params:acme:error:malformed",
					Detail: "The request message was malformed",
					Status: 400,
					Err:    errors.New(`error unmarshalling Wire DPoP challenge payload: invalid character '?' looking for beginning of value`),
				},
			}
		},
		"fail/wire-parse-id": func(t *testing.T) test {
			ctx := NewProvisionerContext(context.Background(), newWireProvisionerWithOptions(t, &provisioner.Options{
				Wire: &wireprovisioner.Options{
					OIDC: &wireprovisioner.OIDCOptions{
						Provider: &wireprovisioner.Provider{
							IssuerURL:  "https://issuer.example.com",
							Algorithms: []string{"ES256"},
						},
						Config: &wireprovisioner.Config{
							ClientID:            "test",
							SignatureAlgorithms: []string{"ES256"},
							Now:                 time.Now,
						},
						TransformTemplate: "",
					},
					DPOP: &wireprovisioner.DPOPOptions{
						SigningKey: []byte(fakeKey),
					},
				},
			}))
			ctx = NewLinkerContext(ctx, NewLinker("ca.example.com", "acme"))
			return test{
				ctx:     ctx,
				payload: []byte("{}"),
				ch: &Challenge{
					ID:              "chID",
					AuthorizationID: "azID",
					AccountID:       "accID",
					Token:           "token",
					Type:            "wire-dpop-01",
					Status:          StatusPending,
					Value:           "1234",
				},
				db: &MockWireDB{},
				expectedErr: &Error{
					Type:   "urn:ietf:params:acme:error:serverInternal",
					Detail: "The server experienced an internal error",
					Status: 500,
					Err:    errors.New(`error unmarshalling challenge data: json: cannot unmarshal number into Go value of type wire.DeviceID`),
				},
			}
		},
		"fail/wire-parse-client-id": func(t *testing.T) test {
			ctx := NewProvisionerContext(context.Background(), newWireProvisionerWithOptions(t, &provisioner.Options{
				Wire: &wireprovisioner.Options{
					OIDC: &wireprovisioner.OIDCOptions{
						Provider: &wireprovisioner.Provider{
							IssuerURL:  "https://issuer.example.com",
							Algorithms: []string{"ES256"},
						},
						Config: &wireprovisioner.Config{
							ClientID:            "test",
							SignatureAlgorithms: []string{"ES256"},
							Now:                 time.Now,
						},
						TransformTemplate: "",
					},
					DPOP: &wireprovisioner.DPOPOptions{
						SigningKey: []byte(fakeKey),
					},
				},
			}))
			ctx = NewLinkerContext(ctx, NewLinker("ca.example.com", "acme"))
			valueBytes, err := json.Marshal(struct {
				Name     string `json:"name,omitempty"`
				Domain   string `json:"domain,omitempty"`
				ClientID string `json:"client-id,omitempty"`
				Handle   string `json:"handle,omitempty"`
			}{
				Name:     "Alice Smith",
				Domain:   "wire.com",
				ClientID: "wireapp://594930e9d50bb175@wire.com",
				Handle:   "wireapp://%40alice_wire@wire.com",
			})
			require.NoError(t, err)
			return test{
				ctx:     ctx,
				payload: []byte("{}"),
				ch: &Challenge{
					ID:              "chID",
					AuthorizationID: "azID",
					AccountID:       "accID",
					Token:           "token",
					Type:            "wire-dpop-01",
					Status:          StatusPending,
					Value:           string(valueBytes),
				},
				db: &MockWireDB{},
				expectedErr: &Error{
					Type:   "urn:ietf:params:acme:error:serverInternal",
					Detail: "The server experienced an internal error",
					Status: 500,
					Err:    errors.New(`error parsing device id: invalid Wire client ID username "594930e9d50bb175"`),
				},
			}
		},
		"fail/parse-and-verify": func(t *testing.T) test {
			ctx := NewProvisionerContext(context.Background(), newWireProvisionerWithOptions(t, &provisioner.Options{
				Wire: &wireprovisioner.Options{
					OIDC: &wireprovisioner.OIDCOptions{
						Provider: &wireprovisioner.Provider{
							IssuerURL:  "http://issuer.example.com",
							Algorithms: []string{"ES256"},
						},
						Config: &wireprovisioner.Config{
							ClientID:            "test",
							SignatureAlgorithms: []string{"ES256"},
							Now:                 time.Now,
						},
						TransformTemplate: "",
					},
					DPOP: &wireprovisioner.DPOPOptions{
						Target:     "{{ .DeviceID }}",
						SigningKey: []byte(fakeKey),
					},
				},
			}))
			ctx = NewLinkerContext(ctx, NewLinker("ca.example.com", "acme"))
			valueBytes, err := json.Marshal(struct {
				Name     string `json:"name,omitempty"`
				Domain   string `json:"domain,omitempty"`
				ClientID string `json:"client-id,omitempty"`
				Handle   string `json:"handle,omitempty"`
			}{
				Name:     "Alice Smith",
				Domain:   "wire.com",
				ClientID: "wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com",
				Handle:   "wireapp://%40alice_wire@wire.com",
			})
			require.NoError(t, err)
			jwk, _ := mustAccountAndKeyAuthorization(t, "token")
			return test{
				ctx:     ctx,
				payload: []byte("{}"),
				jwk:     jwk,
				ch: &Challenge{
					ID:              "chID",
					AuthorizationID: "azID",
					AccountID:       "accID",
					Token:           "token",
					Type:            "wire-dpop-01",
					Status:          StatusPending,
					Value:           string(valueBytes),
				},
				db: &MockWireDB{
					MockDB: MockDB{
						MockUpdateChallenge: func(ctx context.Context, ch *Challenge) error {
							assert.Equal(t, "chID", ch.ID)
							assert.Equal(t, "azID", ch.AuthorizationID)
							assert.Equal(t, "accID", ch.AccountID)
							assert.Equal(t, "token", ch.Token)
							assert.Equal(t, ChallengeType("wire-dpop-01"), ch.Type)
							assert.Equal(t, StatusInvalid, ch.Status)
							assert.Equal(t, string(valueBytes), ch.Value)
							if assert.NotNil(t, ch.Error) {
								var k *Error // NOTE: the error is not returned up, but stored with the challenge instead
								if errors.As(ch.Error, &k) {
									assert.Equal(t, "urn:ietf:params:acme:error:rejectedIdentifier", k.Type)
									assert.Equal(t, "The server will not issue certificates for the identifier", k.Detail)
									assert.Equal(t, 400, k.Status)
									assert.Equal(t, `failed validating Wire access token: failed parsing token: go-jose/go-jose: compact JWS format must have three parts`, k.Err.Error())
								}
							}
							return nil
						},
					},
				},
			}
		},
		"fail/db.UpdateChallenge": func(t *testing.T) test {
			jwk, keyAuth := mustAccountAndKeyAuthorization(t, "token")
			_ = keyAuth // TODO(hs): keyAuth (not) required for DPoP? Or needs to be added to validation?
			dpopSigner, err := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.SignatureAlgorithm(jwk.Algorithm),
				Key:       jwk,
			}, new(jose.SignerOptions))
			require.NoError(t, err)
			signerJWK, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			require.NoError(t, err)
			signer, err := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.SignatureAlgorithm(signerJWK.Algorithm),
				Key:       signerJWK,
			}, new(jose.SignerOptions))
			require.NoError(t, err)
			signerPEMBlock, err := pemutil.Serialize(signerJWK.Public().Key)
			require.NoError(t, err)
			signerPEMBytes := pem.EncodeToMemory(signerPEMBlock)
			dpopBytes, err := json.Marshal(struct {
				jose.Claims
				Challenge string `json:"chal,omitempty"`
				Handle    string `json:"handle,omitempty"`
				Nonce     string `json:"nonce,omitempty"`
				HTU       string `json:"htu,omitempty"`
				Name      string `json:"name,omitempty"`
			}{
				Claims: jose.Claims{
					Subject:  "wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com",
					Audience: jose.Audience{"https://ca.example.com/acme/wire/challenge/azID/chID"},
				},
				Challenge: "token",
				Handle:    "wireapp://%40alice_wire@wire.com",
				Nonce:     "nonce",
				HTU:       "http://issuer.example.com",
				Name:      "Alice Smith",
			})
			require.NoError(t, err)
			dpop, err := dpopSigner.Sign(dpopBytes)
			require.NoError(t, err)
			proof, err := dpop.CompactSerialize()
			require.NoError(t, err)
			tokenBytes, err := json.Marshal(struct {
				jose.Claims
				Challenge string `json:"chal,omitempty"`
				Nonce     string `json:"nonce,omitempty"`
				Cnf       struct {
					Kid string `json:"kid,omitempty"`
				} `json:"cnf"`
				Proof      string `json:"proof,omitempty"`
				ClientID   string `json:"client_id"`
				APIVersion int    `json:"api_version"`
				Scope      string `json:"scope"`
			}{
				Claims: jose.Claims{
					Issuer:   "http://issuer.example.com",
					Audience: jose.Audience{"https://ca.example.com/acme/wire/challenge/azID/chID"},
					Expiry:   jose.NewNumericDate(time.Now().Add(1 * time.Minute)),
				},
				Challenge: "token",
				Nonce:     "nonce",
				Cnf: struct {
					Kid string `json:"kid,omitempty"`
				}{
					Kid: jwk.KeyID,
				},
				Proof:      proof,
				ClientID:   "wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com",
				APIVersion: 5,
				Scope:      "wire_client_id",
			})

			require.NoError(t, err)
			signed, err := signer.Sign(tokenBytes)
			require.NoError(t, err)
			accessToken, err := signed.CompactSerialize()
			require.NoError(t, err)
			payload, err := json.Marshal(struct {
				AccessToken string `json:"access_token"`
			}{
				AccessToken: accessToken,
			})
			require.NoError(t, err)
			valueBytes, err := json.Marshal(struct {
				Name     string `json:"name,omitempty"`
				Domain   string `json:"domain,omitempty"`
				ClientID string `json:"client-id,omitempty"`
				Handle   string `json:"handle,omitempty"`
			}{
				Name:     "Alice Smith",
				Domain:   "wire.com",
				ClientID: "wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com",
				Handle:   "wireapp://%40alice_wire@wire.com",
			})
			require.NoError(t, err)
			ctx := NewProvisionerContext(context.Background(), newWireProvisionerWithOptions(t, &provisioner.Options{
				Wire: &wireprovisioner.Options{
					OIDC: &wireprovisioner.OIDCOptions{
						Provider: &wireprovisioner.Provider{
							IssuerURL:  "http://issuer.example.com",
							Algorithms: []string{"ES256"},
						},
						Config: &wireprovisioner.Config{
							ClientID:            "test",
							SignatureAlgorithms: []string{"ES256"},
							Now:                 time.Now,
						},
						TransformTemplate: "",
					},
					DPOP: &wireprovisioner.DPOPOptions{
						Target:     "http://issuer.example.com",
						SigningKey: signerPEMBytes,
					},
				},
			}))
			ctx = NewLinkerContext(ctx, NewLinker("ca.example.com", "acme"))
			return test{
				ch: &Challenge{
					ID:              "chID",
					AuthorizationID: "azID",
					AccountID:       "accID",
					Token:           "token",
					Type:            "wire-dpop-01",
					Status:          StatusPending,
					Value:           string(valueBytes),
				},
				payload: payload,
				ctx:     ctx,
				jwk:     jwk,
				db: &MockWireDB{
					MockDB: MockDB{
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusValid, updch.Status)
							assert.Equal(t, ChallengeType("wire-dpop-01"), updch.Type)
							assert.Equal(t, string(valueBytes), updch.Value)
							return errors.New("fail")
						},
					},
				},
				expectedErr: &Error{
					Type:   "urn:ietf:params:acme:error:serverInternal",
					Detail: "The server experienced an internal error",
					Status: 500,
					Err:    errors.New(`error updating challenge: fail`),
				},
			}
		},
		"fail/db.GetAllOrdersByAccountID": func(t *testing.T) test {
			jwk, keyAuth := mustAccountAndKeyAuthorization(t, "token")
			_ = keyAuth // TODO(hs): keyAuth (not) required for DPoP? Or needs to be added to validation?
			dpopSigner, err := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.SignatureAlgorithm(jwk.Algorithm),
				Key:       jwk,
			}, new(jose.SignerOptions))
			require.NoError(t, err)
			signerJWK, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			require.NoError(t, err)
			signer, err := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.SignatureAlgorithm(signerJWK.Algorithm),
				Key:       signerJWK,
			}, new(jose.SignerOptions))
			require.NoError(t, err)
			signerPEMBlock, err := pemutil.Serialize(signerJWK.Public().Key)
			require.NoError(t, err)
			signerPEMBytes := pem.EncodeToMemory(signerPEMBlock)
			dpopBytes, err := json.Marshal(struct {
				jose.Claims
				Challenge string `json:"chal,omitempty"`
				Handle    string `json:"handle,omitempty"`
				Nonce     string `json:"nonce,omitempty"`
				HTU       string `json:"htu,omitempty"`
				Name      string `json:"name,omitempty"`
			}{
				Claims: jose.Claims{
					Subject:  "wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com",
					Audience: jose.Audience{"https://ca.example.com/acme/wire/challenge/azID/chID"},
				},
				Challenge: "token",
				Handle:    "wireapp://%40alice_wire@wire.com",
				Nonce:     "nonce",
				HTU:       "http://issuer.example.com",
				Name:      "Alice Smith",
			})
			require.NoError(t, err)
			dpop, err := dpopSigner.Sign(dpopBytes)
			require.NoError(t, err)
			proof, err := dpop.CompactSerialize()
			require.NoError(t, err)
			tokenBytes, err := json.Marshal(struct {
				jose.Claims
				Challenge string `json:"chal,omitempty"`
				Nonce     string `json:"nonce,omitempty"`
				Cnf       struct {
					Kid string `json:"kid,omitempty"`
				} `json:"cnf"`
				Proof      string `json:"proof,omitempty"`
				ClientID   string `json:"client_id"`
				APIVersion int    `json:"api_version"`
				Scope      string `json:"scope"`
			}{
				Claims: jose.Claims{
					Issuer:   "http://issuer.example.com",
					Audience: jose.Audience{"https://ca.example.com/acme/wire/challenge/azID/chID"},
					Expiry:   jose.NewNumericDate(time.Now().Add(1 * time.Minute)),
				},
				Challenge: "token",
				Nonce:     "nonce",
				Cnf: struct {
					Kid string `json:"kid,omitempty"`
				}{
					Kid: jwk.KeyID,
				},
				Proof:      proof,
				ClientID:   "wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com",
				APIVersion: 5,
				Scope:      "wire_client_id",
			})

			require.NoError(t, err)
			signed, err := signer.Sign(tokenBytes)
			require.NoError(t, err)
			accessToken, err := signed.CompactSerialize()
			require.NoError(t, err)
			payload, err := json.Marshal(struct {
				AccessToken string `json:"access_token"`
			}{
				AccessToken: accessToken,
			})
			require.NoError(t, err)
			valueBytes, err := json.Marshal(struct {
				Name     string `json:"name,omitempty"`
				Domain   string `json:"domain,omitempty"`
				ClientID string `json:"client-id,omitempty"`
				Handle   string `json:"handle,omitempty"`
			}{
				Name:     "Alice Smith",
				Domain:   "wire.com",
				ClientID: "wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com",
				Handle:   "wireapp://%40alice_wire@wire.com",
			})
			require.NoError(t, err)
			ctx := NewProvisionerContext(context.Background(), newWireProvisionerWithOptions(t, &provisioner.Options{
				Wire: &wireprovisioner.Options{
					OIDC: &wireprovisioner.OIDCOptions{
						Provider: &wireprovisioner.Provider{
							IssuerURL:  "http://issuer.example.com",
							Algorithms: []string{"ES256"},
						},
						Config: &wireprovisioner.Config{
							ClientID:            "test",
							SignatureAlgorithms: []string{"ES256"},
							Now:                 time.Now,
						},
						TransformTemplate: "",
					},
					DPOP: &wireprovisioner.DPOPOptions{
						Target:     "http://issuer.example.com",
						SigningKey: signerPEMBytes,
					},
				},
			}))
			ctx = NewLinkerContext(ctx, NewLinker("ca.example.com", "acme"))
			return test{
				ch: &Challenge{
					ID:              "chID",
					AuthorizationID: "azID",
					AccountID:       "accID",
					Token:           "token",
					Type:            "wire-dpop-01",
					Status:          StatusPending,
					Value:           string(valueBytes),
				},
				payload: payload,
				ctx:     ctx,
				jwk:     jwk,
				db: &MockWireDB{
					MockDB: MockDB{
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusValid, updch.Status)
							assert.Equal(t, ChallengeType("wire-dpop-01"), updch.Type)
							assert.Equal(t, string(valueBytes), updch.Value)
							return nil
						},
					},
					MockGetAllOrdersByAccountID: func(ctx context.Context, accountID string) ([]string, error) {
						assert.Equal(t, "accID", accountID)
						return nil, errors.New("fail")
					},
				},
				expectedErr: &Error{
					Type:   "urn:ietf:params:acme:error:serverInternal",
					Detail: "The server experienced an internal error",
					Status: 500,
					Err:    errors.New(`could not find current order by account id: fail`),
				},
			}
		},
		"fail/db.GetAllOrdersByAccountID-zero": func(t *testing.T) test {
			jwk, keyAuth := mustAccountAndKeyAuthorization(t, "token")
			_ = keyAuth // TODO(hs): keyAuth (not) required for DPoP? Or needs to be added to validation?
			dpopSigner, err := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.SignatureAlgorithm(jwk.Algorithm),
				Key:       jwk,
			}, new(jose.SignerOptions))
			require.NoError(t, err)
			signerJWK, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			require.NoError(t, err)
			signer, err := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.SignatureAlgorithm(signerJWK.Algorithm),
				Key:       signerJWK,
			}, new(jose.SignerOptions))
			require.NoError(t, err)
			signerPEMBlock, err := pemutil.Serialize(signerJWK.Public().Key)
			require.NoError(t, err)
			signerPEMBytes := pem.EncodeToMemory(signerPEMBlock)
			dpopBytes, err := json.Marshal(struct {
				jose.Claims
				Challenge string `json:"chal,omitempty"`
				Handle    string `json:"handle,omitempty"`
				Nonce     string `json:"nonce,omitempty"`
				HTU       string `json:"htu,omitempty"`
				Name      string `json:"name,omitempty"`
			}{
				Claims: jose.Claims{
					Subject:  "wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com",
					Audience: jose.Audience{"https://ca.example.com/acme/wire/challenge/azID/chID"},
				},
				Challenge: "token",
				Handle:    "wireapp://%40alice_wire@wire.com",
				Nonce:     "nonce",
				HTU:       "http://issuer.example.com",
				Name:      "Alice Smith",
			})
			require.NoError(t, err)
			dpop, err := dpopSigner.Sign(dpopBytes)
			require.NoError(t, err)
			proof, err := dpop.CompactSerialize()
			require.NoError(t, err)
			tokenBytes, err := json.Marshal(struct {
				jose.Claims
				Challenge string `json:"chal,omitempty"`
				Nonce     string `json:"nonce,omitempty"`
				Cnf       struct {
					Kid string `json:"kid,omitempty"`
				} `json:"cnf"`
				Proof      string `json:"proof,omitempty"`
				ClientID   string `json:"client_id"`
				APIVersion int    `json:"api_version"`
				Scope      string `json:"scope"`
			}{
				Claims: jose.Claims{
					Issuer:   "http://issuer.example.com",
					Audience: jose.Audience{"https://ca.example.com/acme/wire/challenge/azID/chID"},
					Expiry:   jose.NewNumericDate(time.Now().Add(1 * time.Minute)),
				},
				Challenge: "token",
				Nonce:     "nonce",
				Cnf: struct {
					Kid string `json:"kid,omitempty"`
				}{
					Kid: jwk.KeyID,
				},
				Proof:      proof,
				ClientID:   "wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com",
				APIVersion: 5,
				Scope:      "wire_client_id",
			})

			require.NoError(t, err)
			signed, err := signer.Sign(tokenBytes)
			require.NoError(t, err)
			accessToken, err := signed.CompactSerialize()
			require.NoError(t, err)
			payload, err := json.Marshal(struct {
				AccessToken string `json:"access_token"`
			}{
				AccessToken: accessToken,
			})
			require.NoError(t, err)
			valueBytes, err := json.Marshal(struct {
				Name     string `json:"name,omitempty"`
				Domain   string `json:"domain,omitempty"`
				ClientID string `json:"client-id,omitempty"`
				Handle   string `json:"handle,omitempty"`
			}{
				Name:     "Alice Smith",
				Domain:   "wire.com",
				ClientID: "wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com",
				Handle:   "wireapp://%40alice_wire@wire.com",
			})
			require.NoError(t, err)
			ctx := NewProvisionerContext(context.Background(), newWireProvisionerWithOptions(t, &provisioner.Options{
				Wire: &wireprovisioner.Options{
					OIDC: &wireprovisioner.OIDCOptions{
						Provider: &wireprovisioner.Provider{
							IssuerURL:  "http://issuer.example.com",
							Algorithms: []string{"ES256"},
						},
						Config: &wireprovisioner.Config{
							ClientID:            "test",
							SignatureAlgorithms: []string{"ES256"},
							Now:                 time.Now,
						},
						TransformTemplate: "",
					},
					DPOP: &wireprovisioner.DPOPOptions{
						Target:     "http://issuer.example.com",
						SigningKey: signerPEMBytes,
					},
				},
			}))
			ctx = NewLinkerContext(ctx, NewLinker("ca.example.com", "acme"))
			return test{
				ch: &Challenge{
					ID:              "chID",
					AuthorizationID: "azID",
					AccountID:       "accID",
					Token:           "token",
					Type:            "wire-dpop-01",
					Status:          StatusPending,
					Value:           string(valueBytes),
				},
				payload: payload,
				ctx:     ctx,
				jwk:     jwk,
				db: &MockWireDB{
					MockDB: MockDB{
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusValid, updch.Status)
							assert.Equal(t, ChallengeType("wire-dpop-01"), updch.Type)
							assert.Equal(t, string(valueBytes), updch.Value)
							return nil
						},
					},
					MockGetAllOrdersByAccountID: func(ctx context.Context, accountID string) ([]string, error) {
						assert.Equal(t, "accID", accountID)
						return []string{}, nil
					},
				},
				expectedErr: &Error{
					Type:   "urn:ietf:params:acme:error:serverInternal",
					Detail: "The server experienced an internal error",
					Status: 500,
					Err:    errors.New(`there are not enough orders for this account for this custom OIDC challenge`),
				},
			}
		},
		"fail/db.CreateDpopToken": func(t *testing.T) test {
			jwk, keyAuth := mustAccountAndKeyAuthorization(t, "token")
			_ = keyAuth // TODO(hs): keyAuth (not) required for DPoP? Or needs to be added to validation?
			dpopSigner, err := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.SignatureAlgorithm(jwk.Algorithm),
				Key:       jwk,
			}, new(jose.SignerOptions))
			require.NoError(t, err)
			signerJWK, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			require.NoError(t, err)
			signer, err := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.SignatureAlgorithm(signerJWK.Algorithm),
				Key:       signerJWK,
			}, new(jose.SignerOptions))
			require.NoError(t, err)
			signerPEMBlock, err := pemutil.Serialize(signerJWK.Public().Key)
			require.NoError(t, err)
			signerPEMBytes := pem.EncodeToMemory(signerPEMBlock)
			dpopBytes, err := json.Marshal(struct {
				jose.Claims
				Challenge string `json:"chal,omitempty"`
				Handle    string `json:"handle,omitempty"`
				Nonce     string `json:"nonce,omitempty"`
				HTU       string `json:"htu,omitempty"`
				Name      string `json:"name,omitempty"`
			}{
				Claims: jose.Claims{
					Subject:  "wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com",
					Audience: jose.Audience{"https://ca.example.com/acme/wire/challenge/azID/chID"},
				},
				Challenge: "token",
				Handle:    "wireapp://%40alice_wire@wire.com",
				Nonce:     "nonce",
				HTU:       "http://issuer.example.com",
				Name:      "Alice Smith",
			})
			require.NoError(t, err)
			dpop, err := dpopSigner.Sign(dpopBytes)
			require.NoError(t, err)
			proof, err := dpop.CompactSerialize()
			require.NoError(t, err)
			tokenBytes, err := json.Marshal(struct {
				jose.Claims
				Challenge string `json:"chal,omitempty"`
				Nonce     string `json:"nonce,omitempty"`
				Cnf       struct {
					Kid string `json:"kid,omitempty"`
				} `json:"cnf"`
				Proof      string `json:"proof,omitempty"`
				ClientID   string `json:"client_id"`
				APIVersion int    `json:"api_version"`
				Scope      string `json:"scope"`
			}{
				Claims: jose.Claims{
					Issuer:   "http://issuer.example.com",
					Audience: jose.Audience{"https://ca.example.com/acme/wire/challenge/azID/chID"},
					Expiry:   jose.NewNumericDate(time.Now().Add(1 * time.Minute)),
				},
				Challenge: "token",
				Nonce:     "nonce",
				Cnf: struct {
					Kid string `json:"kid,omitempty"`
				}{
					Kid: jwk.KeyID,
				},
				Proof:      proof,
				ClientID:   "wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com",
				APIVersion: 5,
				Scope:      "wire_client_id",
			})

			require.NoError(t, err)
			signed, err := signer.Sign(tokenBytes)
			require.NoError(t, err)
			accessToken, err := signed.CompactSerialize()
			require.NoError(t, err)
			payload, err := json.Marshal(struct {
				AccessToken string `json:"access_token"`
			}{
				AccessToken: accessToken,
			})
			require.NoError(t, err)
			valueBytes, err := json.Marshal(struct {
				Name     string `json:"name,omitempty"`
				Domain   string `json:"domain,omitempty"`
				ClientID string `json:"client-id,omitempty"`
				Handle   string `json:"handle,omitempty"`
			}{
				Name:     "Alice Smith",
				Domain:   "wire.com",
				ClientID: "wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com",
				Handle:   "wireapp://%40alice_wire@wire.com",
			})
			require.NoError(t, err)
			ctx := NewProvisionerContext(context.Background(), newWireProvisionerWithOptions(t, &provisioner.Options{
				Wire: &wireprovisioner.Options{
					OIDC: &wireprovisioner.OIDCOptions{
						Provider: &wireprovisioner.Provider{
							IssuerURL:  "http://issuer.example.com",
							Algorithms: []string{"ES256"},
						},
						Config: &wireprovisioner.Config{
							ClientID:            "test",
							SignatureAlgorithms: []string{"ES256"},
							Now:                 time.Now,
						},
						TransformTemplate: "",
					},
					DPOP: &wireprovisioner.DPOPOptions{
						Target:     "http://issuer.example.com",
						SigningKey: signerPEMBytes,
					},
				},
			}))
			ctx = NewLinkerContext(ctx, NewLinker("ca.example.com", "acme"))
			return test{
				ch: &Challenge{
					ID:              "chID",
					AuthorizationID: "azID",
					AccountID:       "accID",
					Token:           "token",
					Type:            "wire-dpop-01",
					Status:          StatusPending,
					Value:           string(valueBytes),
				},
				payload: payload,
				ctx:     ctx,
				jwk:     jwk,
				db: &MockWireDB{
					MockDB: MockDB{
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusValid, updch.Status)
							assert.Equal(t, ChallengeType("wire-dpop-01"), updch.Type)
							assert.Equal(t, string(valueBytes), updch.Value)
							return nil
						},
					},
					MockGetAllOrdersByAccountID: func(ctx context.Context, accountID string) ([]string, error) {
						assert.Equal(t, "accID", accountID)
						return []string{"orderID"}, nil
					},
					MockCreateDpopToken: func(ctx context.Context, orderID string, dpop map[string]interface{}) error {
						assert.Equal(t, "orderID", orderID)
						assert.Equal(t, "token", dpop["chal"].(string))
						assert.Equal(t, "wireapp://%40alice_wire@wire.com", dpop["handle"].(string))
						assert.Equal(t, "wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com", dpop["sub"].(string))
						return errors.New("fail")
					},
				},
				expectedErr: &Error{
					Type:   "urn:ietf:params:acme:error:serverInternal",
					Detail: "The server experienced an internal error",
					Status: 500,
					Err:    errors.New(`failed storing DPoP token: fail`),
				},
			}
		},
		"ok": func(t *testing.T) test {
			jwk, keyAuth := mustAccountAndKeyAuthorization(t, "token")
			_ = keyAuth // TODO(hs): keyAuth (not) required for DPoP? Or needs to be added to validation?
			dpopSigner, err := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.SignatureAlgorithm(jwk.Algorithm),
				Key:       jwk,
			}, new(jose.SignerOptions))
			require.NoError(t, err)
			signerJWK, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			require.NoError(t, err)
			signer, err := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.SignatureAlgorithm(signerJWK.Algorithm),
				Key:       signerJWK,
			}, new(jose.SignerOptions))
			require.NoError(t, err)
			signerPEMBlock, err := pemutil.Serialize(signerJWK.Public().Key)
			require.NoError(t, err)
			signerPEMBytes := pem.EncodeToMemory(signerPEMBlock)
			dpopBytes, err := json.Marshal(struct {
				jose.Claims
				Challenge string `json:"chal,omitempty"`
				Handle    string `json:"handle,omitempty"`
				Nonce     string `json:"nonce,omitempty"`
				HTU       string `json:"htu,omitempty"`
				Name      string `json:"name,omitempty"`
			}{
				Claims: jose.Claims{
					Subject:  "wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com",
					Audience: jose.Audience{"https://ca.example.com/acme/wire/challenge/azID/chID"},
				},
				Challenge: "token",
				Handle:    "wireapp://%40alice_wire@wire.com",
				Nonce:     "nonce",
				HTU:       "http://issuer.example.com",
				Name:      "Alice Smith",
			})
			require.NoError(t, err)
			dpop, err := dpopSigner.Sign(dpopBytes)
			require.NoError(t, err)
			proof, err := dpop.CompactSerialize()
			require.NoError(t, err)
			tokenBytes, err := json.Marshal(struct {
				jose.Claims
				Challenge string `json:"chal,omitempty"`
				Nonce     string `json:"nonce,omitempty"`
				Cnf       struct {
					Kid string `json:"kid,omitempty"`
				} `json:"cnf"`
				Proof      string `json:"proof,omitempty"`
				ClientID   string `json:"client_id"`
				APIVersion int    `json:"api_version"`
				Scope      string `json:"scope"`
			}{
				Claims: jose.Claims{
					Issuer:   "http://issuer.example.com",
					Audience: jose.Audience{"https://ca.example.com/acme/wire/challenge/azID/chID"},
					Expiry:   jose.NewNumericDate(time.Now().Add(1 * time.Minute)),
				},
				Challenge: "token",
				Nonce:     "nonce",
				Cnf: struct {
					Kid string `json:"kid,omitempty"`
				}{
					Kid: jwk.KeyID,
				},
				Proof:      proof,
				ClientID:   "wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com",
				APIVersion: 5,
				Scope:      "wire_client_id",
			})
			require.NoError(t, err)
			signed, err := signer.Sign(tokenBytes)
			require.NoError(t, err)
			accessToken, err := signed.CompactSerialize()
			require.NoError(t, err)
			payload, err := json.Marshal(struct {
				AccessToken string `json:"access_token"`
			}{
				AccessToken: accessToken,
			})
			require.NoError(t, err)
			valueBytes, err := json.Marshal(struct {
				Name     string `json:"name,omitempty"`
				Domain   string `json:"domain,omitempty"`
				ClientID string `json:"client-id,omitempty"`
				Handle   string `json:"handle,omitempty"`
			}{
				Name:     "Alice Smith",
				Domain:   "wire.com",
				ClientID: "wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com",
				Handle:   "wireapp://%40alice_wire@wire.com",
			})
			require.NoError(t, err)
			ctx := NewProvisionerContext(context.Background(), newWireProvisionerWithOptions(t, &provisioner.Options{
				Wire: &wireprovisioner.Options{
					OIDC: &wireprovisioner.OIDCOptions{
						Provider: &wireprovisioner.Provider{
							IssuerURL:  "http://issuer.example.com",
							Algorithms: []string{"ES256"},
						},
						Config: &wireprovisioner.Config{
							ClientID:            "test",
							SignatureAlgorithms: []string{"ES256"},
							Now:                 time.Now,
						},
						TransformTemplate: "",
					},
					DPOP: &wireprovisioner.DPOPOptions{
						Target:     "http://issuer.example.com",
						SigningKey: signerPEMBytes,
					},
				},
			}))
			ctx = NewLinkerContext(ctx, NewLinker("ca.example.com", "acme"))
			return test{
				ch: &Challenge{
					ID:              "chID",
					AuthorizationID: "azID",
					AccountID:       "accID",
					Token:           "token",
					Type:            "wire-dpop-01",
					Status:          StatusPending,
					Value:           string(valueBytes),
				},
				payload: payload,
				ctx:     ctx,
				jwk:     jwk,
				db: &MockWireDB{
					MockDB: MockDB{
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusValid, updch.Status)
							assert.Equal(t, ChallengeType("wire-dpop-01"), updch.Type)
							assert.Equal(t, string(valueBytes), updch.Value)
							return nil
						},
					},
					MockGetAllOrdersByAccountID: func(ctx context.Context, accountID string) ([]string, error) {
						assert.Equal(t, "accID", accountID)
						return []string{"orderID"}, nil
					},
					MockCreateDpopToken: func(ctx context.Context, orderID string, dpop map[string]interface{}) error {
						assert.Equal(t, "orderID", orderID)
						assert.Equal(t, "token", dpop["chal"].(string))
						assert.Equal(t, "wireapp://%40alice_wire@wire.com", dpop["handle"].(string))
						assert.Equal(t, "wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com", dpop["sub"].(string))
						return nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			err := wireDPOP01Validate(tc.ctx, tc.ch, tc.db, tc.jwk, tc.payload)
			if tc.expectedErr != nil {
				var k *Error
				if errors.As(err, &k) {
					assert.Equal(t, tc.expectedErr.Type, k.Type)
					assert.Equal(t, tc.expectedErr.Detail, k.Detail)
					assert.Equal(t, tc.expectedErr.Status, k.Status)
					assert.Equal(t, tc.expectedErr.Err.Error(), k.Err.Error())
				} else {
					assert.Fail(t, "unexpected error type")
				}
				return
			}

			assert.NoError(t, err)
		})
	}
}

func Test_wireOIDC01Validate(t *testing.T) {
	fakeKey := `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA5c+4NKZSNQcR1T8qN6SjwgdPZQ0Ge12Ylx/YeGAJ35k=
-----END PUBLIC KEY-----`
	type test struct {
		ch          *Challenge
		jwk         *jose.JSONWebKey
		db          WireDB
		payload     []byte
		srv         *httptest.Server
		ctx         context.Context
		expectedErr *Error
	}
	tests := map[string]func(t *testing.T) test{
		"fail/no-provisioner": func(t *testing.T) test {
			return test{
				ctx: context.Background(),
				db:  &MockWireDB{},
				expectedErr: &Error{
					Type:   "urn:ietf:params:acme:error:serverInternal",
					Detail: "The server experienced an internal error",
					Status: 500,
					Err:    errors.New("missing provisioner"),
				},
			}
		},
		"fail/no-linker": func(t *testing.T) test {
			ctx := NewProvisionerContext(context.Background(), newWireProvisionerWithOptions(t, &provisioner.Options{
				Wire: &wireprovisioner.Options{
					OIDC: &wireprovisioner.OIDCOptions{
						Provider: &wireprovisioner.Provider{
							IssuerURL:  "https://issuer.example.com",
							Algorithms: []string{"ES256"},
						},
						Config: &wireprovisioner.Config{
							ClientID:            "test",
							SignatureAlgorithms: []string{"ES256"},
							Now:                 time.Now,
						},
						TransformTemplate: "",
					},
					DPOP: &wireprovisioner.DPOPOptions{
						SigningKey: []byte(fakeKey),
					},
				},
			}))
			return test{
				ctx: ctx,
				db:  &MockWireDB{},
				expectedErr: &Error{
					Type:   "urn:ietf:params:acme:error:serverInternal",
					Detail: "The server experienced an internal error",
					Status: 500,
					Err:    errors.New("missing linker"),
				},
			}
		},
		"fail/unmarshal": func(t *testing.T) test {
			ctx := NewProvisionerContext(context.Background(), newWireProvisionerWithOptions(t, &provisioner.Options{
				Wire: &wireprovisioner.Options{
					OIDC: &wireprovisioner.OIDCOptions{
						Provider: &wireprovisioner.Provider{
							IssuerURL:  "https://issuer.example.com",
							Algorithms: []string{"ES256"},
						},
						Config: &wireprovisioner.Config{
							ClientID:            "test",
							SignatureAlgorithms: []string{"ES256"},
							Now:                 time.Now,
						},
						TransformTemplate: "",
					},
					DPOP: &wireprovisioner.DPOPOptions{
						SigningKey: []byte(fakeKey),
					},
				},
			}))
			ctx = NewLinkerContext(ctx, NewLinker("ca.example.com", "acme"))
			return test{
				ctx:     ctx,
				payload: []byte("?!"),
				ch: &Challenge{
					ID:              "chID",
					AuthorizationID: "azID",
					AccountID:       "accID",
					Token:           "token",
					Type:            "wire-oidc-01",
					Status:          StatusPending,
					Value:           "1234",
				},
				db: &MockWireDB{
					MockDB: MockDB{
						MockUpdateChallenge: func(ctx context.Context, ch *Challenge) error {
							assert.Equal(t, "chID", ch.ID)
							return nil
						},
					},
				},
				expectedErr: &Error{
					Type:   "urn:ietf:params:acme:error:malformed",
					Detail: "The request message was malformed",
					Status: 400,
					Err:    errors.New(`error unmarshalling Wire OIDC challenge payload: invalid character '?' looking for beginning of value`),
				},
			}
		},
		"fail/wire-parse-id": func(t *testing.T) test {
			ctx := NewProvisionerContext(context.Background(), newWireProvisionerWithOptions(t, &provisioner.Options{
				Wire: &wireprovisioner.Options{
					OIDC: &wireprovisioner.OIDCOptions{
						Provider: &wireprovisioner.Provider{
							IssuerURL:  "https://issuer.example.com",
							Algorithms: []string{"ES256"},
						},
						Config: &wireprovisioner.Config{
							ClientID:            "test",
							SignatureAlgorithms: []string{"ES256"},
							Now:                 time.Now,
						},
						TransformTemplate: "",
					},
					DPOP: &wireprovisioner.DPOPOptions{
						SigningKey: []byte(fakeKey),
					},
				},
			}))
			ctx = NewLinkerContext(ctx, NewLinker("ca.example.com", "acme"))
			return test{
				ctx:     ctx,
				payload: []byte("{}"),
				ch: &Challenge{
					ID:              "chID",
					AuthorizationID: "azID",
					AccountID:       "accID",
					Token:           "token",
					Type:            "wire-oidc-01",
					Status:          StatusPending,
					Value:           "1234",
				},
				db: &MockWireDB{},
				expectedErr: &Error{
					Type:   "urn:ietf:params:acme:error:serverInternal",
					Detail: "The server experienced an internal error",
					Status: 500,
					Err:    errors.New(`error unmarshalling challenge data: json: cannot unmarshal number into Go value of type wire.UserID`),
				},
			}
		},
		"fail/verify": func(t *testing.T) test {
			jwk, keyAuth := mustAccountAndKeyAuthorization(t, "token")
			signerJWK, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			require.NoError(t, err)
			signer, err := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.SignatureAlgorithm(signerJWK.Algorithm),
				Key:       signerJWK,
			}, new(jose.SignerOptions))
			require.NoError(t, err)
			anotherSignerJWK, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			require.NoError(t, err)
			srv := mustJWKServer(t, anotherSignerJWK.Public())
			tokenBytes, err := json.Marshal(struct {
				jose.Claims
				Name              string `json:"name,omitempty"`
				PreferredUsername string `json:"preferred_username,omitempty"`
				KeyAuth           string `json:"keyauth"`
				ACMEAudience      string `json:"acme_aud"`
			}{
				Claims: jose.Claims{
					Issuer:   srv.URL,
					Audience: []string{"test"},
					Expiry:   jose.NewNumericDate(time.Now().Add(1 * time.Minute)),
				},
				Name:              "Alice Smith",
				PreferredUsername: "wireapp://%40alice_wire@wire.com",
				KeyAuth:           keyAuth,
				ACMEAudience:      "https://ca.example.com/acme/wire/challenge/azID/chID",
			})
			require.NoError(t, err)
			signed, err := signer.Sign(tokenBytes)
			require.NoError(t, err)
			idToken, err := signed.CompactSerialize()
			require.NoError(t, err)
			payload, err := json.Marshal(struct {
				IDToken string `json:"id_token"`
			}{
				IDToken: idToken,
			})
			require.NoError(t, err)
			valueBytes, err := json.Marshal(struct {
				Name     string `json:"name,omitempty"`
				Domain   string `json:"domain,omitempty"`
				ClientID string `json:"client-id,omitempty"`
				Handle   string `json:"handle,omitempty"`
			}{
				Name:     "Alice Smith",
				Domain:   "wire.com",
				ClientID: "wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com",
				Handle:   "wireapp://%40alice_wire@wire.com",
			})
			require.NoError(t, err)
			ctx := NewProvisionerContext(context.Background(), newWireProvisionerWithOptions(t, &provisioner.Options{
				Wire: &wireprovisioner.Options{
					OIDC: &wireprovisioner.OIDCOptions{
						Provider: &wireprovisioner.Provider{
							IssuerURL:  srv.URL,
							JWKSURL:    srv.URL + "/keys",
							Algorithms: []string{"ES256"},
						},
						Config: &wireprovisioner.Config{
							ClientID:            "test",
							SignatureAlgorithms: []string{"ES256"},
							Now:                 time.Now,
						},
						TransformTemplate: "",
					},
					DPOP: &wireprovisioner.DPOPOptions{
						SigningKey: []byte(fakeKey),
					},
				},
			}))
			ctx = NewLinkerContext(ctx, NewLinker("ca.example.com", "acme"))
			return test{
				ch: &Challenge{
					ID:              "chID",
					AuthorizationID: "azID",
					AccountID:       "accID",
					Token:           "token",
					Type:            "wire-oidc-01",
					Status:          StatusPending,
					Value:           string(valueBytes),
				},
				srv:     srv,
				payload: payload,
				ctx:     ctx,
				jwk:     jwk,
				db: &MockWireDB{
					MockDB: MockDB{
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusInvalid, updch.Status)
							assert.Equal(t, ChallengeType("wire-oidc-01"), updch.Type)
							assert.Equal(t, string(valueBytes), updch.Value)
							if assert.NotNil(t, updch.Error) {
								var k *Error // NOTE: the error is not returned up, but stored with the challenge instead
								if errors.As(updch.Error, &k) {
									assert.Equal(t, "urn:ietf:params:acme:error:rejectedIdentifier", k.Type)
									assert.Equal(t, "The server will not issue certificates for the identifier", k.Detail)
									assert.Equal(t, 400, k.Status)
									assert.Equal(t, `error verifying ID token signature: failed to verify signature: failed to verify id token signature`, k.Err.Error())
								}
							}
							return nil
						},
					},
				},
			}
		},
		"fail/keyauth-mismatch": func(t *testing.T) test {
			jwk, _ := mustAccountAndKeyAuthorization(t, "token")
			signerJWK, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			require.NoError(t, err)
			signer, err := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.SignatureAlgorithm(signerJWK.Algorithm),
				Key:       signerJWK,
			}, new(jose.SignerOptions))
			require.NoError(t, err)
			srv := mustJWKServer(t, signerJWK.Public())
			tokenBytes, err := json.Marshal(struct {
				jose.Claims
				Name              string `json:"name,omitempty"`
				PreferredUsername string `json:"preferred_username,omitempty"`
				KeyAuth           string `json:"keyauth"`
				ACMEAudience      string `json:"acme_aud"`
			}{
				Claims: jose.Claims{
					Issuer:   srv.URL,
					Audience: []string{"test"},
					Expiry:   jose.NewNumericDate(time.Now().Add(1 * time.Minute)),
				},
				Name:              "Alice Smith",
				PreferredUsername: "wireapp://%40alice_wire@wire.com",
				KeyAuth:           "wrong-keyauth",
				ACMEAudience:      "https://ca.example.com/acme/wire/challenge/azID/chID",
			})
			require.NoError(t, err)
			signed, err := signer.Sign(tokenBytes)
			require.NoError(t, err)
			idToken, err := signed.CompactSerialize()
			require.NoError(t, err)
			payload, err := json.Marshal(struct {
				IDToken string `json:"id_token"`
			}{
				IDToken: idToken,
			})
			require.NoError(t, err)
			valueBytes, err := json.Marshal(struct {
				Name     string `json:"name,omitempty"`
				Domain   string `json:"domain,omitempty"`
				ClientID string `json:"client-id,omitempty"`
				Handle   string `json:"handle,omitempty"`
			}{
				Name:     "Alice Smith",
				Domain:   "wire.com",
				ClientID: "wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com",
				Handle:   "wireapp://%40alice_wire@wire.com",
			})
			require.NoError(t, err)
			ctx := NewProvisionerContext(context.Background(), newWireProvisionerWithOptions(t, &provisioner.Options{
				Wire: &wireprovisioner.Options{
					OIDC: &wireprovisioner.OIDCOptions{
						Provider: &wireprovisioner.Provider{
							IssuerURL:  srv.URL,
							JWKSURL:    srv.URL + "/keys",
							Algorithms: []string{"ES256"},
						},
						Config: &wireprovisioner.Config{
							ClientID:            "test",
							SignatureAlgorithms: []string{"ES256"},
							Now:                 time.Now,
						},
						TransformTemplate: "",
					},
					DPOP: &wireprovisioner.DPOPOptions{
						SigningKey: []byte(fakeKey),
					},
				},
			}))
			ctx = NewLinkerContext(ctx, NewLinker("ca.example.com", "acme"))
			return test{
				ch: &Challenge{
					ID:              "chID",
					AuthorizationID: "azID",
					AccountID:       "accID",
					Token:           "token",
					Type:            "wire-oidc-01",
					Status:          StatusPending,
					Value:           string(valueBytes),
				},
				srv:     srv,
				payload: payload,
				ctx:     ctx,
				jwk:     jwk,
				db: &MockWireDB{
					MockDB: MockDB{
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusInvalid, updch.Status)
							assert.Equal(t, ChallengeType("wire-oidc-01"), updch.Type)
							assert.Equal(t, string(valueBytes), updch.Value)
							if assert.NotNil(t, updch.Error) {
								var k *Error // NOTE: the error is not returned up, but stored with the challenge instead
								if errors.As(updch.Error, &k) {
									assert.Equal(t, "urn:ietf:params:acme:error:rejectedIdentifier", k.Type)
									assert.Equal(t, "The server will not issue certificates for the identifier", k.Detail)
									assert.Equal(t, 400, k.Status)
									assert.Contains(t, k.Err.Error(), "keyAuthorization does not match")
								}
							}
							return nil
						},
					},
				},
			}
		},
		"fail/validateWireOIDCClaims": func(t *testing.T) test {
			jwk, keyAuth := mustAccountAndKeyAuthorization(t, "token")
			signerJWK, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			require.NoError(t, err)
			signer, err := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.SignatureAlgorithm(signerJWK.Algorithm),
				Key:       signerJWK,
			}, new(jose.SignerOptions))
			require.NoError(t, err)
			srv := mustJWKServer(t, signerJWK.Public())
			tokenBytes, err := json.Marshal(struct {
				jose.Claims
				Name              string `json:"name,omitempty"`
				PreferredUsername string `json:"preferred_username,omitempty"`
				KeyAuth           string `json:"keyauth"`
				ACMEAudience      string `json:"acme_aud"`
			}{
				Claims: jose.Claims{
					Issuer:   srv.URL,
					Audience: []string{"test"},
					Expiry:   jose.NewNumericDate(time.Now().Add(1 * time.Minute)),
				},
				Name:              "Alice Smith",
				PreferredUsername: "wireapp://%40bob@wire.com",
				KeyAuth:           keyAuth,
				ACMEAudience:      "https://ca.example.com/acme/wire/challenge/azID/chID",
			})
			require.NoError(t, err)
			signed, err := signer.Sign(tokenBytes)
			require.NoError(t, err)
			idToken, err := signed.CompactSerialize()
			require.NoError(t, err)
			payload, err := json.Marshal(struct {
				IDToken string `json:"id_token"`
			}{
				IDToken: idToken,
			})
			require.NoError(t, err)
			valueBytes, err := json.Marshal(struct {
				Name     string `json:"name,omitempty"`
				Domain   string `json:"domain,omitempty"`
				ClientID string `json:"client-id,omitempty"`
				Handle   string `json:"handle,omitempty"`
			}{
				Name:     "Alice Smith",
				Domain:   "wire.com",
				ClientID: "wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com",
				Handle:   "wireapp://%40alice_wire@wire.com",
			})
			require.NoError(t, err)
			ctx := NewProvisionerContext(context.Background(), newWireProvisionerWithOptions(t, &provisioner.Options{
				Wire: &wireprovisioner.Options{
					OIDC: &wireprovisioner.OIDCOptions{
						Provider: &wireprovisioner.Provider{
							IssuerURL:  srv.URL,
							JWKSURL:    srv.URL + "/keys",
							Algorithms: []string{"ES256"},
						},
						Config: &wireprovisioner.Config{
							ClientID:            "test",
							SignatureAlgorithms: []string{"ES256"},
							Now:                 time.Now,
						},
						TransformTemplate: "",
					},
					DPOP: &wireprovisioner.DPOPOptions{
						SigningKey: []byte(fakeKey),
					},
				},
			}))
			ctx = NewLinkerContext(ctx, NewLinker("ca.example.com", "acme"))
			return test{
				ch: &Challenge{
					ID:              "chID",
					AuthorizationID: "azID",
					AccountID:       "accID",
					Token:           "token",
					Type:            "wire-oidc-01",
					Status:          StatusPending,
					Value:           string(valueBytes),
				},
				srv:     srv,
				payload: payload,
				ctx:     ctx,
				jwk:     jwk,
				db: &MockWireDB{
					MockDB: MockDB{
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusInvalid, updch.Status)
							assert.Equal(t, ChallengeType("wire-oidc-01"), updch.Type)
							assert.Equal(t, string(valueBytes), updch.Value)
							if assert.NotNil(t, updch.Error) {
								var k *Error // NOTE: the error is not returned up, but stored with the challenge instead
								if errors.As(updch.Error, &k) {
									assert.Equal(t, "urn:ietf:params:acme:error:rejectedIdentifier", k.Type)
									assert.Equal(t, "The server will not issue certificates for the identifier", k.Detail)
									assert.Equal(t, 400, k.Status)
									assert.Equal(t, `claims in OIDC ID token don't match: invalid 'preferred_username' "wireapp://%40bob@wire.com" after transformation`, k.Err.Error())
								}
							}
							return nil
						},
					},
				},
			}
		},
		"fail/db.UpdateChallenge": func(t *testing.T) test {
			jwk, keyAuth := mustAccountAndKeyAuthorization(t, "token")
			signerJWK, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			require.NoError(t, err)
			signer, err := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.SignatureAlgorithm(signerJWK.Algorithm),
				Key:       signerJWK,
			}, new(jose.SignerOptions))
			require.NoError(t, err)
			srv := mustJWKServer(t, signerJWK.Public())
			tokenBytes, err := json.Marshal(struct {
				jose.Claims
				Name              string `json:"name,omitempty"`
				PreferredUsername string `json:"preferred_username,omitempty"`
				KeyAuth           string `json:"keyauth"`
				ACMEAudience      string `json:"acme_aud"`
			}{
				Claims: jose.Claims{
					Issuer:   srv.URL,
					Audience: []string{"test"},
					Expiry:   jose.NewNumericDate(time.Now().Add(1 * time.Minute)),
				},
				Name:              "Alice Smith",
				PreferredUsername: "wireapp://%40alice_wire@wire.com",
				KeyAuth:           keyAuth,
				ACMEAudience:      "https://ca.example.com/acme/wire/challenge/azID/chID",
			})
			require.NoError(t, err)
			signed, err := signer.Sign(tokenBytes)
			require.NoError(t, err)
			idToken, err := signed.CompactSerialize()
			require.NoError(t, err)
			payload, err := json.Marshal(struct {
				IDToken string `json:"id_token"`
			}{
				IDToken: idToken,
			})
			require.NoError(t, err)
			valueBytes, err := json.Marshal(struct {
				Name     string `json:"name,omitempty"`
				Domain   string `json:"domain,omitempty"`
				ClientID string `json:"client-id,omitempty"`
				Handle   string `json:"handle,omitempty"`
			}{
				Name:     "Alice Smith",
				Domain:   "wire.com",
				ClientID: "wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com",
				Handle:   "wireapp://%40alice_wire@wire.com",
			})
			require.NoError(t, err)
			ctx := NewProvisionerContext(context.Background(), newWireProvisionerWithOptions(t, &provisioner.Options{
				Wire: &wireprovisioner.Options{
					OIDC: &wireprovisioner.OIDCOptions{
						Provider: &wireprovisioner.Provider{
							IssuerURL:  srv.URL,
							JWKSURL:    srv.URL + "/keys",
							Algorithms: []string{"ES256"},
						},
						Config: &wireprovisioner.Config{
							ClientID:            "test",
							SignatureAlgorithms: []string{"ES256"},
							Now:                 time.Now,
						},
						TransformTemplate: "",
					},
					DPOP: &wireprovisioner.DPOPOptions{
						SigningKey: []byte(fakeKey),
					},
				},
			}))
			ctx = NewLinkerContext(ctx, NewLinker("ca.example.com", "acme"))
			return test{
				ch: &Challenge{
					ID:              "chID",
					AuthorizationID: "azID",
					AccountID:       "accID",
					Token:           "token",
					Type:            "wire-oidc-01",
					Status:          StatusPending,
					Value:           string(valueBytes),
				},
				srv:     srv,
				payload: payload,
				ctx:     ctx,
				jwk:     jwk,
				db: &MockWireDB{
					MockDB: MockDB{
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusValid, updch.Status)
							assert.Equal(t, ChallengeType("wire-oidc-01"), updch.Type)
							assert.Equal(t, string(valueBytes), updch.Value)
							return errors.New("fail")
						},
					},
				},
				expectedErr: &Error{
					Type:   "urn:ietf:params:acme:error:serverInternal",
					Detail: "The server experienced an internal error",
					Status: 500,
					Err:    errors.New(`error updating challenge: fail`),
				},
			}
		},
		"fail/db.GetAllOrdersByAccountID": func(t *testing.T) test {
			jwk, keyAuth := mustAccountAndKeyAuthorization(t, "token")
			signerJWK, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			require.NoError(t, err)
			signer, err := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.SignatureAlgorithm(signerJWK.Algorithm),
				Key:       signerJWK,
			}, new(jose.SignerOptions))
			require.NoError(t, err)
			srv := mustJWKServer(t, signerJWK.Public())
			tokenBytes, err := json.Marshal(struct {
				jose.Claims
				Name              string `json:"name,omitempty"`
				PreferredUsername string `json:"preferred_username,omitempty"`
				KeyAuth           string `json:"keyauth"`
				ACMEAudience      string `json:"acme_aud"`
			}{
				Claims: jose.Claims{
					Issuer:   srv.URL,
					Audience: []string{"test"},
					Expiry:   jose.NewNumericDate(time.Now().Add(1 * time.Minute)),
				},
				Name:              "Alice Smith",
				PreferredUsername: "wireapp://%40alice_wire@wire.com",
				KeyAuth:           keyAuth,
				ACMEAudience:      "https://ca.example.com/acme/wire/challenge/azID/chID",
			})
			require.NoError(t, err)
			signed, err := signer.Sign(tokenBytes)
			require.NoError(t, err)
			idToken, err := signed.CompactSerialize()
			require.NoError(t, err)
			payload, err := json.Marshal(struct {
				IDToken string `json:"id_token"`
			}{
				IDToken: idToken,
			})
			require.NoError(t, err)
			valueBytes, err := json.Marshal(struct {
				Name     string `json:"name,omitempty"`
				Domain   string `json:"domain,omitempty"`
				ClientID string `json:"client-id,omitempty"`
				Handle   string `json:"handle,omitempty"`
			}{
				Name:     "Alice Smith",
				Domain:   "wire.com",
				ClientID: "wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com",
				Handle:   "wireapp://%40alice_wire@wire.com",
			})
			require.NoError(t, err)
			ctx := NewProvisionerContext(context.Background(), newWireProvisionerWithOptions(t, &provisioner.Options{
				Wire: &wireprovisioner.Options{
					OIDC: &wireprovisioner.OIDCOptions{
						Provider: &wireprovisioner.Provider{
							IssuerURL:  srv.URL,
							JWKSURL:    srv.URL + "/keys",
							Algorithms: []string{"ES256"},
						},
						Config: &wireprovisioner.Config{
							ClientID:            "test",
							SignatureAlgorithms: []string{"ES256"},
							Now:                 time.Now,
						},
						TransformTemplate: "",
					},
					DPOP: &wireprovisioner.DPOPOptions{
						SigningKey: []byte(fakeKey),
					},
				},
			}))
			ctx = NewLinkerContext(ctx, NewLinker("ca.example.com", "acme"))
			return test{
				ch: &Challenge{
					ID:              "chID",
					AuthorizationID: "azID",
					AccountID:       "accID",
					Token:           "token",
					Type:            "wire-oidc-01",
					Status:          StatusPending,
					Value:           string(valueBytes),
				},
				srv:     srv,
				payload: payload,
				ctx:     ctx,
				jwk:     jwk,
				db: &MockWireDB{
					MockDB: MockDB{
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusValid, updch.Status)
							assert.Equal(t, ChallengeType("wire-oidc-01"), updch.Type)
							assert.Equal(t, string(valueBytes), updch.Value)
							return nil
						},
					},
					MockGetAllOrdersByAccountID: func(ctx context.Context, accountID string) ([]string, error) {
						assert.Equal(t, "accID", accountID)
						return nil, errors.New("fail")
					},
				},
				expectedErr: &Error{
					Type:   "urn:ietf:params:acme:error:serverInternal",
					Detail: "The server experienced an internal error",
					Status: 500,
					Err:    errors.New(`could not retrieve current order by account id: fail`),
				},
			}
		},
		"fail/db.GetAllOrdersByAccountID-zero": func(t *testing.T) test {
			jwk, keyAuth := mustAccountAndKeyAuthorization(t, "token")
			signerJWK, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			require.NoError(t, err)
			signer, err := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.SignatureAlgorithm(signerJWK.Algorithm),
				Key:       signerJWK,
			}, new(jose.SignerOptions))
			require.NoError(t, err)
			srv := mustJWKServer(t, signerJWK.Public())
			tokenBytes, err := json.Marshal(struct {
				jose.Claims
				Name              string `json:"name,omitempty"`
				PreferredUsername string `json:"preferred_username,omitempty"`
				KeyAuth           string `json:"keyauth"`
				ACMEAudience      string `json:"acme_aud"`
			}{
				Claims: jose.Claims{
					Issuer:   srv.URL,
					Audience: []string{"test"},
					Expiry:   jose.NewNumericDate(time.Now().Add(1 * time.Minute)),
				},
				Name:              "Alice Smith",
				PreferredUsername: "wireapp://%40alice_wire@wire.com",
				KeyAuth:           keyAuth,
				ACMEAudience:      "https://ca.example.com/acme/wire/challenge/azID/chID",
			})
			require.NoError(t, err)
			signed, err := signer.Sign(tokenBytes)
			require.NoError(t, err)
			idToken, err := signed.CompactSerialize()
			require.NoError(t, err)
			payload, err := json.Marshal(struct {
				IDToken string `json:"id_token"`
			}{
				IDToken: idToken,
			})
			require.NoError(t, err)
			valueBytes, err := json.Marshal(struct {
				Name     string `json:"name,omitempty"`
				Domain   string `json:"domain,omitempty"`
				ClientID string `json:"client-id,omitempty"`
				Handle   string `json:"handle,omitempty"`
			}{
				Name:     "Alice Smith",
				Domain:   "wire.com",
				ClientID: "wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com",
				Handle:   "wireapp://%40alice_wire@wire.com",
			})
			require.NoError(t, err)
			ctx := NewProvisionerContext(context.Background(), newWireProvisionerWithOptions(t, &provisioner.Options{
				Wire: &wireprovisioner.Options{
					OIDC: &wireprovisioner.OIDCOptions{
						Provider: &wireprovisioner.Provider{
							IssuerURL:  srv.URL,
							JWKSURL:    srv.URL + "/keys",
							Algorithms: []string{"ES256"},
						},
						Config: &wireprovisioner.Config{
							ClientID:            "test",
							SignatureAlgorithms: []string{"ES256"},
							Now:                 time.Now,
						},
						TransformTemplate: "",
					},
					DPOP: &wireprovisioner.DPOPOptions{
						SigningKey: []byte(fakeKey),
					},
				},
			}))
			ctx = NewLinkerContext(ctx, NewLinker("ca.example.com", "acme"))
			return test{
				ch: &Challenge{
					ID:              "chID",
					AuthorizationID: "azID",
					AccountID:       "accID",
					Token:           "token",
					Type:            "wire-oidc-01",
					Status:          StatusPending,
					Value:           string(valueBytes),
				},
				srv:     srv,
				payload: payload,
				ctx:     ctx,
				jwk:     jwk,
				db: &MockWireDB{
					MockDB: MockDB{
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusValid, updch.Status)
							assert.Equal(t, ChallengeType("wire-oidc-01"), updch.Type)
							assert.Equal(t, string(valueBytes), updch.Value)
							return nil
						},
					},
					MockGetAllOrdersByAccountID: func(ctx context.Context, accountID string) ([]string, error) {
						assert.Equal(t, "accID", accountID)
						return []string{}, nil
					},
				},
				expectedErr: &Error{
					Type:   "urn:ietf:params:acme:error:serverInternal",
					Detail: "The server experienced an internal error",
					Status: 500,
					Err:    errors.New(`there are not enough orders for this account for this custom OIDC challenge`),
				},
			}
		},
		"fail/db.CreateOidcToken": func(t *testing.T) test {
			jwk, keyAuth := mustAccountAndKeyAuthorization(t, "token")
			signerJWK, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			require.NoError(t, err)
			signer, err := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.SignatureAlgorithm(signerJWK.Algorithm),
				Key:       signerJWK,
			}, new(jose.SignerOptions))
			require.NoError(t, err)
			srv := mustJWKServer(t, signerJWK.Public())
			tokenBytes, err := json.Marshal(struct {
				jose.Claims
				Name              string `json:"name,omitempty"`
				PreferredUsername string `json:"preferred_username,omitempty"`
				KeyAuth           string `json:"keyauth"`
				ACMEAudience      string `json:"acme_aud"`
			}{
				Claims: jose.Claims{
					Issuer:   srv.URL,
					Audience: []string{"test"},
					Expiry:   jose.NewNumericDate(time.Now().Add(1 * time.Minute)),
				},
				Name:              "Alice Smith",
				PreferredUsername: "wireapp://%40alice_wire@wire.com",
				KeyAuth:           keyAuth,
				ACMEAudience:      "https://ca.example.com/acme/wire/challenge/azID/chID",
			})
			require.NoError(t, err)
			signed, err := signer.Sign(tokenBytes)
			require.NoError(t, err)
			idToken, err := signed.CompactSerialize()
			require.NoError(t, err)
			payload, err := json.Marshal(struct {
				IDToken string `json:"id_token"`
			}{
				IDToken: idToken,
			})
			require.NoError(t, err)
			valueBytes, err := json.Marshal(struct {
				Name     string `json:"name,omitempty"`
				Domain   string `json:"domain,omitempty"`
				ClientID string `json:"client-id,omitempty"`
				Handle   string `json:"handle,omitempty"`
			}{
				Name:     "Alice Smith",
				Domain:   "wire.com",
				ClientID: "wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com",
				Handle:   "wireapp://%40alice_wire@wire.com",
			})
			require.NoError(t, err)
			ctx := NewProvisionerContext(context.Background(), newWireProvisionerWithOptions(t, &provisioner.Options{
				Wire: &wireprovisioner.Options{
					OIDC: &wireprovisioner.OIDCOptions{
						Provider: &wireprovisioner.Provider{
							IssuerURL:  srv.URL,
							JWKSURL:    srv.URL + "/keys",
							Algorithms: []string{"ES256"},
						},
						Config: &wireprovisioner.Config{
							ClientID:            "test",
							SignatureAlgorithms: []string{"ES256"},
							Now:                 time.Now,
						},
						TransformTemplate: "",
					},
					DPOP: &wireprovisioner.DPOPOptions{
						SigningKey: []byte(fakeKey),
					},
				},
			}))
			ctx = NewLinkerContext(ctx, NewLinker("ca.example.com", "acme"))
			return test{
				ch: &Challenge{
					ID:              "chID",
					AuthorizationID: "azID",
					AccountID:       "accID",
					Token:           "token",
					Type:            "wire-oidc-01",
					Status:          StatusPending,
					Value:           string(valueBytes),
				},
				srv:     srv,
				payload: payload,
				ctx:     ctx,
				jwk:     jwk,
				db: &MockWireDB{
					MockDB: MockDB{
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusValid, updch.Status)
							assert.Equal(t, ChallengeType("wire-oidc-01"), updch.Type)
							assert.Equal(t, string(valueBytes), updch.Value)
							return nil
						},
					},
					MockGetAllOrdersByAccountID: func(ctx context.Context, accountID string) ([]string, error) {
						assert.Equal(t, "accID", accountID)
						return []string{"orderID"}, nil
					},
					MockCreateOidcToken: func(ctx context.Context, orderID string, idToken map[string]interface{}) error {
						assert.Equal(t, "orderID", orderID)
						assert.Equal(t, "Alice Smith", idToken["name"].(string))
						assert.Equal(t, "wireapp://%40alice_wire@wire.com", idToken["preferred_username"].(string))
						return errors.New("fail")
					},
				},
				expectedErr: &Error{
					Type:   "urn:ietf:params:acme:error:serverInternal",
					Detail: "The server experienced an internal error",
					Status: 500,
					Err:    errors.New(`failed storing OIDC id token: fail`),
				},
			}
		},
		"ok/wire-oidc-01": func(t *testing.T) test {
			jwk, keyAuth := mustAccountAndKeyAuthorization(t, "token")
			signerJWK, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			require.NoError(t, err)
			signer, err := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.SignatureAlgorithm(signerJWK.Algorithm),
				Key:       signerJWK,
			}, new(jose.SignerOptions))
			require.NoError(t, err)
			srv := mustJWKServer(t, signerJWK.Public())
			tokenBytes, err := json.Marshal(struct {
				jose.Claims
				Name              string `json:"name,omitempty"`
				PreferredUsername string `json:"preferred_username,omitempty"`
				KeyAuth           string `json:"keyauth"`
				ACMEAudience      string `json:"acme_aud"`
			}{
				Claims: jose.Claims{
					Issuer:   srv.URL,
					Audience: []string{"test"},
					Expiry:   jose.NewNumericDate(time.Now().Add(1 * time.Minute)),
				},
				Name:              "Alice Smith",
				PreferredUsername: "wireapp://%40alice_wire@wire.com",
				KeyAuth:           keyAuth,
				ACMEAudience:      "https://ca.example.com/acme/wire/challenge/azID/chID",
			})
			require.NoError(t, err)
			signed, err := signer.Sign(tokenBytes)
			require.NoError(t, err)
			idToken, err := signed.CompactSerialize()
			require.NoError(t, err)
			payload, err := json.Marshal(struct {
				IDToken string `json:"id_token"`
			}{
				IDToken: idToken,
			})
			require.NoError(t, err)
			valueBytes, err := json.Marshal(struct {
				Name     string `json:"name,omitempty"`
				Domain   string `json:"domain,omitempty"`
				ClientID string `json:"client-id,omitempty"`
				Handle   string `json:"handle,omitempty"`
			}{
				Name:     "Alice Smith",
				Domain:   "wire.com",
				ClientID: "wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com",
				Handle:   "wireapp://%40alice_wire@wire.com",
			})
			require.NoError(t, err)
			ctx := NewProvisionerContext(context.Background(), newWireProvisionerWithOptions(t, &provisioner.Options{
				Wire: &wireprovisioner.Options{
					OIDC: &wireprovisioner.OIDCOptions{
						Provider: &wireprovisioner.Provider{
							IssuerURL:  srv.URL,
							JWKSURL:    srv.URL + "/keys",
							Algorithms: []string{"ES256"},
						},
						Config: &wireprovisioner.Config{
							ClientID:            "test",
							SignatureAlgorithms: []string{"ES256"},
							Now:                 time.Now,
						},
						TransformTemplate: "",
					},
					DPOP: &wireprovisioner.DPOPOptions{
						SigningKey: []byte(fakeKey),
					},
				},
			}))
			ctx = NewLinkerContext(ctx, NewLinker("ca.example.com", "acme"))
			return test{
				ch: &Challenge{
					ID:              "chID",
					AuthorizationID: "azID",
					AccountID:       "accID",
					Token:           "token",
					Type:            "wire-oidc-01",
					Status:          StatusPending,
					Value:           string(valueBytes),
				},
				srv:     srv,
				payload: payload,
				ctx:     ctx,
				jwk:     jwk,
				db: &MockWireDB{
					MockDB: MockDB{
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusValid, updch.Status)
							assert.Equal(t, ChallengeType("wire-oidc-01"), updch.Type)
							assert.Equal(t, string(valueBytes), updch.Value)
							return nil
						},
					},
					MockGetAllOrdersByAccountID: func(ctx context.Context, accountID string) ([]string, error) {
						assert.Equal(t, "accID", accountID)
						return []string{"orderID"}, nil
					},
					MockCreateOidcToken: func(ctx context.Context, orderID string, idToken map[string]interface{}) error {
						assert.Equal(t, "orderID", orderID)
						assert.Equal(t, "Alice Smith", idToken["name"].(string))
						assert.Equal(t, "wireapp://%40alice_wire@wire.com", idToken["preferred_username"].(string))
						return nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if tc.srv != nil {
				defer tc.srv.Close()
			}
			err := wireOIDC01Validate(tc.ctx, tc.ch, tc.db, tc.jwk, tc.payload)
			if tc.expectedErr != nil {
				var k *Error
				if errors.As(err, &k) {
					assert.Equal(t, tc.expectedErr.Type, k.Type)
					assert.Equal(t, tc.expectedErr.Detail, k.Detail)
					assert.Equal(t, tc.expectedErr.Status, k.Status)
					assert.Equal(t, tc.expectedErr.Err.Error(), k.Err.Error())
				} else {
					assert.Fail(t, "unexpected error type")
				}
				return
			}

			assert.NoError(t, err)
		})
	}
}

func Test_parseAndVerifyWireAccessToken(t *testing.T) {
	t.Skip("skip until we can retrieve public key from e2e test, so that we can actually verify the token")
	key := `
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAB2IYqBWXAouDt3WcCZgCM3t9gumMEKMlgMsGenSu+fA=
-----END PUBLIC KEY-----`
	publicKey, err := pemutil.Parse([]byte(key))
	require.NoError(t, err)
	pk, ok := publicKey.(ed25519.PublicKey)
	require.True(t, ok)

	issuer := "http://wire.com:19983/clients/7a41cf5b79683410/access-token"
	wireID := wire.DeviceID{
		ClientID: "wireapp://guVX5xeFS3eTatmXBIyA4A!7a41cf5b79683410@wire.com",
		Handle:   "wireapp://%40alice_wire@wire.com",
	}

	token := `eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Im8zcWZhQ045a2FzSnZJRlhPdFNMTGhlYW0wTE5jcVF5MHdBMk9PeFRRNW8ifX0.eyJpYXQiOjE3MDU0OTc3MzksImV4cCI6MTcwNTUwMTY5OSwibmJmIjoxNzA1NDk3NzM5LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MTY4MjQvY2xpZW50cy8zN2ZlOThiZDQwZDBkZmUvYWNjZXNzLXRva2VuIiwic3ViIjoid2lyZWFwcDovLzE4NXdIUmtRVHdTOTVGODhaZTQ1SlEhMzdmZTk4YmQ0MGQwZGZlQHdpcmUuY29tIiwiYXVkIjoiaHR0cHM6Ly9zdGVwY2E6NTUwMjMvYWNtZS93aXJlL2NoYWxsZW5nZS9SeEdSWGVoRGxCcHcxNTJQTVUzem0xY2M0cEtGcHVWRi9RWnRFazdQNUVFRXhadHBSYngydjVoYlc3QXB1S2NOSSIsImp0aSI6ImU1MzllODYzLTRkNTgtNGMwMS1iYjk3LTYwODdiNTEzOWIyMCIsIm5vbmNlIjoiUzJKYWVWcExkV28wUkZKaFFrWndXR0ZKY0VoVlFrNUxXVGd4WkhkRFVqQSIsImNoYWwiOiIyaDFPdUdxbTBKUXd6bHVsWGtLSTJEMGZiRDgzRUIxdyIsImNuZiI6eyJraWQiOiJhSEY3MVhYeG0tTWE5Q05zSjNaU1RKTjlYS0ZxOFFmOGh2UTJLN3NLQmQ4In0sInByb29mIjoiZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pWVVsaVMwcFBha0poWXpZeVF6TnRhVmhHVjAxb09ITTJkRXQzUkROaGNHRnVSMHBQZURaVVFYVklRU0o5ZlEuZXlKcFlYUWlPakUzTURVME9UYzNNemtzSW1WNGNDSTZNVGN3TlRVd05Ea3pPU3dpYm1KbUlqb3hOekExTkRrM056TTVMQ0p6ZFdJaU9pSjNhWEpsWVhCd09pOHZNVGcxZDBoU2ExRlVkMU01TlVZNE9GcGxORFZLVVNFek4yWmxPVGhpWkRRd1pEQmtabVZBZDJseVpTNWpiMjBpTENKaGRXUWlPaUpvZEhSd2N6b3ZMM04wWlhCallUbzFOVEF5TXk5aFkyMWxMM2RwY21VdlkyaGhiR3hsYm1kbEwxSjRSMUpZWldoRWJFSndkekUxTWxCTlZUTjZiVEZqWXpSd1MwWndkVlpHTDFGYWRFVnJOMUExUlVWRmVGcDBjRkppZURKMk5XaGlWemRCY0hWTFkwNUpJaXdpYW5ScElqb2lNV1kxTUdRM1lUQXRaamt6WmkwME5XWXdMV0V3TWpBdE1ETm1NREJpTlRreVlUUmtJaXdpYm05dVkyVWlPaUpUTWtwaFpWWndUR1JYYnpCU1JrcG9VV3RhZDFkSFJrcGpSV2hXVVdzMVRGZFVaM2hhU0dSRVZXcEJJaXdpYUhSdElqb2lVRTlUVkNJc0ltaDBkU0k2SW1oMGRIQTZMeTkzYVhKbExtTnZiVG94TmpneU5DOWpiR2xsYm5Sekx6TTNabVU1T0dKa05EQmtNR1JtWlM5aFkyTmxjM010ZEc5clpXNGlMQ0pqYUdGc0lqb2lNbWd4VDNWSGNXMHdTbEYzZW14MWJGaHJTMGt5UkRCbVlrUTRNMFZDTVhjaUxDSm9ZVzVrYkdVaU9pSjNhWEpsWVhCd09pOHZKVFF3WVd4cFkyVmZkMmx5WlVCM2FYSmxMbU52YlNJc0luUmxZVzBpT2lKM2FYSmxJbjAuZlNmQnFuWWlfMTRhZEc5MDAyZ0RJdEgybXNyYW55eXVnR0g5bHpFcmprdmRGbkRPOFRVWWRYUXJKUzdlX3BlU0lzcGxlRUVkaGhzc0gwM3FBWHY2QXciLCJjbGllbnRfaWQiOiJ3aXJlYXBwOi8vMTg1d0hSa1FUd1M5NUY4OFplNDVKUSEzN2ZlOThiZDQwZDBkZmVAd2lyZS5jb20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.GKK7ZsJ8EWJjeaHqf8P48H9mluJhxyXUmI0FO3xstda3XDJIK7Z5Ur4hi1OIJB0ZsS5BqRVT2q5whL4KP9hZCA`
	ch := &Challenge{
		Token: "bXUGNpUfcRx3EhB34xP3y62aQZoGZS6j",
	}

	issuedAtUnix, err := strconv.ParseInt("1704985205", 10, 64)
	require.NoError(t, err)
	issuedAt := time.Unix(issuedAtUnix, 0)

	jwkBytes := []byte(`{"crv": "Ed25519", "kty": "OKP", "x": "1L1eH2a6AgVvzTp5ZalKRfq6pVPOtEjI7h8TPzBYFgM"}`)
	var accountJWK jose.JSONWebKey
	json.Unmarshal(jwkBytes, &accountJWK)

	rawKid, err := accountJWK.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	accountJWK.KeyID = base64.RawURLEncoding.EncodeToString(rawKid)

	at, dpop, err := parseAndVerifyWireAccessToken(wireVerifyParams{
		token:     token,
		tokenKey:  pk,
		dpopKey:   accountJWK.Public(),
		dpopKeyID: accountJWK.KeyID,
		issuer:    issuer,
		wireID:    wireID,
		chToken:   ch.Token,
		t:         issuedAt.Add(1 * time.Minute), // set validation time to be one minute after issuance
	})

	if assert.NoError(t, err) {
		// token assertions
		assert.Equal(t, "42c46d4c-e510-4175-9fb5-d055e125a49d", at.ID)
		assert.Equal(t, "http://wire.com:19983/clients/7a41cf5b79683410/access-token", at.Issuer)
		assert.Equal(t, "wireapp://guVX5xeFS3eTatmXBIyA4A!7a41cf5b79683410@wire.com", at.Subject)
		assert.Contains(t, at.Audience, "http://wire.com:19983/clients/7a41cf5b79683410/access-token")
		assert.Equal(t, "bXUGNpUfcRx3EhB34xP3y62aQZoGZS6j", at.Challenge)
		assert.Equal(t, "wireapp://guVX5xeFS3eTatmXBIyA4A!7a41cf5b79683410@wire.com", at.ClientID)
		assert.Equal(t, 5, at.APIVersion)
		assert.Equal(t, "wire_client_id", at.Scope)
		if assert.NotNil(t, at.Cnf) {
			assert.Equal(t, "oMWfNDJQsI5cPlXN5UoBNncKtc4f2dq2vwCjjXsqw7Q", at.Cnf.Kid)
		}

		// dpop proof assertions
		dt := *dpop
		assert.Equal(t, "bXUGNpUfcRx3EhB34xP3y62aQZoGZS6j", dt["chal"].(string))
		assert.Equal(t, "wireapp://%40alice_wire@wire.com", dt["handle"].(string))
		assert.Equal(t, "POST", dt["htm"].(string))
		assert.Equal(t, "http://wire.com:19983/clients/7a41cf5b79683410/access-token", dt["htu"].(string))
		assert.Equal(t, "5e6684cb-6b48-468d-b091-ff04bed6ec2e", dt["jti"].(string))
		assert.Equal(t, "UEJyR2dqOEhzZFJEYWJBaTkyODNEYTE2aEs0dHIxcEc", dt["nonce"].(string))
		assert.Equal(t, "wireapp://guVX5xeFS3eTatmXBIyA4A!7a41cf5b79683410@wire.com", dt["sub"].(string))
		assert.Equal(t, "wire", dt["team"].(string))
	}
}

func Test_validateWireOIDCClaims(t *testing.T) {
	fakeKey := `
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA5c+4NKZSNQcR1T8qN6SjwgdPZQ0Ge12Ylx/YeGAJ35k=
-----END PUBLIC KEY-----`
	opts := &wireprovisioner.Options{
		OIDC: &wireprovisioner.OIDCOptions{
			Provider: &wireprovisioner.Provider{
				IssuerURL:  "http://dex:15818/dex",
				Algorithms: []string{"ES256"},
			},
			Config: &wireprovisioner.Config{
				ClientID:            "wireapp",
				SignatureAlgorithms: []string{"RS256"},
				Now: func() time.Time {
					return time.Date(2024, 1, 12, 18, 32, 41, 0, time.UTC) // (Token Expiry: 2024-01-12 21:32:42 +0100 CET)
				},
				InsecureSkipSignatureCheck: true, // skipping signature check for this specific test
			},
			TransformTemplate: `{"name": "{{ .preferred_username }}", "preferred_username": "{{ .name }}"}`,
		},
		DPOP: &wireprovisioner.DPOPOptions{
			SigningKey: []byte(fakeKey),
		},
	}

	err := opts.Validate()
	require.NoError(t, err)

	idTokenString := `eyJhbGciOiJSUzI1NiIsImtpZCI6IjZhNDZlYzQ3YTQzYWI1ZTc4NzU3MzM5NWY1MGY4ZGQ5MWI2OTM5MzcifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE1ODE4L2RleCIsInN1YiI6IkNqcDNhWEpsWVhCd09pOHZTMmh0VjBOTFpFTlRXakoyT1dWTWFHRk9XVlp6WnlFeU5UZzFNVEpoT0RRek5qTXhaV1V6UUhkcGNtVXVZMjl0RWdSc1pHRnciLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNzA1MDkxNTYyLCJpYXQiOjE3MDUwMDUxNjIsIm5vbmNlIjoib0VjUzBRQUNXLVIyZWkxS09wUmZ2QSIsImF0X2hhc2giOiJoYzk0NmFwS25FeEV5TDVlSzJZMzdRIiwiY19oYXNoIjoidmRubFp2V1d1bVd1Z2NYR1JpOU5FUSIsIm5hbWUiOiJ3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.aEBhWJugBJ9J_0L_4odUCg8SR8HMXVjd__X8uZRo42BSJQQO7-wdpy0jU3S4FOX9fQKr68wD61gS_QsnhfiT7w9U36mLpxaYlNVDCYfpa-gklVFit_0mjUOukXajTLK6H527TGiSss8z22utc40ckS1SbZa2BzKu3yOcqnFHUQwQc5sLYfpRABTB6WBoYFtnWDzdpyWJDaOzz7lfKYv2JBnf9vV8u8SYm-6gNKgtiQ3UUnjhIVUjdfHet2BMvmV2ooZ8V441RULCzKKG_sWZba-D_k_TOnSholGobtUOcKHlmVlmfUe8v7kuyBdhbPcembfgViaNldLQGKZjZfgvLg`
	ctx := context.Background()
	o := opts.GetOIDCOptions()
	verifier, err := o.GetVerifier(ctx)
	require.NoError(t, err)
	idToken, err := verifier.Verify(ctx, idTokenString)
	require.NoError(t, err)

	wireID := wire.UserID{
		Name:   "Alice Smith",
		Handle: "wireapp://%40alice_wire@wire.com",
	}

	got, err := validateWireOIDCClaims(o, idToken, wireID)
	assert.NoError(t, err)

	assert.Equal(t, "wireapp://%40alice_wire@wire.com", got["preferred_username"].(string))
	assert.Equal(t, "Alice Smith", got["name"].(string))
	assert.Equal(t, "http://dex:15818/dex", got["iss"].(string))
}

func createWireOptions(t *testing.T, transformTemplate string) *wireprovisioner.Options {
	t.Helper()
	fakeKey := `
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA5c+4NKZSNQcR1T8qN6SjwgdPZQ0Ge12Ylx/YeGAJ35k=
-----END PUBLIC KEY-----`
	opts := &wireprovisioner.Options{
		OIDC: &wireprovisioner.OIDCOptions{
			Provider: &wireprovisioner.Provider{
				IssuerURL:  "https://issuer.example.com",
				Algorithms: []string{"ES256"},
			},
			Config: &wireprovisioner.Config{
				ClientID:            "unit test",
				SignatureAlgorithms: []string{"ES256"},
				Now:                 time.Now,
			},
			TransformTemplate: transformTemplate,
		},
		DPOP: &wireprovisioner.DPOPOptions{
			SigningKey: []byte(fakeKey),
		},
	}

	err := opts.Validate()
	require.NoError(t, err)

	return opts
}

func Test_idTokenTransformation(t *testing.T) {
	// {"name": "wireapp://%40alice_wire@wire.com", "preferred_username": "Alice Smith", "iss": "http://dex:15818/dex", ...}
	idTokenString := `eyJhbGciOiJSUzI1NiIsImtpZCI6IjZhNDZlYzQ3YTQzYWI1ZTc4NzU3MzM5NWY1MGY4ZGQ5MWI2OTM5MzcifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE1ODE4L2RleCIsInN1YiI6IkNqcDNhWEpsWVhCd09pOHZTMmh0VjBOTFpFTlRXakoyT1dWTWFHRk9XVlp6WnlFeU5UZzFNVEpoT0RRek5qTXhaV1V6UUhkcGNtVXVZMjl0RWdSc1pHRnciLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNzA1MDkxNTYyLCJpYXQiOjE3MDUwMDUxNjIsIm5vbmNlIjoib0VjUzBRQUNXLVIyZWkxS09wUmZ2QSIsImF0X2hhc2giOiJoYzk0NmFwS25FeEV5TDVlSzJZMzdRIiwiY19oYXNoIjoidmRubFp2V1d1bVd1Z2NYR1JpOU5FUSIsIm5hbWUiOiJ3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.aEBhWJugBJ9J_0L_4odUCg8SR8HMXVjd__X8uZRo42BSJQQO7-wdpy0jU3S4FOX9fQKr68wD61gS_QsnhfiT7w9U36mLpxaYlNVDCYfpa-gklVFit_0mjUOukXajTLK6H527TGiSss8z22utc40ckS1SbZa2BzKu3yOcqnFHUQwQc5sLYfpRABTB6WBoYFtnWDzdpyWJDaOzz7lfKYv2JBnf9vV8u8SYm-6gNKgtiQ3UUnjhIVUjdfHet2BMvmV2ooZ8V441RULCzKKG_sWZba-D_k_TOnSholGobtUOcKHlmVlmfUe8v7kuyBdhbPcembfgViaNldLQGKZjZfgvLg`
	var claims struct {
		Name   string `json:"name,omitempty"`
		Handle string `json:"preferred_username,omitempty"`
		Issuer string `json:"iss,omitempty"`
	}

	idToken, err := jose.ParseSigned(idTokenString)
	require.NoError(t, err)
	err = idToken.UnsafeClaimsWithoutVerification(&claims)
	require.NoError(t, err)

	// original token contains "Alice Smith" as handle, and name as "wireapp://%40alice_wire@wire.com"
	assert.Equal(t, "Alice Smith", claims.Handle)
	assert.Equal(t, "wireapp://%40alice_wire@wire.com", claims.Name)
	assert.Equal(t, "http://dex:15818/dex", claims.Issuer)

	var m map[string]any
	err = idToken.UnsafeClaimsWithoutVerification(&m)
	require.NoError(t, err)

	opts := createWireOptions(t, "") // uses default transformation template
	result, err := opts.GetOIDCOptions().Transform(m)
	require.NoError(t, err)

	// default transformation sets preferred username to handle; name as name
	assert.Equal(t, "Alice Smith", result["preferred_username"].(string))
	assert.Equal(t, "wireapp://%40alice_wire@wire.com", result["name"].(string))
	assert.Equal(t, "http://dex:15818/dex", result["iss"].(string))

	// swap the preferred_name and the name
	swap := `{"name": "{{ .preferred_username }}", "preferred_username": "{{ .name }}"}`
	opts = createWireOptions(t, swap)
	result, err = opts.GetOIDCOptions().Transform(m)
	require.NoError(t, err)

	// with the transformation, handle now contains wireapp://%40alice_wire@wire.com, name contains Alice Smith
	assert.Equal(t, "wireapp://%40alice_wire@wire.com", result["preferred_username"].(string))
	assert.Equal(t, "Alice Smith", result["name"].(string))
	assert.Equal(t, "http://dex:15818/dex", result["iss"].(string))
}
