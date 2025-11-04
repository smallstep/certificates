//go:build tpmsimulator

package acme

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smallstep/go-attestation/attest"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/minica"
	"go.step.sm/crypto/tpm"
	"go.step.sm/crypto/tpm/simulator"
	tpmstorage "go.step.sm/crypto/tpm/storage"
	"go.step.sm/crypto/x509util"
)

func newSimulatedTPM(t *testing.T) *tpm.TPM {
	t.Helper()
	tmpDir := t.TempDir()
	tpm, err := tpm.New(withSimulator(t), tpm.WithStore(tpmstorage.NewDirstore(tmpDir))) // TODO: provide in-memory storage implementation instead
	require.NoError(t, err)
	return tpm
}

func withSimulator(t *testing.T) tpm.NewTPMOption {
	t.Helper()
	var sim simulator.Simulator
	t.Cleanup(func() {
		if sim == nil {
			return
		}
		err := sim.Close()
		require.NoError(t, err)
	})
	sim, err := simulator.New()
	require.NoError(t, err)
	err = sim.Open()
	require.NoError(t, err)
	return tpm.WithSimulator(sim)
}

func generateKeyID(t *testing.T, pub crypto.PublicKey) []byte {
	t.Helper()
	b, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	hash := sha256.Sum256(b)
	return hash[:]
}

func mustAttestTPM(t *testing.T, keyAuthorization string, permanentIdentifiers []string) ([]byte, crypto.Signer, *x509.Certificate) {
	t.Helper()
	aca, err := minica.New(
		minica.WithName("TPM Testing"),
		minica.WithGetSignerFunc(
			func() (crypto.Signer, error) {
				return keyutil.GenerateSigner("RSA", "", 2048)
			},
		),
	)
	require.NoError(t, err)

	// prepare simulated TPM and create an AK
	stpm := newSimulatedTPM(t)
	eks, err := stpm.GetEKs(context.Background())
	require.NoError(t, err)
	ak, err := stpm.CreateAK(context.Background(), "first-ak")
	require.NoError(t, err)
	require.NotNil(t, ak)

	// extract the AK public key // TODO(hs): replace this when there's a simpler method to get the AK public key (e.g. ak.Public())
	ap, err := ak.AttestationParameters(context.Background())
	require.NoError(t, err)
	akp, err := attest.ParseAKPublic(attest.TPMVersion20, ap.Public)
	require.NoError(t, err)

	// create template and sign certificate for the AK public key
	keyID := generateKeyID(t, eks[0].Public())
	template := &x509.Certificate{
		PublicKey:          akp.Public,
		IsCA:               false,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{oidTCGKpAIKCertificate},
	}
	sans := []x509util.SubjectAlternativeName{}
	uris := []*url.URL{{Scheme: "urn", Opaque: "ek:sha256:" + base64.StdEncoding.EncodeToString(keyID)}}
	for _, pi := range permanentIdentifiers {
		sans = append(sans, x509util.SubjectAlternativeName{
			Type:  x509util.PermanentIdentifierType,
			Value: pi,
		})
	}
	asn1Value := []byte(fmt.Sprintf(`{"extraNames":[{"type": %q, "value": %q},{"type": %q, "value": %q},{"type": %q, "value": %q}]}`, oidTPMManufacturer, "1414747215", oidTPMModel, "SLB 9670 TPM2.0", oidTPMVersion, "7.55"))
	sans = append(sans, x509util.SubjectAlternativeName{
		Type:      x509util.DirectoryNameType,
		ASN1Value: asn1Value,
	})
	ext, err := createSubjectAltNameExtension(nil, nil, nil, uris, sans, true)
	require.NoError(t, err)
	ext.Set(template)
	akCert, err := aca.Sign(template)
	require.NoError(t, err)
	require.NotNil(t, akCert)

	// create a new key attested by the AK, while including
	// the key authorization bytes as qualifying data.
	keyAuthSum := sha256.Sum256([]byte(keyAuthorization))
	config := tpm.AttestKeyConfig{
		Algorithm:      "RSA",
		Size:           2048,
		QualifyingData: keyAuthSum[:],
	}
	key, err := stpm.AttestKey(context.Background(), "first-ak", "first-key", config)
	require.NoError(t, err)
	require.NotNil(t, key)
	require.Equal(t, "first-key", key.Name())
	require.NotEqual(t, 0, len(key.Data()))
	require.Equal(t, "first-ak", key.AttestedBy())
	require.True(t, key.WasAttested())
	require.True(t, key.WasAttestedBy(ak))

	signer, err := key.Signer(context.Background())
	require.NoError(t, err)

	// prepare the attestation object with the AK certificate chain,
	// the attested key, its metadata and the signature signed by the
	// AK.
	params, err := key.CertificationParameters(context.Background())
	require.NoError(t, err)
	attObj, err := cbor.Marshal(struct {
		Format       string                 `json:"fmt"`
		AttStatement map[string]interface{} `json:"attStmt,omitempty"`
	}{
		Format: "tpm",
		AttStatement: map[string]interface{}{
			"ver":      "2.0",
			"x5c":      []interface{}{akCert.Raw, aca.Intermediate.Raw},
			"alg":      int64(-257), // RS256
			"sig":      params.CreateSignature,
			"certInfo": params.CreateAttestation,
			"pubArea":  params.Public,
		},
	})
	require.NoError(t, err)

	// marshal the ACME payload
	payload, err := json.Marshal(struct {
		AttObj string `json:"attObj"`
	}{
		AttObj: base64.RawURLEncoding.EncodeToString(attObj),
	})
	require.NoError(t, err)

	return payload, signer, aca.Root
}

func Test_deviceAttest01ValidateWithTPMSimulator(t *testing.T) {
	type args struct {
		ctx     context.Context
		ch      *Challenge
		db      DB
		jwk     *jose.JSONWebKey
		payload []byte
	}
	type test struct {
		args    args
		wantErr *Error
	}
	tests := map[string]func(t *testing.T) test{
		"ok/doTPMAttestationFormat-storeError": func(t *testing.T) test {
			jwk, keyAuth := mustAccountAndKeyAuthorization(t, "token")
			payload, _, root := mustAttestTPM(t, keyAuth, nil) // TODO: value(s) for AK cert?
			caRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})
			ctx := NewProvisionerContext(context.Background(), mustAttestationProvisioner(t, caRoot))

			// parse payload, set invalid "ver", remarshal
			var p payloadType
			err := json.Unmarshal(payload, &p)
			require.NoError(t, err)
			attObj, err := base64.RawURLEncoding.DecodeString(p.AttObj)
			require.NoError(t, err)
			att := attestationObject{}
			err = cbor.Unmarshal(attObj, &att)
			require.NoError(t, err)
			att.AttStatement["ver"] = "bogus"
			attObj, err = cbor.Marshal(struct {
				Format       string                 `json:"fmt"`
				AttStatement map[string]interface{} `json:"attStmt,omitempty"`
			}{
				Format:       "tpm",
				AttStatement: att.AttStatement,
			})
			require.NoError(t, err)
			payload, err = json.Marshal(struct {
				AttObj string `json:"attObj"`
			}{
				AttObj: base64.RawURLEncoding.EncodeToString(attObj),
			})
			require.NoError(t, err)
			return test{
				args: args{
					ctx: ctx,
					jwk: jwk,
					ch: &Challenge{
						ID:              "chID",
						AuthorizationID: "azID",
						Token:           "token",
						Type:            "device-attest-01",
						Status:          StatusPending,
						Value:           "device.id.12345678",
					},
					payload: payload,
					db: &MockDB{
						MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
							assert.Equal(t, "azID", id)
							return &Authorization{ID: "azID"}, nil
						},
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusInvalid, updch.Status)
							assert.Equal(t, ChallengeType("device-attest-01"), updch.Type)
							assert.Equal(t, "device.id.12345678", updch.Value)

							err := NewDetailedError(ErrorBadAttestationStatementType, `version "bogus" is not supported`)

							assert.EqualError(t, updch.Error.Err, err.Err.Error())
							assert.Equal(t, err.Type, updch.Error.Type)
							assert.Equal(t, err.Detail, updch.Error.Detail)
							assert.Equal(t, err.Status, updch.Error.Status)
							assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

							return nil
						},
					},
				},
				wantErr: nil,
			}
		},
		"ok with invalid PermanentIdentifier SAN": func(t *testing.T) test {
			jwk, keyAuth := mustAccountAndKeyAuthorization(t, "token")
			payload, _, root := mustAttestTPM(t, keyAuth, []string{"device.id.12345678"}) // TODO: value(s) for AK cert?
			caRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})
			ctx := NewProvisionerContext(context.Background(), mustAttestationProvisioner(t, caRoot))
			return test{
				args: args{
					ctx: ctx,
					jwk: jwk,
					ch: &Challenge{
						ID:              "chID",
						AuthorizationID: "azID",
						Token:           "token",
						Type:            "device-attest-01",
						Status:          StatusPending,
						Value:           "device.id.99999999",
					},
					payload: payload,
					db: &MockDB{
						MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
							assert.Equal(t, "azID", id)
							return &Authorization{ID: "azID"}, nil
						},
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusInvalid, updch.Status)
							assert.Equal(t, ChallengeType("device-attest-01"), updch.Type)
							assert.Equal(t, "device.id.99999999", updch.Value)

							err := NewDetailedError(ErrorBadAttestationStatementType, `permanent identifier does not match`).
								AddSubproblems(NewSubproblemWithIdentifier(
									ErrorRejectedIdentifierType,
									Identifier{Type: "permanent-identifier", Value: "device.id.99999999"},
									`challenge identifier "device.id.99999999" doesn't match any of the attested hardware identifiers ["device.id.12345678"]`,
								))

							assert.EqualError(t, updch.Error.Err, err.Err.Error())
							assert.Equal(t, err.Type, updch.Error.Type)
							assert.Equal(t, err.Detail, updch.Error.Detail)
							assert.Equal(t, err.Status, updch.Error.Status)
							assert.Equal(t, err.Subproblems, updch.Error.Subproblems)

							return nil
						},
					},
				},
				wantErr: nil,
			}
		},
		"ok": func(t *testing.T) test {
			jwk, keyAuth := mustAccountAndKeyAuthorization(t, "token")
			payload, signer, root := mustAttestTPM(t, keyAuth, nil) // TODO: value(s) for AK cert?
			caRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})
			ctx := NewProvisionerContext(context.Background(), mustAttestationProvisioner(t, caRoot))
			return test{
				args: args{
					ctx: ctx,
					jwk: jwk,
					ch: &Challenge{
						ID:              "chID",
						AuthorizationID: "azID",
						Token:           "token",
						Type:            "device-attest-01",
						Status:          StatusPending,
						Value:           "device.id.12345678",
					},
					payload: payload,
					db: &MockDB{
						MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
							assert.Equal(t, "azID", id)
							return &Authorization{ID: "azID"}, nil
						},
						MockUpdateAuthorization: func(ctx context.Context, az *Authorization) error {
							fingerprint, err := keyutil.Fingerprint(signer.Public())
							assert.NoError(t, err)
							assert.Equal(t, "azID", az.ID)
							assert.Equal(t, fingerprint, az.Fingerprint)
							return nil
						},
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusValid, updch.Status)
							assert.Equal(t, ChallengeType("device-attest-01"), updch.Type)
							assert.Equal(t, "device.id.12345678", updch.Value)
							return nil
						},
					},
				},
				wantErr: nil,
			}
		},
		"ok with PermanentIdentifier SAN": func(t *testing.T) test {
			jwk, keyAuth := mustAccountAndKeyAuthorization(t, "token")
			payload, signer, root := mustAttestTPM(t, keyAuth, []string{"device.id.12345678"}) // TODO: value(s) for AK cert?
			caRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})
			ctx := NewProvisionerContext(context.Background(), mustAttestationProvisioner(t, caRoot))
			return test{
				args: args{
					ctx: ctx,
					jwk: jwk,
					ch: &Challenge{
						ID:              "chID",
						AuthorizationID: "azID",
						Token:           "token",
						Type:            "device-attest-01",
						Status:          StatusPending,
						Value:           "device.id.12345678",
					},
					payload: payload,
					db: &MockDB{
						MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
							assert.Equal(t, "azID", id)
							return &Authorization{ID: "azID"}, nil
						},
						MockUpdateAuthorization: func(ctx context.Context, az *Authorization) error {
							fingerprint, err := keyutil.Fingerprint(signer.Public())
							assert.NoError(t, err)
							assert.Equal(t, "azID", az.ID)
							assert.Equal(t, fingerprint, az.Fingerprint)
							return nil
						},
						MockUpdateChallenge: func(ctx context.Context, updch *Challenge) error {
							assert.Equal(t, "chID", updch.ID)
							assert.Equal(t, "token", updch.Token)
							assert.Equal(t, StatusValid, updch.Status)
							assert.Equal(t, ChallengeType("device-attest-01"), updch.Type)
							assert.Equal(t, "device.id.12345678", updch.Value)
							return nil
						},
					},
				},
				wantErr: nil,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)

			if err := deviceAttest01Validate(tc.args.ctx, tc.args.ch, tc.args.db, tc.args.jwk, tc.args.payload); err != nil {
				assert.Error(t, tc.wantErr)
				assert.EqualError(t, err, tc.wantErr.Error())
				return
			}

			assert.Nil(t, tc.wantErr)
		})
	}
}

func newBadAttestationStatementError(msg string) *Error {
	return &Error{
		Type:   "urn:ietf:params:acme:error:badAttestationStatement",
		Status: 400,
		Err:    errors.New(msg),
	}
}

func newInternalServerError(msg string) *Error {
	return &Error{
		Type:   "urn:ietf:params:acme:error:serverInternal",
		Status: 500,
		Err:    errors.New(msg),
	}
}

var (
	oidPermanentIdentifier          = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 3}
	oidHardwareModuleNameIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 4}
)

func Test_doTPMAttestationFormat(t *testing.T) {
	ctx := context.Background()
	aca, err := minica.New(
		minica.WithName("TPM Testing"),
		minica.WithGetSignerFunc(
			func() (crypto.Signer, error) {
				return keyutil.GenerateSigner("RSA", "", 2048)
			},
		),
	)
	require.NoError(t, err)
	acaRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: aca.Root.Raw})

	// prepare simulated TPM and create an AK
	stpm := newSimulatedTPM(t)
	eks, err := stpm.GetEKs(context.Background())
	require.NoError(t, err)
	ak, err := stpm.CreateAK(context.Background(), "first-ak")
	require.NoError(t, err)
	require.NotNil(t, ak)

	// extract the AK public key // TODO(hs): replace this when there's a simpler method to get the AK public key (e.g. ak.Public())
	ap, err := ak.AttestationParameters(context.Background())
	require.NoError(t, err)
	akp, err := attest.ParseAKPublic(attest.TPMVersion20, ap.Public)
	require.NoError(t, err)

	// create template and sign certificate for the AK public key
	keyID := generateKeyID(t, eks[0].Public())
	template := &x509.Certificate{
		PublicKey:          akp.Public,
		IsCA:               false,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{oidTCGKpAIKCertificate},
	}
	sans := []x509util.SubjectAlternativeName{}
	uris := []*url.URL{{Scheme: "urn", Opaque: "ek:sha256:" + base64.StdEncoding.EncodeToString(keyID)}}
	asn1Value := []byte(fmt.Sprintf(`{"extraNames":[{"type": %q, "value": %q},{"type": %q, "value": %q},{"type": %q, "value": %q}]}`, oidTPMManufacturer, "1414747215", oidTPMModel, "SLB 9670 TPM2.0", oidTPMVersion, "7.55"))
	sans = append(sans, x509util.SubjectAlternativeName{
		Type:      x509util.DirectoryNameType,
		ASN1Value: asn1Value,
	})
	ext, err := createSubjectAltNameExtension(nil, nil, nil, uris, sans, true)
	require.NoError(t, err)
	ext.Set(template)
	akCert, err := aca.Sign(template)
	require.NoError(t, err)
	require.NotNil(t, akCert)

	invalidTemplate := &x509.Certificate{
		PublicKey:          akp.Public,
		IsCA:               false,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{oidTCGKpAIKCertificate},
	}
	invalidAKCert, err := aca.Sign(invalidTemplate)
	require.NoError(t, err)
	require.NotNil(t, invalidAKCert)

	// generate a JWK and the key authorization value
	jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
	require.NoError(t, err)
	keyAuthorization, err := KeyAuthorization("token", jwk)
	require.NoError(t, err)

	// create a new key attested by the AK, while including
	// the key authorization bytes as qualifying data.
	keyAuthSum := sha256.Sum256([]byte(keyAuthorization))
	config := tpm.AttestKeyConfig{
		Algorithm:      "RSA",
		Size:           2048,
		QualifyingData: keyAuthSum[:],
	}
	key, err := stpm.AttestKey(context.Background(), "first-ak", "first-key", config)
	require.NoError(t, err)
	require.NotNil(t, key)
	params, err := key.CertificationParameters(context.Background())
	require.NoError(t, err)

	signer, err := key.Signer(context.Background())
	require.NoError(t, err)
	fingerprint, err := keyutil.Fingerprint(signer.Public())
	require.NoError(t, err)

	// attest another key and get its certification parameters
	anotherKey, err := stpm.AttestKey(context.Background(), "first-ak", "another-key", config)
	require.NoError(t, err)
	require.NotNil(t, key)
	anotherKeyParams, err := anotherKey.CertificationParameters(context.Background())
	require.NoError(t, err)

	type args struct {
		ctx  context.Context
		prov Provisioner
		ch   *Challenge
		jwk  *jose.JSONWebKey
		att  *attestationObject
	}
	tests := []struct {
		name   string
		args   args
		want   *tpmAttestationData
		expErr *Error
	}{
		{"ok", args{ctx, mustAttestationProvisioner(t, acaRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "tpm",
			AttStatement: map[string]interface{}{
				"ver":      "2.0",
				"x5c":      []interface{}{akCert.Raw, aca.Intermediate.Raw},
				"alg":      int64(-257), // RS256
				"sig":      params.CreateSignature,
				"certInfo": params.CreateAttestation,
				"pubArea":  params.Public,
			},
		}}, nil, nil},
		{"fail ver not present", args{ctx, mustAttestationProvisioner(t, acaRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "tpm",
			AttStatement: map[string]interface{}{
				"x5c":      []interface{}{akCert.Raw, aca.Intermediate.Raw},
				"alg":      int64(-257), // RS256
				"sig":      params.CreateSignature,
				"certInfo": params.CreateAttestation,
				"pubArea":  params.Public,
			},
		}}, nil, newBadAttestationStatementError("ver not present")},
		{"fail ver type", args{ctx, mustAttestationProvisioner(t, acaRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "tpm",
			AttStatement: map[string]interface{}{
				"ver":      []interface{}{},
				"x5c":      []interface{}{akCert.Raw, aca.Intermediate.Raw},
				"alg":      int64(-257), // RS256
				"sig":      params.CreateSignature,
				"certInfo": params.CreateAttestation,
				"pubArea":  params.Public,
			},
		}}, nil, newBadAttestationStatementError("ver not present")},
		{"fail bogus ver", args{ctx, mustAttestationProvisioner(t, acaRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "tpm",
			AttStatement: map[string]interface{}{
				"ver":      "bogus",
				"x5c":      []interface{}{akCert.Raw, aca.Intermediate.Raw},
				"alg":      int64(-257), // RS256
				"sig":      params.CreateSignature,
				"certInfo": params.CreateAttestation,
				"pubArea":  params.Public,
			},
		}}, nil, newBadAttestationStatementError(`version "bogus" is not supported`)},
		{"fail x5c not present", args{ctx, mustAttestationProvisioner(t, acaRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "tpm",
			AttStatement: map[string]interface{}{
				"ver":      "2.0",
				"alg":      int64(-257), // RS256
				"sig":      params.CreateSignature,
				"certInfo": params.CreateAttestation,
				"pubArea":  params.Public,
			},
		}}, nil, newBadAttestationStatementError("x5c not present")},
		{"fail x5c type", args{ctx, mustAttestationProvisioner(t, acaRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "tpm",
			AttStatement: map[string]interface{}{
				"ver":      "2.0",
				"x5c":      [][]byte{akCert.Raw, aca.Intermediate.Raw},
				"alg":      int64(-257), // RS256
				"sig":      params.CreateSignature,
				"certInfo": params.CreateAttestation,
				"pubArea":  params.Public,
			},
		}}, nil, newBadAttestationStatementError("x5c not present")},
		{"fail x5c empty", args{ctx, mustAttestationProvisioner(t, acaRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "tpm",
			AttStatement: map[string]interface{}{
				"ver":      "2.0",
				"x5c":      []interface{}{},
				"alg":      int64(-257), // RS256
				"sig":      params.CreateSignature,
				"certInfo": params.CreateAttestation,
				"pubArea":  params.Public,
			},
		}}, nil, newBadAttestationStatementError("x5c is empty")},
		{"fail leaf type", args{ctx, mustAttestationProvisioner(t, acaRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "step",
			AttStatement: map[string]interface{}{
				"ver":      "2.0",
				"x5c":      []interface{}{"leaf", aca.Intermediate.Raw},
				"alg":      int64(-257), // RS256
				"sig":      params.CreateSignature,
				"certInfo": params.CreateAttestation,
				"pubArea":  params.Public,
			},
		}}, nil, newBadAttestationStatementError("x5c is malformed")},
		{"fail leaf parse", args{ctx, mustAttestationProvisioner(t, acaRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "step",
			AttStatement: map[string]interface{}{
				"ver":      "2.0",
				"x5c":      []interface{}{akCert.Raw[:100], aca.Intermediate.Raw},
				"alg":      int64(-257), // RS256
				"sig":      params.CreateSignature,
				"certInfo": params.CreateAttestation,
				"pubArea":  params.Public,
			},
		}}, nil, newBadAttestationStatementError("x5c is malformed: x509: malformed certificate")},
		{"fail intermediate type", args{ctx, mustAttestationProvisioner(t, acaRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "step",
			AttStatement: map[string]interface{}{
				"ver":      "2.0",
				"x5c":      []interface{}{akCert.Raw, "intermediate"},
				"alg":      int64(-257), // RS256
				"sig":      params.CreateSignature,
				"certInfo": params.CreateAttestation,
				"pubArea":  params.Public,
			},
		}}, nil, newBadAttestationStatementError("x5c is malformed")},
		{"fail intermediate parse", args{ctx, mustAttestationProvisioner(t, acaRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "step",
			AttStatement: map[string]interface{}{
				"ver":      "2.0",
				"x5c":      []interface{}{akCert.Raw, aca.Intermediate.Raw[:100]},
				"alg":      int64(-257), // RS256
				"sig":      params.CreateSignature,
				"certInfo": params.CreateAttestation,
				"pubArea":  params.Public,
			},
		}}, nil, newBadAttestationStatementError("x5c is malformed: x509: malformed certificate")},
		{"fail roots", args{ctx, mustAttestationProvisioner(t, nil), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "tpm",
			AttStatement: map[string]interface{}{
				"ver":      "2.0",
				"x5c":      []interface{}{akCert.Raw, aca.Intermediate.Raw},
				"alg":      int64(-257), // RS256
				"sig":      params.CreateSignature,
				"certInfo": params.CreateAttestation,
				"pubArea":  params.Public,
			},
		}}, nil, newInternalServerError("no root CA bundle available to verify the attestation certificate")},
		{"fail verify", args{ctx, mustAttestationProvisioner(t, acaRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "step",
			AttStatement: map[string]interface{}{
				"ver":      "2.0",
				"x5c":      []interface{}{akCert.Raw},
				"alg":      int64(-257), // RS256
				"sig":      params.CreateSignature,
				"certInfo": params.CreateAttestation,
				"pubArea":  params.Public,
			},
		}}, nil, newBadAttestationStatementError("x5c is not valid: x509: certificate signed by unknown authority")},
		{"fail validateAKCertificate", args{ctx, mustAttestationProvisioner(t, acaRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "tpm",
			AttStatement: map[string]interface{}{
				"ver":      "2.0",
				"x5c":      []interface{}{invalidAKCert.Raw, aca.Intermediate.Raw},
				"alg":      int64(-257), // RS256
				"sig":      params.CreateSignature,
				"certInfo": params.CreateAttestation,
				"pubArea":  params.Public,
			},
		}}, nil, newBadAttestationStatementError("AK certificate is not valid: missing TPM manufacturer")},
		{"fail pubArea not present", args{ctx, mustAttestationProvisioner(t, acaRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "tpm",
			AttStatement: map[string]interface{}{
				"ver":      "2.0",
				"x5c":      []interface{}{akCert.Raw, aca.Intermediate.Raw},
				"alg":      int64(-257), // RS256
				"sig":      params.CreateSignature,
				"certInfo": params.CreateAttestation,
			},
		}}, nil, newBadAttestationStatementError("invalid pubArea in attestation statement")},
		{"fail pubArea type", args{ctx, mustAttestationProvisioner(t, acaRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "tpm",
			AttStatement: map[string]interface{}{
				"ver":      "2.0",
				"x5c":      []interface{}{akCert.Raw, aca.Intermediate.Raw},
				"alg":      int64(-257), // RS256
				"sig":      params.CreateSignature,
				"certInfo": params.CreateAttestation,
				"pubArea":  []interface{}{},
			},
		}}, nil, newBadAttestationStatementError("invalid pubArea in attestation statement")},
		{"fail pubArea empty", args{ctx, mustAttestationProvisioner(t, acaRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "tpm",
			AttStatement: map[string]interface{}{
				"ver":      "2.0",
				"x5c":      []interface{}{akCert.Raw, aca.Intermediate.Raw},
				"alg":      int64(-257), // RS256
				"sig":      params.CreateSignature,
				"certInfo": params.CreateAttestation,
				"pubArea":  []byte{},
			},
		}}, nil, newBadAttestationStatementError("pubArea is empty")},
		{"fail sig not present", args{ctx, mustAttestationProvisioner(t, acaRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "tpm",
			AttStatement: map[string]interface{}{
				"ver":      "2.0",
				"x5c":      []interface{}{akCert.Raw, aca.Intermediate.Raw},
				"alg":      int64(-257), // RS256
				"certInfo": params.CreateAttestation,
				"pubArea":  params.Public,
			},
		}}, nil, newBadAttestationStatementError("invalid sig in attestation statement")},
		{"fail sig type", args{ctx, mustAttestationProvisioner(t, acaRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "tpm",
			AttStatement: map[string]interface{}{
				"ver":      "2.0",
				"x5c":      []interface{}{akCert.Raw, aca.Intermediate.Raw},
				"alg":      int64(-257), // RS256
				"sig":      []interface{}{},
				"certInfo": params.CreateAttestation,
				"pubArea":  params.Public,
			},
		}}, nil, newBadAttestationStatementError("invalid sig in attestation statement")},
		{"fail sig empty", args{ctx, mustAttestationProvisioner(t, acaRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "tpm",
			AttStatement: map[string]interface{}{
				"ver":      "2.0",
				"x5c":      []interface{}{akCert.Raw, aca.Intermediate.Raw},
				"alg":      int64(-257), // RS256
				"sig":      []byte{},
				"certInfo": params.CreateAttestation,
				"pubArea":  params.Public,
			},
		}}, nil, newBadAttestationStatementError("sig is empty")},
		{"fail certInfo not present", args{ctx, mustAttestationProvisioner(t, acaRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "tpm",
			AttStatement: map[string]interface{}{
				"ver":     "2.0",
				"x5c":     []interface{}{akCert.Raw, aca.Intermediate.Raw},
				"alg":     int64(-257), // RS256
				"sig":     params.CreateSignature,
				"pubArea": params.Public,
			},
		}}, nil, newBadAttestationStatementError("invalid certInfo in attestation statement")},
		{"fail certInfo type", args{ctx, mustAttestationProvisioner(t, acaRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "tpm",
			AttStatement: map[string]interface{}{
				"ver":      "2.0",
				"x5c":      []interface{}{akCert.Raw, aca.Intermediate.Raw},
				"alg":      int64(-257), // RS256
				"sig":      params.CreateSignature,
				"certInfo": []interface{}{},
				"pubArea":  params.Public,
			},
		}}, nil, newBadAttestationStatementError("invalid certInfo in attestation statement")},
		{"fail certInfo empty", args{ctx, mustAttestationProvisioner(t, acaRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "tpm",
			AttStatement: map[string]interface{}{
				"ver":      "2.0",
				"x5c":      []interface{}{akCert.Raw, aca.Intermediate.Raw},
				"alg":      int64(-257), // RS256
				"sig":      params.CreateSignature,
				"certInfo": []byte{},
				"pubArea":  params.Public,
			},
		}}, nil, newBadAttestationStatementError("certInfo is empty")},
		{"fail alg not present", args{ctx, mustAttestationProvisioner(t, acaRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "tpm",
			AttStatement: map[string]interface{}{
				"ver":      "2.0",
				"x5c":      []interface{}{akCert.Raw, aca.Intermediate.Raw},
				"sig":      params.CreateSignature,
				"certInfo": params.CreateAttestation,
				"pubArea":  params.Public,
			},
		}}, nil, newBadAttestationStatementError("invalid alg in attestation statement")},
		{"fail alg type", args{ctx, mustAttestationProvisioner(t, acaRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "tpm",
			AttStatement: map[string]interface{}{
				"ver":      "2.0",
				"x5c":      []interface{}{akCert.Raw, aca.Intermediate.Raw},
				"alg":      int64(0), // invalid alg
				"sig":      params.CreateSignature,
				"certInfo": params.CreateAttestation,
				"pubArea":  params.Public,
			},
		}}, nil, newBadAttestationStatementError("invalid alg 0 in attestation statement")},
		{"fail attestation verification", args{ctx, mustAttestationProvisioner(t, acaRoot), &Challenge{Token: "token"}, jwk, &attestationObject{
			Format: "tpm",
			AttStatement: map[string]interface{}{
				"ver":      "2.0",
				"x5c":      []interface{}{akCert.Raw, aca.Intermediate.Raw},
				"alg":      int64(-257), // RS256
				"sig":      params.CreateSignature,
				"certInfo": params.CreateAttestation,
				"pubArea":  anotherKeyParams.Public,
			},
		}}, nil, newBadAttestationStatementError("invalid certification parameters: certification refers to a different key")},
		{"fail keyAuthorization", args{ctx, mustAttestationProvisioner(t, acaRoot), &Challenge{Token: "token"}, &jose.JSONWebKey{Key: []byte("not an asymmetric key")}, &attestationObject{
			Format: "tpm",
			AttStatement: map[string]interface{}{
				"ver":      "2.0",
				"x5c":      []interface{}{akCert.Raw, aca.Intermediate.Raw},
				"alg":      int64(-257), // RS256
				"sig":      params.CreateSignature,
				"certInfo": params.CreateAttestation,
				"pubArea":  params.Public,
			},
		}}, nil, newInternalServerError("failed creating key auth digest: error generating JWK thumbprint: go-jose/go-jose: unknown key type '[]uint8'")},
		{"fail different keyAuthorization", args{ctx, mustAttestationProvisioner(t, acaRoot), &Challenge{Token: "aDifferentToken"}, jwk, &attestationObject{
			Format: "tpm",
			AttStatement: map[string]interface{}{
				"ver":      "2.0",
				"x5c":      []interface{}{akCert.Raw, aca.Intermediate.Raw},
				"alg":      int64(-257), //
				"sig":      params.CreateSignature,
				"certInfo": params.CreateAttestation,
				"pubArea":  params.Public,
			},
		}}, nil, newBadAttestationStatementError("key authorization invalid")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := doTPMAttestationFormat(tt.args.ctx, tt.args.prov, tt.args.ch, tt.args.jwk, tt.args.att)
			if tt.expErr != nil {
				var ae *Error
				if assert.True(t, errors.As(err, &ae)) {
					assert.EqualError(t, err, tt.expErr.Error())
					assert.Equal(t, ae.StatusCode(), tt.expErr.StatusCode())
					assert.Equal(t, ae.Type, tt.expErr.Type)
				}
				assert.Nil(t, got)
				return
			}

			assert.NoError(t, err)
			if assert.NotNil(t, got) {
				assert.Equal(t, akCert, got.Certificate)
				assert.Equal(t, [][]*x509.Certificate{
					{
						akCert, aca.Intermediate, aca.Root,
					},
				}, got.VerifiedChains)
				assert.Equal(t, fingerprint, got.Fingerprint)
				assert.Empty(t, got.PermanentIdentifiers) // currently expected to be always empty
			}
		})
	}
}
