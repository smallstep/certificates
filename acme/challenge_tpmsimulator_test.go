//go:build tpmsimulator
// +build tpmsimulator

package acme

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/url"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-attestation/attest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/minica"
	"go.step.sm/crypto/tpm"
	"go.step.sm/crypto/tpm/simulator"
	tpmstorage "go.step.sm/crypto/tpm/storage"
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
	sim = simulator.New()
	err := sim.Open()
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

func mustAttestTPM(t *testing.T, keyAuthorization string) ([]byte, crypto.Signer, *x509.Certificate) {
	t.Helper()
	aca, err := minica.New(
		minica.WithGetSignerFunc(
			func() (crypto.Signer, error) {
				return keyutil.GenerateSigner("RSA", "", 2048)
			},
		),
	)
	require.NoError(t, err)

	// prepare simulated TPM and create an AK
	ctpm := newSimulatedTPM(t)
	eks, err := ctpm.GetEKs(context.Background())
	require.NoError(t, err)
	ak, err := ctpm.CreateAK(context.Background(), "first-ak")
	require.NoError(t, err)
	require.NotNil(t, ak)

	// extract the AK public key
	ap, err := ak.AttestationParameters(context.Background())
	require.NoError(t, err)
	akp, err := attest.ParseAKPublic(attest.TPMVersion20, ap.Public)
	require.NoError(t, err)

	// create template and sign certificate for the AK public key
	keyID := generateKeyID(t, eks[0].Public())
	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "testakcert",
		},
		PublicKey: akp.Public,
		URIs: []*url.URL{
			{Scheme: "urn", Opaque: "ek:sha256:" + base64.StdEncoding.EncodeToString(keyID)},
		},
	}
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
	key, err := ctpm.AttestKey(context.Background(), "first-ak", "first-key", config)
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
			"alg":      int64(-257), // RSA
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
		"ok": func(t *testing.T) test {
			jwk, keyAuth := mustAccountAndKeyAuthorization(t, "token")
			payload, signer, root := mustAttestTPM(t, keyAuth) // TODO: value(s) for AK cert?
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
