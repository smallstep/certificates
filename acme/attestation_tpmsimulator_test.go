//go:build tpmsimulator

package acme

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/keyutil"
)

func TestVerifyDeviceAttestationWithTPMSimulator(t *testing.T) {
	for _, tc := range []struct {
		name        string
		identifiers []string
	}{
		{"attested identifier", []string{"device.id.12345678"}},
		{"legacy without identifier", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			account, keyAuth := mustAccountAndKeyAuthorization(t, "token")
			payload, signer, root := mustAttestTPM(t, keyAuth, tc.identifiers)
			prov := mustAttestationProvisioner(t, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}))
			var response payloadType
			require.NoError(t, json.Unmarshal(payload, &response))
			object, err := base64.RawURLEncoding.DecodeString(response.AttObj)
			require.NoError(t, err)
			params := DeviceAttestationParams{Token: "token", Identifier: "device.id.12345678", AccountKey: account}
			result, err := VerifyDeviceAttestation(context.Background(), prov, params, object)
			require.NoError(t, err)
			fingerprint, err := keyutil.Fingerprint(signer.Public())
			require.NoError(t, err)
			require.Equal(t, &DeviceAttestationResult{
				Format: "tpm", Fingerprint: fingerprint, ChallengeBound: true, IdentifierBound: len(tc.identifiers) != 0,
			}, result)

			wrongToken := params
			wrongToken.Token = "wrong"
			_, err = VerifyDeviceAttestation(context.Background(), prov, wrongToken, object)
			require.Error(t, err)
			if len(tc.identifiers) != 0 {
				wrongIdentifier := params
				wrongIdentifier.Identifier = "another-device"
				_, err = VerifyDeviceAttestation(context.Background(), prov, wrongIdentifier, object)
				require.ErrorContains(t, err, "permanent identifier does not match")
			}
		})
	}
}
