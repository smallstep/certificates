package nosql

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/attestation"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/certificates/webhook"
)

// TestDB_Challenge_remoteAttestation checks that the fields of a
// remote-attest-01 challenge are stored and read back.
func TestDB_Challenge_remoteAttestation(t *testing.T) {
	var stored []byte
	d := DB{db: &db.MockNoSQLDB{
		MCmpAndSwap: func(_, _, _, nu []byte) ([]byte, bool, error) {
			stored = nu
			return nu, true, nil
		},
		MGet: func(bucket, key []byte) ([]byte, error) {
			assert.Equal(t, challengeTable, bucket)
			return stored, nil
		},
	}}

	ch := &acme.Challenge{
		AccountID:        "accountID",
		Type:             acme.REMOTEATTEST01,
		Status:           acme.StatusPending,
		Token:            "token",
		FreshnessNonce:   "yoW1RL2zPBzYEHBQ06Jy",
		AttestClaimsHint: []string{"hwmodel", "swversion"},
	}
	require.NoError(t, d.CreateChallenge(context.Background(), ch))
	assert.Contains(t, string(stored), `"freshnessNonce":"yoW1RL2zPBzYEHBQ06Jy"`)

	got, err := d.GetChallenge(context.Background(), ch.ID, "azID")
	require.NoError(t, err)
	assert.Equal(t, acme.REMOTEATTEST01, got.Type)
	assert.Equal(t, ch.FreshnessNonce, got.FreshnessNonce)
	assert.Equal(t, ch.AttestClaimsHint, got.AttestClaimsHint)

	// Other challenges store neither field.
	require.NoError(t, d.CreateChallenge(context.Background(), &acme.Challenge{Type: acme.DNS01, Token: "token"}))
	assert.NotContains(t, string(stored), "freshnessNonce")
	assert.NotContains(t, string(stored), "attestClaimsHint")
}

// TestDB_Authorization_remoteAttestation checks that the attestation a
// remote-attest-01 challenge verified is stored with the authorization and
// read back.
func TestDB_Authorization_remoteAttestation(t *testing.T) {
	var stored []byte
	d := DB{db: &db.MockNoSQLDB{
		MCmpAndSwap: func(_, _, _, nu []byte) ([]byte, bool, error) {
			stored = nu
			return nu, true, nil
		},
		MGet: func(bucket, key []byte) ([]byte, error) {
			assert.Equal(t, authzTable, bucket)
			return stored, nil
		},
	}}
	att := &webhook.Attestation{
		Challenge:        "remote-attest-01",
		FreshnessNonce:   "nonce",
		KeyAuthorization: "nonce.thumbprint",
		BindingDigest:    "01",
		ClaimNonce:       "claim",
		Result: &attestation.Result{
			Format:   attestation.FormatSEVSNP,
			SEVSNP:   &attestation.SEVSNP{Measurement: "aa", GuestSVN: 2},
			Evidence: []byte("report"),
		},
	}
	az := &acme.Authorization{
		AccountID:  "accountID",
		Identifier: acme.Identifier{Type: acme.RemoteAttestation},
		Status:     acme.StatusPending,
		Challenges: []*acme.Challenge{},
	}
	require.NoError(t, d.CreateAuthorization(context.Background(), az))
	assert.NotContains(t, string(stored), `"attestation"`)

	az.Status = acme.StatusValid
	az.Attestation = att
	require.NoError(t, d.UpdateAuthorization(context.Background(), az))

	got, err := d.GetAuthorization(context.Background(), az.ID)
	require.NoError(t, err)
	assert.Equal(t, att, got.Attestation)
}

// TestDB_GetExternalAccountKeyByAccountID checks that the EAB key an account
// was created with is found among its provisioner's keys, as a remote-attest-01
// order's webhooks receive it.
func TestDB_GetExternalAccountKeyByAccountID(t *testing.T) {
	keys := map[string]dbExternalAccountKey{
		"eak-1": {ID: "eak-1", ProvisionerID: "acme", Reference: "machine-1", AccountID: "account-1"},
		"eak-2": {ID: "eak-2", ProvisionerID: "acme", Reference: "machine-2"},
	}
	d := DB{db: &db.MockNoSQLDB{
		MGet: func(bucket, key []byte) ([]byte, error) {
			switch string(bucket) {
			case string(externalAccountKeyIDsByProvisionerIDTable):
				assert.Equal(t, "acme", string(key))
				return json.Marshal([]string{"eak-1", "eak-2"})
			case string(externalAccountKeyTable):
				eak, ok := keys[string(key)]
				require.True(t, ok)
				return json.Marshal(eak)
			default:
				t.Fatalf("unexpected bucket %s", bucket)
				return nil, nil
			}
		},
	}}

	got, err := d.GetExternalAccountKeyByAccountID(context.Background(), "acme", "account-1")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "eak-1", got.ID)
	assert.Equal(t, "machine-1", got.Reference)

	got, err = d.GetExternalAccountKeyByAccountID(context.Background(), "acme", "account-without-eab")
	require.NoError(t, err)
	assert.Nil(t, got)

	got, err = d.GetExternalAccountKeyByAccountID(context.Background(), "acme", "")
	require.NoError(t, err)
	assert.Nil(t, got)
}
