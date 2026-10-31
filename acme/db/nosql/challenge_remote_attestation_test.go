package nosql

import (
	"context"
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
		Challenge:      "remote-attest-01",
		FreshnessNonce: "nonce",
		KeyDigest:      "01",
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
