package api

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/authority/provisioner"
)

func newRemoteAttestationProv(t *testing.T, challenges []provisioner.ACMEChallenge, o *provisioner.ACMERemoteAttestation) *provisioner.ACME {
	t.Helper()
	p := &provisioner.ACME{
		Type:              "ACME",
		Name:              "attested",
		Challenges:        challenges,
		RemoteAttestation: o,
	}
	require.NoError(t, p.Init(provisioner.Config{Claims: globalProvisionerClaims}))
	return p
}

func TestNewOrderRequest_Validate_remoteAttestation(t *testing.T) {
	tests := []struct {
		name    string
		ids     []acme.Identifier
		wantErr string
	}{
		{"ok empty hint", []acme.Identifier{{Type: acme.RemoteAttestation}}, ""},
		{"ok with dns", []acme.Identifier{{Type: acme.DNS, Value: "example.com"}, {Type: acme.RemoteAttestation, Value: "measured_boot"}}, ""},
		{"ok longest hint", []acme.Identifier{{Type: acme.RemoteAttestation, Value: strings.Repeat("a", maxRemoteAttestationHint)}}, ""},
		{"fail hint too long", []acme.Identifier{{Type: acme.RemoteAttestation, Value: strings.Repeat("a", maxRemoteAttestationHint+1)}},
			"remote-attestation identifier value cannot be longer than 128 bytes"},
		{"fail two", []acme.Identifier{{Type: acme.RemoteAttestation}, {Type: acme.RemoteAttestation, Value: "hsm"}},
			"an order cannot have more than one remote-attestation identifier"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := (&NewOrderRequest{Identifiers: tt.ids}).Validate()
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			var acmeErr *acme.Error
			require.ErrorAs(t, err, &acmeErr)
			assert.Equal(t, acme.NewError(acme.ErrorMalformedType, "").Type, acmeErr.Type)
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestAddRemoteAttestationIdentifier(t *testing.T) {
	enabled := []provisioner.ACMEChallenge{provisioner.DNS_01, provisioner.REMOTE_ATTEST_01}
	dns := acme.Identifier{Type: acme.DNS, Value: "example.com"}
	ra := acme.Identifier{Type: acme.RemoteAttestation, Value: "hsm"}

	tests := []struct {
		name    string
		prov    *provisioner.ACME
		ids     []acme.Identifier
		want    []acme.Identifier
		wantErr bool
	}{
		{"ok not required", newRemoteAttestationProv(t, enabled, nil), []acme.Identifier{dns}, []acme.Identifier{dns}, false},
		{"ok required", newRemoteAttestationProv(t, enabled, &provisioner.ACMERemoteAttestation{Require: true}),
			[]acme.Identifier{dns}, []acme.Identifier{dns, {Type: acme.RemoteAttestation}}, false},
		{"ok required and present", newRemoteAttestationProv(t, enabled, &provisioner.ACMERemoteAttestation{Require: true}),
			[]acme.Identifier{ra, dns}, []acme.Identifier{ra, dns}, false},
		{"ok required but not enabled", newRemoteAttestationProv(t, nil, &provisioner.ACMERemoteAttestation{Require: true}),
			[]acme.Identifier{dns}, []acme.Identifier{dns}, false},
		{"fail not enabled", newRemoteAttestationProv(t, nil, nil), []acme.Identifier{dns, ra}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nor := &NewOrderRequest{Identifiers: tt.ids}
			err := addRemoteAttestationIdentifier(context.Background(), tt.prov, nor)
			if tt.wantErr {
				var acmeErr *acme.Error
				require.ErrorAs(t, err, &acmeErr)
				assert.Equal(t, acme.NewError(acme.ErrorUnsupportedIdentifierType, "").Type, acmeErr.Type)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, nor.Identifiers)
		})
	}
}

func TestChallengeTypes_remoteAttestation(t *testing.T) {
	got := challengeTypes(&acme.Authorization{Identifier: acme.Identifier{Type: acme.RemoteAttestation}})
	assert.Equal(t, []acme.ChallengeType{acme.REMOTEATTEST01}, got)
}

func TestNewAuthorization_remoteAttestation(t *testing.T) {
	prov := newRemoteAttestationProv(t, []provisioner.ACMEChallenge{provisioner.REMOTE_ATTEST_01}, &provisioner.ACMERemoteAttestation{
		ClaimsHint: []string{"hwmodel", "swversion"},
	})
	var created []*acme.Challenge
	db := &acme.MockDB{
		MockCreateChallenge: func(_ context.Context, ch *acme.Challenge) error {
			ch.ID = "chID"
			created = append(created, ch)
			return nil
		},
		MockCreateAuthorization: func(_ context.Context, az *acme.Authorization) error {
			az.ID = "azID"
			return nil
		},
	}
	ctx := acme.NewProvisionerContext(context.Background(), prov)
	ctx = acme.NewDatabaseContext(ctx, db)

	az := &acme.Authorization{
		AccountID:  "accID",
		Identifier: acme.Identifier{Type: acme.RemoteAttestation, Value: "measured_boot"},
		Status:     acme.StatusPending,
	}
	require.NoError(t, newAuthorization(ctx, az))
	require.Len(t, created, 1)
	ch := created[0]
	assert.Equal(t, acme.REMOTEATTEST01, ch.Type)
	assert.Equal(t, "measured_boot", ch.Value)
	assert.Equal(t, []string{"hwmodel", "swversion"}, ch.AttestClaimsHint)
	nonce, err := base64.RawURLEncoding.DecodeString(ch.FreshnessNonce)
	require.NoError(t, err)
	assert.Len(t, nonce, 32)
	assert.Equal(t, []*acme.Challenge{ch}, az.Challenges)

	// Each challenge gets its own nonce.
	require.NoError(t, newAuthorization(ctx, &acme.Authorization{
		AccountID:  "accID",
		Identifier: acme.Identifier{Type: acme.RemoteAttestation},
	}))
	require.Len(t, created, 2)
	assert.NotEqual(t, created[0].FreshnessNonce, created[1].FreshnessNonce)
}
