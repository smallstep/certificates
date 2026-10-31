package authority

import (
	"testing"
	"time"

	"github.com/smallstep/linkedca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smallstep/certificates/attestation"
	"github.com/smallstep/certificates/attestation/confidentialspace"
	"github.com/smallstep/certificates/authority/provisioner"
)

// TestProvisioner_remoteAttestation checks that an ACME provisioner with the
// remote-attest-01 challenge and its configuration survives the conversions to
// linkedca and back, which remote management goes through.
func TestProvisioner_remoteAttestation(t *testing.T) {
	ra := &provisioner.ACMERemoteAttestation{
		Require:     true,
		Formats:     []attestation.Format{attestation.FormatTDX, attestation.FormatConfidentialSpace},
		ClaimsHint:  []string{"hwmodel"},
		TDXRoots:    []byte("tdx roots"),
		SEVSNPRoots: []byte("sev-snp roots"),
		ConfidentialSpace: &provisioner.ACMEConfidentialSpace{
			Roots:       []byte("roots"),
			Audience:    "my-project",
			MaxTokenAge: &provisioner.Duration{Duration: 5 * time.Minute},
			Expectations: confidentialspace.Expectations{
				ImageDigests:             []string{"sha256:00"},
				ImageSignerKeyIDs:        []string{"c0ffee"},
				RequireSupportAttributes: []string{"STABLE"},
				HWModels:                 []string{"GCP_INTEL_TDX"},
				SWNames:                  []string{"CONFIDENTIAL_SPACE"},
				ProjectIDs:               []string{"my-project"},
				ServiceAccounts:          []string{"workload@my-project.iam.gserviceaccount.com"},
			},
		},
	}
	p := &provisioner.ACME{
		ID:                "acme-id",
		Type:              "ACME",
		Name:              "attested",
		Challenges:        []provisioner.ACMEChallenge{provisioner.DNS_01, provisioner.REMOTE_ATTEST_01},
		RemoteAttestation: ra,
	}

	lp, err := ProvisionerToLinkedca(p)
	require.NoError(t, err)
	acme := lp.GetDetails().GetACME()
	require.NotNil(t, acme)
	assert.Equal(t, []linkedca.ACMEProvisioner_ChallengeType{
		linkedca.ACMEProvisioner_DNS_01, linkedca.ACMEProvisioner_REMOTE_ATTEST_01,
	}, acme.Challenges)
	require.NotNil(t, acme.RemoteAttestation)
	assert.Equal(t, []string{"tdx", "confidential-space"}, acme.RemoteAttestation.Formats)
	assert.Equal(t, "5m0s", acme.RemoteAttestation.ConfidentialSpace.MaxTokenAge)

	got, err := ProvisionerToCertificates(lp)
	require.NoError(t, err)
	gotACME, ok := got.(*provisioner.ACME)
	require.True(t, ok)
	assert.Equal(t, p.Challenges, gotACME.Challenges)
	assert.Equal(t, ra, gotACME.RemoteAttestation)

	t.Run("no configuration", func(t *testing.T) {
		lp, err := ProvisionerToLinkedca(&provisioner.ACME{Type: "ACME", Name: "plain"})
		require.NoError(t, err)
		assert.Nil(t, lp.GetDetails().GetACME().RemoteAttestation)
		got, err := ProvisionerToCertificates(lp)
		require.NoError(t, err)
		assert.Nil(t, got.(*provisioner.ACME).RemoteAttestation)
	})

	t.Run("fail max token age", func(t *testing.T) {
		lp, err := ProvisionerToLinkedca(p)
		require.NoError(t, err)
		lp.GetDetails().GetACME().RemoteAttestation.ConfidentialSpace.MaxTokenAge = "five minutes"
		_, err = ProvisionerToCertificates(lp)
		assert.ErrorContains(t, err, "error parsing remote attestation maxTokenAge")
	})
}
