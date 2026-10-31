package provisioner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smallstep/certificates/attestation"
	"github.com/smallstep/certificates/attestation/cmw"
	"github.com/smallstep/certificates/attestation/confidentialspace"
	cstest "github.com/smallstep/certificates/attestation/confidentialspace/confidentialspacetest"
	"github.com/smallstep/certificates/authority/policy"
)

const testRemoteAttestationAudience = "https://ca.example.com/acme/attested/directory"

// staticHTTPClient serves fixed responses by URL and fails any other request,
// so that a test fails instead of reaching a vendor's service.
type staticHTTPClient map[string][]byte

func (c staticHTTPClient) Do(req *http.Request) (*http.Response, error) {
	body, ok := c[req.URL.String()]
	if !ok {
		return nil, errors.New("unexpected request to " + req.URL.String())
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewReader(body)),
	}, nil
}

func (c staticHTTPClient) Get(url string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

func newRemoteAttestationACME(t *testing.T, o *ACMERemoteAttestation, client HTTPClient) *ACME {
	t.Helper()
	p := &ACME{
		Type:              "ACME",
		Name:              "attested",
		Challenges:        []ACMEChallenge{REMOTE_ATTEST_01},
		RemoteAttestation: o,
	}
	require.NoError(t, p.Init(Config{Claims: globalProvisionerClaims, HTTPClient: client}))
	return p
}

// testBound returns the data a client binds to its evidence, 32 bytes for
// the key authorization's digest and 32 for the key's.
func testBound() []byte {
	ka := sha256.Sum256([]byte("token.thumbprint"))
	key := sha256.Sum256([]byte("spki"))
	return append(ka[:], key[:]...)
}

func jsonCMW(mediaType string, value []byte, ind cmw.Indicator) *cmw.Record {
	return &cmw.Record{MediaType: mediaType, Value: value, Indicator: ind}
}

func TestACME_Init_remoteAttestation(t *testing.T) {
	pki := cstest.New(t)
	tests := []struct {
		name        string
		challenges  []ACMEChallenge
		o           *ACMERemoteAttestation
		wantFormats []attestation.Format
		wantErr     string
	}{
		{"ok defaults", []ACMEChallenge{REMOTE_ATTEST_01}, nil,
			[]attestation.Format{attestation.FormatTDX, attestation.FormatSEVSNP}, ""},
		{"ok uppercase challenge", []ACMEChallenge{"REMOTE-ATTEST-01"}, nil,
			[]attestation.Format{attestation.FormatTDX, attestation.FormatSEVSNP}, ""},
		{"ok confidential space by default", []ACMEChallenge{REMOTE_ATTEST_01},
			&ACMERemoteAttestation{ConfidentialSpace: &ACMEConfidentialSpace{Roots: pki.RootPEM()}},
			[]attestation.Format{attestation.FormatTDX, attestation.FormatSEVSNP, attestation.FormatConfidentialSpace}, ""},
		{"ok formats", []ACMEChallenge{REMOTE_ATTEST_01},
			&ACMERemoteAttestation{Formats: []attestation.Format{attestation.FormatSEVSNP}},
			[]attestation.Format{attestation.FormatSEVSNP}, ""},
		{"ok not enabled", []ACMEChallenge{DNS_01},
			&ACMERemoteAttestation{Formats: []attestation.Format{"tpm"}}, nil, ""},
		{"fail format", []ACMEChallenge{REMOTE_ATTEST_01},
			&ACMERemoteAttestation{Formats: []attestation.Format{"tpm"}}, nil, `attestation format "tpm" is not supported`},
		{"fail claims hint", []ACMEChallenge{REMOTE_ATTEST_01},
			&ACMERemoteAttestation{ClaimsHint: []string{"hwmodel", ""}}, nil, "claimsHint cannot contain empty values"},
		{"fail tdx roots", []ACMEChallenge{REMOTE_ATTEST_01},
			&ACMERemoteAttestation{TDXRoots: []byte("not pem")}, nil, "error initializing the tdx format"},
		{"fail sev-snp roots", []ACMEChallenge{REMOTE_ATTEST_01},
			&ACMERemoteAttestation{SEVSNPRoots: pki.RootPEM()}, nil, "error initializing the sev-snp format"},
		{"fail confidential space without roots", []ACMEChallenge{REMOTE_ATTEST_01},
			&ACMERemoteAttestation{Formats: []attestation.Format{attestation.FormatConfidentialSpace}}, nil,
			"confidentialSpace.roots is required"},
		{"fail confidential space roots", []ACMEChallenge{REMOTE_ATTEST_01},
			&ACMERemoteAttestation{ConfidentialSpace: &ACMEConfidentialSpace{Roots: []byte("not pem")}}, nil,
			"no certificates found in confidentialSpace.roots"},
		{"fail confidential space max age", []ACMEChallenge{REMOTE_ATTEST_01},
			&ACMERemoteAttestation{ConfidentialSpace: &ACMEConfidentialSpace{Roots: pki.RootPEM(), MaxTokenAge: &Duration{}}}, nil,
			"confidentialSpace.maxTokenAge must be greater than 0"},
		{"fail confidential space expectations", []ACMEChallenge{REMOTE_ATTEST_01},
			&ACMERemoteAttestation{ConfidentialSpace: &ACMEConfidentialSpace{
				Roots:        pki.RootPEM(),
				Expectations: confidentialspace.Expectations{ProjectIDs: []string{""}},
			}}, nil, "confidentialSpace: projectIDs cannot contain empty values"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &ACME{
				Type:              "ACME",
				Name:              "attested",
				Challenges:        tt.challenges,
				RemoteAttestation: tt.o,
			}
			err := p.Init(Config{Claims: globalProvisionerClaims})
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			if tt.wantFormats == nil {
				assert.Nil(t, p.remoteAttestation)
				return
			}
			require.NotNil(t, p.remoteAttestation)
			assert.Equal(t, tt.wantFormats, p.remoteAttestation.formats)
		})
	}
}

func TestACMERemoteAttestation_getters(t *testing.T) {
	var o *ACMERemoteAttestation
	assert.False(t, o.IsRequired())
	assert.Nil(t, o.GetClaimsHint())
	o = &ACMERemoteAttestation{Require: true, ClaimsHint: []string{"hwmodel"}}
	assert.True(t, o.IsRequired())
	assert.Equal(t, []string{"hwmodel"}, o.GetClaimsHint())
	assert.Equal(t, o, (&ACME{RemoteAttestation: o}).GetRemoteAttestation())
}

func TestACME_AuthorizeOrderIdentifier_remoteAttestation(t *testing.T) {
	// A policy that allows nothing still allows a remote-attestation
	// identifier, which names nothing in the certificate.
	p := &ACME{
		Type: "ACME",
		Name: "attested",
		Options: &Options{X509: &X509Options{
			AllowedNames: &policy.X509NameOptions{DNSDomains: []string{"*.example.com"}},
		}},
	}
	require.NoError(t, p.Init(Config{Claims: globalProvisionerClaims}))
	ctx := context.Background()
	assert.NoError(t, p.AuthorizeOrderIdentifier(ctx, ACMEIdentifier{Type: RemoteAttestation, Value: "anything"}))
	assert.Error(t, p.AuthorizeOrderIdentifier(ctx, ACMEIdentifier{Type: DNS, Value: "anything"}))
}

func TestACME_VerifyRemoteAttestation_confidentialSpace(t *testing.T) {
	pki := cstest.New(t)
	now := time.Now()
	bound := testBound()
	nonces := []string{
		base64.RawURLEncoding.EncodeToString(bound[:32]),
		base64.RawURLEncoding.EncodeToString(bound[32:]),
		"extra-nonce",
	}
	newProv := func(cs *ACMEConfidentialSpace) *ACME {
		cs.Roots = pki.RootPEM()
		return newRemoteAttestationACME(t, &ACMERemoteAttestation{ConfidentialSpace: cs}, staticHTTPClient{})
	}
	mint := func(audience string, nonces ...string) []byte {
		return []byte(pki.Mint(t, cstest.Claims(now, audience, nonces...)))
	}

	t.Run("ok default audience", func(t *testing.T) {
		got, gotBound, err := newProv(&ACMEConfidentialSpace{}).VerifyRemoteAttestation(context.Background(),
			jsonCMW("application/eat+jwt", mint(testRemoteAttestationAudience, nonces...), cmw.AttestationResults),
			testRemoteAttestationAudience)
		require.NoError(t, err)
		assert.Equal(t, bound, gotBound)
		assert.Equal(t, attestation.FormatConfidentialSpace, got.Format)
		assert.Equal(t, "application/eat+jwt", got.MediaType)
		assert.NotEmpty(t, got.Evidence)
		require.NotNil(t, got.ConfidentialSpace)
		assert.Equal(t, "GCP_INTEL_TDX", got.ConfidentialSpace.Claims["hwmodel"])
		assert.Nil(t, got.TDX)
		assert.Nil(t, got.SEVSNP)
	})

	t.Run("ok configured audience and no indicator", func(t *testing.T) {
		_, gotBound, err := newProv(&ACMEConfidentialSpace{Audience: "my-project"}).VerifyRemoteAttestation(context.Background(),
			jsonCMW("application/jwt", mint("my-project", nonces...), 0), testRemoteAttestationAudience)
		require.NoError(t, err)
		assert.Equal(t, bound, gotBound)
	})

	tests := []struct {
		name    string
		cs      *ACMEConfidentialSpace
		record  *cmw.Record
		wantErr string
	}{
		{"fail indicator", &ACMEConfidentialSpace{},
			jsonCMW("application/eat+jwt", mint(testRemoteAttestationAudience, nonces...), cmw.Evidence),
			"must be indicated as an attestation result"},
		{"fail audience", &ACMEConfidentialSpace{},
			jsonCMW("application/eat+jwt", mint("https://other.example.com", nonces...), 0), "attestation token is not valid"},
		{"fail one nonce", &ACMEConfidentialSpace{},
			jsonCMW("application/eat+jwt", mint(testRemoteAttestationAudience, nonces[0]), 0), "between 2 and 6 nonces"},
		{"fail nonce encoding", &ACMEConfidentialSpace{},
			jsonCMW("application/eat+jwt", mint(testRemoteAttestationAudience, nonces[0], "SHA256:"+nonces[1]), 0),
			"eat_nonce[1] is not the base64url encoding of 32 bytes"},
		{"fail nonce size", &ACMEConfidentialSpace{},
			jsonCMW("application/eat+jwt", mint(testRemoteAttestationAudience, "c2hvcnQ", nonces[1]), 0),
			"eat_nonce[0] is not the base64url encoding of 32 bytes"},
		{"fail expectations", &ACMEConfidentialSpace{
			Expectations: confidentialspace.Expectations{ProjectIDs: []string{"other"}},
		}, jsonCMW("application/eat+jwt", mint(testRemoteAttestationAudience, nonces...), 0), `project "my-project" is not allowed`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := newProv(tt.cs).VerifyRemoteAttestation(context.Background(), tt.record, testRemoteAttestationAudience)
			assert.ErrorContains(t, err, tt.wantErr)
			assert.ErrorIs(t, err, attestation.ErrInvalidEvidence)
		})
	}
}

func TestACME_VerifyRemoteAttestation(t *testing.T) {
	pki := cstest.New(t)
	tdxOnly := newRemoteAttestationACME(t, &ACMERemoteAttestation{Formats: []attestation.Format{attestation.FormatTDX}}, staticHTTPClient{})
	defaults := newRemoteAttestationACME(t, nil, staticHTTPClient{})
	tsmJSON := func(provider, aux string) []byte {
		s := `{"provider":"` + provider + `","outblob":"AAEC"`
		if aux != "" {
			s += `,"auxblob":"` + aux + `"`
		}
		return []byte(s + "}")
	}
	token := []byte(pki.Mint(t, cstest.Claims(time.Now(), testRemoteAttestationAudience, "a", "b")))

	tests := []struct {
		name        string
		p           *ACME
		record      *cmw.Record
		wantErr     string
		wantInvalid bool
	}{
		{"fail not enabled", &ACME{}, jsonCMW("application/eat+jwt", token, 0), "remote-attest-01 is not enabled", false},
		{"fail media type", defaults, jsonCMW("text/plain", []byte("x"), 0), `evidence media type "text/plain" is not supported`, true},
		{"fail tsm indicator", defaults, jsonCMW("application/vnd.veraison.tsm-report+json", tsmJSON("tdx_guest", ""), cmw.AttestationResults),
			"a tsm report must be indicated as evidence", true},
		{"fail tsm parse", defaults, jsonCMW("application/vnd.veraison.tsm-report+json", []byte("{"), cmw.Evidence),
			"error parsing tsm report", true},
		{"fail tsm provider", defaults, jsonCMW("application/vnd.veraison.tsm-report+json", tsmJSON("arm_cca_guest", ""), 0),
			`tsm report provider "arm_cca_guest" is not supported`, true},
		{"fail tdx auxblob", defaults, jsonCMW("application/vnd.veraison.tsm-report+json", tsmJSON("tdx_guest", "AAEC"), 0),
			"a tdx tsm report does not take an auxblob", true},
		{"fail tdx quote", defaults, jsonCMW("application/vnd.veraison.tsm-report+json", tsmJSON("tdx_guest", ""), 0),
			"error parsing tdx quote", true},
		{"fail sev-snp report", defaults, jsonCMW("application/vnd.veraison.tsm-report+json", tsmJSON("sev_guest", ""), 0),
			"error parsing sev-snp report", true},
		{"fail sev-snp not enabled", tdxOnly, jsonCMW("application/vnd.veraison.tsm-report+json", tsmJSON("sev_guest", ""), 0),
			"attestation format sev-snp is not enabled", true},
		{"fail confidential space not enabled", defaults, jsonCMW("application/eat+jwt", token, 0),
			"attestation format confidential-space is not enabled", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := tt.p.VerifyRemoteAttestation(context.Background(), tt.record, testRemoteAttestationAudience)
			assert.ErrorContains(t, err, tt.wantErr)
			assert.Equal(t, tt.wantInvalid, errors.Is(err, attestation.ErrInvalidEvidence))
		})
	}
}

func TestIsJWTMediaType(t *testing.T) {
	assert.True(t, isJWTMediaType("application/jwt"))
	assert.True(t, isJWTMediaType(`application/eat+jwt; eat_profile="tag:example.com,2026:x"`))
	assert.False(t, isJWTMediaType("application/eat+cwt"))
	assert.False(t, isJWTMediaType(strings.Repeat(";", 3)))
}
