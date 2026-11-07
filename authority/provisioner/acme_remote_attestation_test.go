package provisioner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/jose"

	"github.com/smallstep/certificates/attestation"
	"github.com/smallstep/certificates/attestation/cmw"
	"github.com/smallstep/certificates/attestation/confidentialspace"
	cstest "github.com/smallstep/certificates/attestation/confidentialspace/confidentialspacetest"
	"github.com/smallstep/certificates/attestation/ita"
	"github.com/smallstep/certificates/attestation/tdx"
	"github.com/smallstep/certificates/authority/policy"
	"github.com/smallstep/certificates/webhook"
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
		{"ok azure-tdx", []ACMEChallenge{REMOTE_ATTEST_01},
			&ACMERemoteAttestation{Formats: []attestation.Format{attestation.FormatAzureTDX}},
			[]attestation.Format{attestation.FormatAzureTDX}, ""},
		{"fail azure-tdx roots", []ACMEChallenge{REMOTE_ATTEST_01},
			&ACMERemoteAttestation{Formats: []attestation.Format{attestation.FormatAzureTDX}, TDXRoots: []byte("not pem")}, nil,
			"error initializing the azure-tdx format"},
		{"fail sev-snp roots", []ACMEChallenge{REMOTE_ATTEST_01},
			&ACMERemoteAttestation{SEVSNPRoots: pki.RootPEM()}, nil, "error initializing the sev-snp format"},
		// Google's root is pinned, so the format needs no configuration.
		{"ok confidential space with the pinned root", []ACMEChallenge{REMOTE_ATTEST_01},
			&ACMERemoteAttestation{Formats: []attestation.Format{attestation.FormatConfidentialSpace}},
			[]attestation.Format{attestation.FormatConfidentialSpace}, ""},
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
	// The binding first, then the relying party's own nonces.
	bound := testBound()[:RemoteAttestationBindingSize]
	nonces := []string{
		base64.RawURLEncoding.EncodeToString(bound),
		"relying-party-nonce",
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

	t.Run("ok binding alone", func(t *testing.T) {
		_, gotBound, err := newProv(&ACMEConfidentialSpace{}).VerifyRemoteAttestation(context.Background(),
			jsonCMW("application/eat+jwt", mint(testRemoteAttestationAudience, nonces[0]), 0), testRemoteAttestationAudience)
		require.NoError(t, err)
		assert.Equal(t, bound, gotBound)
	})

	t.Run("fail token under another root than Google's", func(t *testing.T) {
		// Without configured roots the provisioner trusts only Google Cloud
		// Attestation's pinned root, so the test PKI's token is refused.
		p := newRemoteAttestationACME(t, &ACMERemoteAttestation{ConfidentialSpace: &ACMEConfidentialSpace{}}, staticHTTPClient{})
		_, _, err := p.VerifyRemoteAttestation(context.Background(),
			jsonCMW("application/eat+jwt", mint(testRemoteAttestationAudience, nonces...), 0), testRemoteAttestationAudience)
		assert.ErrorContains(t, err, "attestation token x5c is not valid")
		assert.ErrorIs(t, err, attestation.ErrInvalidEvidence)
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
		{"fail no nonce", &ACMEConfidentialSpace{},
			jsonCMW("application/eat+jwt", mint(testRemoteAttestationAudience), 0), "between 1 and 6 nonces"},
		{"fail binding encoding", &ACMEConfidentialSpace{},
			jsonCMW("application/eat+jwt", mint(testRemoteAttestationAudience, "SHA256:"+nonces[0], nonces[1]), 0),
			"eat_nonce[0] is not the base64url encoding of 32 bytes"},
		{"fail binding size", &ACMEConfidentialSpace{},
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

func TestWebhookController_AppendRequestBodyOptions(t *testing.T) {
	a := &webhook.Attestation{Challenge: "remote-attest-01"}
	wc := &WebhookController{}
	wc.AppendRequestBodyOptions(webhook.WithAttestation(a))

	req := &webhook.RequestBody{}
	require.NoError(t, wc.Enrich(context.Background(), req))
	assert.Equal(t, a, req.Attestation)

	req = &webhook.RequestBody{}
	require.NoError(t, wc.Authorize(context.Background(), req))
	assert.Equal(t, a, req.Attestation)
}

// fakeTDXVerifier stands in for the TDX verifier: a real quote's report data
// cannot be chosen, and a test quote cannot pass Intel's collateral.
type fakeTDXVerifier struct {
	result *attestation.TDX
	bound  []byte
	err    error
	quote  []byte
}

func (f *fakeTDXVerifier) Verify(_ context.Context, quote []byte) (*attestation.TDX, []byte, error) {
	f.quote = quote
	return f.result, f.bound, f.err
}

func TestACME_VerifyRemoteAttestation_tdx(t *testing.T) {
	bound := testBound()
	const mediaType = `application/vnd.veraison.tsm-report+json; provider="tdx_guest"`
	value := []byte(`{"provider":"tdx_guest","outblob":"AAEC"}`)

	t.Run("ok", func(t *testing.T) {
		p := newRemoteAttestationACME(t, nil, staticHTTPClient{})
		fake := &fakeTDXVerifier{result: &attestation.TDX{MRTD: "aa", TCBStatus: "UpToDate"}, bound: bound}
		p.remoteAttestation.tdx = fake
		got, gotBound, err := p.VerifyRemoteAttestation(context.Background(), jsonCMW(mediaType, value, cmw.Evidence), "")
		require.NoError(t, err)
		assert.Equal(t, []byte{0, 1, 2}, fake.quote, "the outblob is the quote")
		assert.Equal(t, bound, gotBound)
		assert.Equal(t, attestation.FormatTDX, got.Format)
		assert.Equal(t, mediaType, got.MediaType)
		assert.Equal(t, value, got.Evidence)
		assert.Equal(t, fake.result, got.TDX)
		assert.Nil(t, got.SEVSNP)
		assert.Nil(t, got.ConfidentialSpace)
	})

	tests := []struct {
		name        string
		fake        *fakeTDXVerifier
		wantErr     string
		wantInvalid bool
	}{
		{"fail invalid quote", &fakeTDXVerifier{err: attestation.Invalidf("tdx quote is from a debug trust domain")},
			"debug trust domain", true},
		// A collateral fetch failure is the CA's, not the evidence's.
		{"fail collateral", &fakeTDXVerifier{err: errors.New("error fetching tdx collateral")},
			"error fetching tdx collateral", false},
		{"fail report data size", &fakeTDXVerifier{result: &attestation.TDX{}, bound: bound[:32]},
			"evidence binds 32 bytes, not 64", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newRemoteAttestationACME(t, nil, staticHTTPClient{})
			p.remoteAttestation.tdx = tt.fake
			_, _, err := p.VerifyRemoteAttestation(context.Background(), jsonCMW(mediaType, value, 0), "")
			assert.ErrorContains(t, err, tt.wantErr)
			assert.Equal(t, tt.wantInvalid, errors.Is(err, attestation.ErrInvalidEvidence))
		})
	}
}

// azureEvidence returns the evidence of an Azure confidential VM whose runtime
// claims carry userData, and the report data that commits to them.
func azureEvidence(t *testing.T, userData []byte) ([]byte, []byte) {
	t.Helper()
	runtime := []byte(`{"keys":[{"kid":"HCLAkPub","kty":"RSA"}],"vm-configuration":{"secure-boot":true},"user-data":"` +
		hex.EncodeToString(userData) + `"}`)
	value, err := json.Marshal(map[string][]byte{"quote": {0, 1, 2}, "runtimeData": runtime})
	require.NoError(t, err)
	reportData := make([]byte, 64)
	sum := sha256.Sum256(runtime)
	copy(reportData, sum[:])
	return value, reportData
}

func TestACME_VerifyRemoteAttestation_azureTDX(t *testing.T) {
	bound := testBound()
	value, reportData := azureEvidence(t, bound)
	azure := &ACMERemoteAttestation{Formats: []attestation.Format{attestation.FormatAzureTDX}}

	t.Run("ok", func(t *testing.T) {
		p := newRemoteAttestationACME(t, azure, staticHTTPClient{})
		fake := &fakeTDXVerifier{result: &attestation.TDX{MRTD: "aa", TCBStatus: "UpToDate"}, bound: reportData}
		p.remoteAttestation.tdx = fake
		got, gotBound, err := p.VerifyRemoteAttestation(context.Background(), jsonCMW(tdx.AzureMediaType, value, cmw.Evidence), "")
		require.NoError(t, err)
		assert.Equal(t, []byte{0, 1, 2}, fake.quote)
		// The binding and the claim nonce come from the runtime claims'
		// user data, not from the quote's report data.
		assert.Equal(t, bound, gotBound)
		assert.Equal(t, attestation.FormatAzureTDX, got.Format)
		assert.Equal(t, fake.result, got.TDX)
		require.NotNil(t, got.AzureRuntime)
		assert.Equal(t, "HCLAkPub", got.AzureRuntime.Keys[0]["kid"])
		assert.Equal(t, true, got.AzureRuntime.VMConfiguration["secure-boot"])
		assert.Equal(t, value, got.Evidence)
	})

	otherReportData := append([]byte(nil), reportData...)
	otherReportData[0] ^= 1
	tests := []struct {
		name        string
		o           *ACMERemoteAttestation
		fake        *fakeTDXVerifier
		record      *cmw.Record
		wantErr     string
		wantInvalid bool
	}{
		// Like configfs-tsm reports, an Azure quote is evidence only when
		// listed, since its MRTD measures Azure's paravisor, not the guest.
		{"fail not enabled", nil, &fakeTDXVerifier{result: &attestation.TDX{}, bound: reportData},
			jsonCMW(tdx.AzureMediaType, value, 0), "attestation format azure-tdx is not enabled", true},
		{"fail indicator", azure, &fakeTDXVerifier{result: &attestation.TDX{}, bound: reportData},
			jsonCMW(tdx.AzureMediaType, value, cmw.AttestationResults), "must be indicated as evidence", true},
		{"fail evidence", azure, &fakeTDXVerifier{result: &attestation.TDX{}, bound: reportData},
			jsonCMW(tdx.AzureMediaType, []byte(`{}`), 0), "needs a quote and runtime data", true},
		{"fail invalid quote", azure, &fakeTDXVerifier{err: attestation.Invalidf("tdx quote is from a debug trust domain")},
			jsonCMW(tdx.AzureMediaType, value, 0), "debug trust domain", true},
		{"fail collateral", azure, &fakeTDXVerifier{err: errors.New("error fetching tdx collateral")},
			jsonCMW(tdx.AzureMediaType, value, 0), "error fetching tdx collateral", false},
		{"fail report data", azure, &fakeTDXVerifier{result: &attestation.TDX{}, bound: otherReportData},
			jsonCMW(tdx.AzureMediaType, value, 0), "does not commit to the azure runtime data", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newRemoteAttestationACME(t, tt.o, staticHTTPClient{})
			if p.remoteAttestation.tdx != nil {
				p.remoteAttestation.tdx = tt.fake
			}
			_, _, err := p.VerifyRemoteAttestation(context.Background(), tt.record, "")
			assert.ErrorContains(t, err, tt.wantErr)
			assert.Equal(t, tt.wantInvalid, errors.Is(err, attestation.ErrInvalidEvidence))
		})
	}
}

// itaToken mints an Intel Trust Authority token for userData with the PKI's
// leaf, published under kid.
func itaToken(t *testing.T, pki *cstest.PKI, kid string, userData []byte, debuggable bool) string {
	t.Helper()
	sum := sha512.Sum512(userData)
	now := time.Now()
	claims := map[string]any{
		"iss": ita.Issuer, "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"tdx": map[string]any{
			"tdx_is_debuggable":     debuggable,
			"attester_user_data":    base64.StdEncoding.EncodeToString(userData),
			"attester_runtime_data": map[string]any{"user-data": hex.EncodeToString(sum[:])},
			"attester_tcb_status":   "UpToDate",
		},
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.PS384, Key: pki.LeafKey},
		new(jose.SignerOptions).WithType("JWT").WithHeader("kid", kid))
	require.NoError(t, err)
	token, err := jose.Signed(signer).Claims(claims).CompactSerialize()
	require.NoError(t, err)
	return token
}

func TestACME_VerifyRemoteAttestation_ita(t *testing.T) {
	pki := cstest.New(t)
	keys := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: pki.Leaf.PublicKey, KeyID: "kid", Algorithm: jose.PS384, Use: "sig", Certificates: pki.Chain(),
	}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(keys)
	}))
	defer srv.Close()
	o := &ACMERemoteAttestation{ITA: &ACMEITA{Roots: pki.RootPEM(), JWKSURL: srv.URL}}
	bound := testBound()

	t.Run("ok", func(t *testing.T) {
		p := newRemoteAttestationACME(t, o, srv.Client())
		assert.Contains(t, p.remoteAttestation.formats, attestation.FormatITA, "ita is enabled when configured")
		token := itaToken(t, pki, "kid", bound, false)
		got, gotBound, err := p.VerifyRemoteAttestation(context.Background(),
			jsonCMW("application/eat+jwt", []byte(token), cmw.AttestationResults), "")
		require.NoError(t, err)
		assert.Equal(t, bound, gotBound)
		assert.Equal(t, attestation.FormatITA, got.Format)
		require.NotNil(t, got.ITA)
		assert.Equal(t, ita.Issuer, got.ITA.Claims["iss"])
		assert.Nil(t, got.ConfidentialSpace)
	})

	tests := []struct {
		name        string
		o           *ACMERemoteAttestation
		record      *cmw.Record
		wantErr     string
		wantInvalid bool
	}{
		{"fail not enabled", nil, jsonCMW("application/eat+jwt", []byte(itaToken(t, pki, "kid", bound, false)), 0),
			"attestation format ita is not enabled", true},
		{"fail indicator", o, jsonCMW("application/eat+jwt", []byte(itaToken(t, pki, "kid", bound, false)), cmw.Evidence),
			"must be indicated as an attestation result", true},
		{"fail debuggable", o, jsonCMW("application/eat+jwt", []byte(itaToken(t, pki, "kid", bound, true)), 0),
			"debuggable", true},
		{"fail binding size", o, jsonCMW("application/eat+jwt", []byte(itaToken(t, pki, "kid", bound[:32], false)), 0),
			"not the base64 encoding of 64 bytes", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newRemoteAttestationACME(t, tt.o, srv.Client())
			_, _, err := p.VerifyRemoteAttestation(context.Background(), tt.record, "")
			assert.ErrorContains(t, err, tt.wantErr)
			assert.Equal(t, tt.wantInvalid, errors.Is(err, attestation.ErrInvalidEvidence))
		})
	}
}

func TestACME_Init_remoteAttestationITA(t *testing.T) {
	for name, tt := range map[string]struct {
		o       *ACMEITA
		wantErr string
	}{
		"ok defaults":     {&ACMEITA{}, ""},
		"fail roots":      {&ACMEITA{Roots: []byte("not pem")}, "no certificates found in ita.roots"},
		"fail max age":    {&ACMEITA{MaxTokenAge: &Duration{Duration: -time.Second}}, "ita.maxTokenAge must be greater than 0"},
		"ok listed alone": {nil, ""},
	} {
		t.Run(name, func(t *testing.T) {
			p := &ACME{Type: "ACME", Name: "attested", Challenges: []ACMEChallenge{REMOTE_ATTEST_01},
				RemoteAttestation: &ACMERemoteAttestation{Formats: []attestation.Format{attestation.FormatITA}, ITA: tt.o}}
			err := p.Init(Config{Claims: globalProvisionerClaims, HTTPClient: staticHTTPClient{}})
			if tt.wantErr == "" {
				require.NoError(t, err)
				assert.Equal(t, ita.DefaultJWKSURL, p.remoteAttestation.itaKeys.URL())
			} else {
				assert.ErrorContains(t, err, tt.wantErr)
			}
		})
	}
}
