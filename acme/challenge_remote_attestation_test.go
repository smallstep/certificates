package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/x509util"

	"github.com/smallstep/certificates/attestation"
	"github.com/smallstep/certificates/attestation/cmw"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/webhook"
)

const testFreshnessNonce = "yoW1RL2zPBzYEHBQ06Jy"

// testRemoteAttestationCMW is a valid CMW record; the provisioner mocks decide
// what it verifies to.
var testRemoteAttestationCMW = []byte(`["application/eat+jwt", "ZXlKaGJHY2lPaUpTVXpJMU5pSjku", 8]`)

func mustCSR(t *testing.T, cn string) (*x509.CertificateRequest, crypto.Signer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(der)
	require.NoError(t, err)
	return csr, key
}

// testBoundData returns the data the evidence of a challenge with the given
// account key binds, for the given CSR's key.
func testBoundData(t *testing.T, jwk *jose.JSONWebKey, csr *x509.CertificateRequest) []byte {
	t.Helper()
	keyAuth, err := KeyAuthorization(testFreshnessNonce, jwk)
	require.NoError(t, err)
	ka := sha256.Sum256([]byte(keyAuth))
	key := sha256.Sum256(csr.RawSubjectPublicKeyInfo)
	return append(ka[:], key[:]...)
}

func TestRemoteAttest01Validate(t *testing.T) {
	jwk, _ := mustAccountAndKeyAuthorization(t, testFreshnessNonce)
	csr, _ := mustCSR(t, "")
	bound := testBoundData(t, jwk, csr)
	result := &attestation.Result{
		Format:            attestation.FormatConfidentialSpace,
		MediaType:         "application/eat+jwt",
		Evidence:          []byte("token"),
		ConfidentialSpace: &attestation.ConfidentialSpace{Claims: map[string]any{"hwmodel": "GCP_INTEL_TDX"}},
	}

	type want struct {
		status    Status
		errType   string
		errDetail string
		err       string
		stored    bool
	}
	tests := []struct {
		name    string
		payload []byte
		nonce   string
		verify  func(context.Context, *cmw.Record, string) (*attestation.Result, []byte, error)
		want    want
	}{
		{"ok", testRemoteAttestationCMW, testFreshnessNonce,
			func(_ context.Context, r *cmw.Record, aud string) (*attestation.Result, []byte, error) {
				assert.Equal(t, "application/eat+jwt", r.MediaType)
				assert.Equal(t, "https://ca.example.com/acme/acme/directory", aud)
				return result, bound, nil
			}, want{status: StatusValid, stored: true}},
		{"ok empty payload", nil, testFreshnessNonce, nil, want{status: StatusPending}},
		{"ok empty object", []byte(" {} "), testFreshnessNonce, nil, want{status: StatusPending}},
		{"fail no nonce", testRemoteAttestationCMW, "", nil, want{status: StatusPending, err: "has no freshness nonce"}},
		{"fail malformed", []byte(`["application/eat+jwt"]`), testFreshnessNonce, nil,
			want{status: StatusPending, err: "must have 2 or 3 elements"}},
		{"fail invalid evidence", testRemoteAttestationCMW, testFreshnessNonce,
			func(context.Context, *cmw.Record, string) (*attestation.Result, []byte, error) {
				return nil, nil, attestation.Invalidf("attestation token dbgstat is %q", "enabled")
			}, want{status: StatusInvalid, errType: "badAttestationStatement", errDetail: `attestation token dbgstat is "enabled"`}},
		{"fail verifier", testRemoteAttestationCMW, testFreshnessNonce,
			func(context.Context, *cmw.Record, string) (*attestation.Result, []byte, error) {
				return nil, nil, errors.New("error fetching tdx collateral")
			}, want{status: StatusPending, err: "error verifying remote attestation"}},
		{"fail bound size", testRemoteAttestationCMW, testFreshnessNonce,
			func(context.Context, *cmw.Record, string) (*attestation.Result, []byte, error) {
				return result, bound[:32], nil
			}, want{status: StatusPending, err: "binds 32 bytes"}},
		{"fail key authorization", testRemoteAttestationCMW, testFreshnessNonce,
			func(context.Context, *cmw.Record, string) (*attestation.Result, []byte, error) {
				other := append([]byte(nil), bound...)
				other[0] ^= 1
				return result, other, nil
			}, want{status: StatusInvalid, errType: "badAttestationStatement", errDetail: "does not bind the key authorization"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				updatedAz *Authorization
				updatedCh *Challenge
			)
			db := &MockDB{
				MockGetAuthorization: func(_ context.Context, id string) (*Authorization, error) {
					assert.Equal(t, "azID", id)
					return &Authorization{ID: id, Identifier: Identifier{Type: RemoteAttestation, Value: "measured_boot"}}, nil
				},
				MockUpdateAuthorization: func(_ context.Context, az *Authorization) error {
					updatedAz = az
					return nil
				},
				MockUpdateChallenge: func(_ context.Context, ch *Challenge) error {
					updatedCh = ch
					return nil
				},
			}
			prov := &MockProvisioner{
				MgetName:                 func() string { return "acme" },
				MverifyRemoteAttestation: tt.verify,
			}
			ctx := NewProvisionerContext(context.Background(), prov)
			ctx = NewLinkerContext(ctx, NewLinker("ca.example.com", "acme"))
			ch := &Challenge{
				ID:              "chID",
				AuthorizationID: "azID",
				Type:            REMOTEATTEST01,
				Status:          StatusPending,
				Token:           "token",
				FreshnessNonce:  tt.nonce,
			}

			err := ch.Validate(ctx, db, jwk, tt.payload)
			if tt.want.err != "" {
				assert.ErrorContains(t, err, tt.want.err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.want.status, ch.Status)

			if tt.want.errType != "" {
				require.NotNil(t, updatedCh)
				require.NotNil(t, ch.Error)
				assert.Equal(t, "urn:ietf:params:acme:error:"+tt.want.errType, ch.Error.Type)
				assert.Contains(t, ch.Error.Detail, tt.want.errDetail)
				assert.Nil(t, updatedAz)
				return
			}
			if !tt.want.stored {
				assert.Nil(t, updatedAz)
				assert.Nil(t, updatedCh)
				return
			}

			require.NotNil(t, updatedCh)
			assert.Nil(t, ch.Error)
			assert.NotEmpty(t, ch.ValidatedAt)
			assert.Equal(t, "confidential-space", ch.PayloadFormat)
			require.NotNil(t, updatedAz)
			require.NotNil(t, updatedAz.Attestation)
			att := updatedAz.Attestation
			assert.Equal(t, "remote-attest-01", att.Challenge)
			assert.Equal(t, "measured_boot", att.Hint)
			assert.Equal(t, testFreshnessNonce, att.FreshnessNonce)
			assert.Equal(t, hex.EncodeToString(bound[:32]), att.KeyAuthorizationDigest)
			assert.Equal(t, remoteAttestationKeyDigest(csr), att.KeyDigest)
			assert.Equal(t, result, att.Result)
		})
	}
}

func TestOrder_checkAttestedKeys(t *testing.T) {
	csr, _ := mustCSR(t, "")
	otherCSR, _ := mustCSR(t, "")
	fp, err := keyutil.Fingerprint(csr.PublicKey)
	require.NoError(t, err)
	otherFP, err := keyutil.Fingerprint(otherCSR.PublicKey)
	require.NoError(t, err)
	att := &webhook.Attestation{Challenge: "remote-attest-01", KeyDigest: remoteAttestationKeyDigest(csr)}
	otherAtt := &webhook.Attestation{Challenge: "remote-attest-01", KeyDigest: remoteAttestationKeyDigest(otherCSR)}

	tests := []struct {
		name    string
		azs     map[string]*Authorization
		want    *webhook.Attestation
		wantErr string
	}{
		{"ok none", map[string]*Authorization{"az1": {}, "az2": {}}, nil, ""},
		{"ok fingerprint", map[string]*Authorization{"az1": {}, "az2": {Fingerprint: fp}}, nil, ""},
		{"ok attestation", map[string]*Authorization{"az1": {}, "az2": {Attestation: att}}, att, ""},
		{"ok both", map[string]*Authorization{"az1": {Fingerprint: fp}, "az2": {Attestation: att}}, att, ""},
		{"fail fingerprint", map[string]*Authorization{"az1": {Fingerprint: otherFP}, "az2": {}}, nil, "csr does not match the attested key"},
		{"fail attestation", map[string]*Authorization{"az1": {}, "az2": {Attestation: otherAtt}}, nil, "csr does not match the attested key"},
		{"fail attestation without digest", map[string]*Authorization{"az1": {Attestation: &webhook.Attestation{}}, "az2": {}}, nil,
			"csr does not match the attested key"},
		// Every attested key is checked, not only the first one found.
		{"fail second fingerprint", map[string]*Authorization{"az1": {Fingerprint: fp}, "az2": {Fingerprint: otherFP}}, nil,
			"csr does not match the attested key"},
		{"fail attestation after fingerprint", map[string]*Authorization{"az1": {Fingerprint: fp}, "az2": {Attestation: otherAtt}}, nil,
			"csr does not match the attested key"},
		{"fail db", map[string]*Authorization{"az1": nil}, nil, "error getting authorization"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &Order{ID: "orderID", AuthorizationIDs: []string{"az1", "az2"}}
			db := &MockDB{
				MockGetAuthorization: func(_ context.Context, id string) (*Authorization, error) {
					az, ok := tt.azs[id]
					if !ok || az == nil {
						return nil, errors.New("force")
					}
					return az, nil
				},
			}
			got, err := o.checkAttestedKeys(context.Background(), db, csr)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestOrder_Finalize_remoteAttestation finalizes an order whose only
// identifier is remote-attestation: the CSR names nothing, and the attestation
// reaches the template data and the bodies of the webhook requests.
func TestOrder_Finalize_remoteAttestation(t *testing.T) {
	csr, _ := mustCSR(t, "")
	att := &webhook.Attestation{
		Challenge: "remote-attest-01",
		KeyDigest: remoteAttestationKeyDigest(csr),
		Result:    &attestation.Result{Format: attestation.FormatTDX, TDX: &attestation.TDX{MRTD: "aa"}},
	}

	newOrder := func() *Order {
		return &Order{
			ID:               "orderID",
			AccountID:        "accID",
			Status:           StatusReady,
			ExpiresAt:        time.Now().Add(time.Hour),
			Identifiers:      []Identifier{{Type: RemoteAttestation}},
			AuthorizationIDs: []string{"azID"},
		}
	}
	db := &MockDB{
		MockGetAuthorization: func(_ context.Context, id string) (*Authorization, error) {
			return &Authorization{ID: id, Status: StatusValid, Attestation: att}, nil
		},
		MockCreateCertificate: func(_ context.Context, cert *Certificate) error {
			cert.ID = "certID"
			return nil
		},
		MockUpdateOrder: func(context.Context, *Order) error { return nil },
	}
	prov := &MockProvisioner{
		MauthorizeSign: func(context.Context, string) ([]provisioner.SignOption, error) {
			return []provisioner.SignOption{&provisioner.WebhookController{}}, nil
		},
		MgetOptions: func() *provisioner.Options { return nil },
	}

	t.Run("ok", func(t *testing.T) {
		leaf, intermediate := &x509.Certificate{Raw: []byte("leaf")}, &x509.Certificate{Raw: []byte("intermediate")}
		ca := &mockSignAuth{
			signWithContext: func(ctx context.Context, _ *x509.CertificateRequest, _ provisioner.SignOptions, opts ...provisioner.SignOption) ([]*x509.Certificate, error) {
				var wc *provisioner.WebhookController
				for _, o := range opts {
					if c, ok := o.(*provisioner.WebhookController); ok {
						wc = c
					}
				}
				require.NotNil(t, wc)
				data, ok := wc.TemplateData.(x509util.TemplateData)
				require.True(t, ok)
				assert.Equal(t, att, data["Attestation"])
				assert.Empty(t, data[x509util.SANsKey])

				req := &webhook.RequestBody{}
				require.NoError(t, wc.Enrich(ctx, req))
				assert.Equal(t, att, req.Attestation)
				return []*x509.Certificate{leaf, intermediate}, nil
			},
		}
		o := newOrder()
		require.NoError(t, o.Finalize(context.Background(), db, csr, ca, prov))
		assert.Equal(t, StatusValid, o.Status)
		assert.Equal(t, "certID", o.CertificateID)
	})

	t.Run("fail other key", func(t *testing.T) {
		other, _ := mustCSR(t, "")
		err := newOrder().Finalize(context.Background(), db, other, &mockSignAuth{}, prov)
		assert.ErrorContains(t, err, "csr does not match the attested key")
	})

	t.Run("fail common name", func(t *testing.T) {
		// The order names nothing, so the CSR cannot name anything either.
		named := mustCSRWithKeyOf(t, csr, "workload.example.com")
		err := newOrder().Finalize(context.Background(), db, named, &mockSignAuth{}, prov)
		var acmeErr *Error
		require.ErrorAs(t, err, &acmeErr)
		assert.Equal(t, "urn:ietf:params:acme:error:badCSR", acmeErr.Type)
	})
}

// mustCSRWithKeyOf returns a CSR whose public key is the one of csr, with the
// given common name. Its signature is not valid, which Finalize does not check.
func mustCSRWithKeyOf(t *testing.T, csr *x509.CertificateRequest, cn string) *x509.CertificateRequest {
	t.Helper()
	named := *csr
	named.Subject = pkix.Name{CommonName: cn}
	return &named
}
