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
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// testBinding returns the binding the evidence of a challenge with the given
// key authorization carries for the CSR's key.
func testBinding(keyAuth string, csr *x509.CertificateRequest) []byte {
	sum := sha256.Sum256(append([]byte(keyAuth), csr.RawSubjectPublicKeyInfo...))
	return sum[:]
}

func TestRemoteAttestationBinding(t *testing.T) {
	csr, _ := mustCSR(t, "")
	want := testBinding("nonce.thumbprint", csr)
	assert.Equal(t, hex.EncodeToString(want), RemoteAttestationBinding("nonce.thumbprint", csr))
	assert.NotEqual(t, hex.EncodeToString(want), RemoteAttestationBinding("other.thumbprint", csr))
}

func TestRemoteAttest01Validate(t *testing.T) {
	jwk, keyAuth := mustAccountAndKeyAuthorization(t, testFreshnessNonce)
	csr, _ := mustCSR(t, "")
	binding := testBinding(keyAuth, csr)
	claimNonce := make([]byte, 32)
	for i := range claimNonce {
		claimNonce[i] = byte(i)
	}
	csResult := &attestation.Result{
		Format:            attestation.FormatConfidentialSpace,
		MediaType:         "application/eat+jwt",
		Evidence:          []byte("token"),
		ConfidentialSpace: &attestation.ConfidentialSpace{Claims: map[string]any{"hwmodel": "GCP_INTEL_TDX"}},
	}
	tdxResult := &attestation.Result{Format: attestation.FormatTDX, TDX: &attestation.TDX{MRTD: "aa"}}

	type want struct {
		status     Status
		errType    string
		errDetail  string
		err        string
		stored     bool
		format     string
		claimNonce string
		result     *attestation.Result
	}
	tests := []struct {
		name    string
		payload []byte
		nonce   string
		verify  func(context.Context, *cmw.Record, string) (*attestation.Result, []byte, error)
		az      func(az *Authorization)
		want    want
	}{
		{"ok confidential space", testRemoteAttestationCMW, testFreshnessNonce,
			func(_ context.Context, r *cmw.Record, aud string) (*attestation.Result, []byte, error) {
				assert.Equal(t, "application/eat+jwt", r.MediaType)
				assert.Equal(t, "https://ca.example.com/acme/acme/directory", aud)
				return csResult, binding, nil
			}, nil, want{status: StatusValid, stored: true, format: "confidential-space", result: csResult}},
		// A quote's report data carries the relying party's claim nonce after
		// the binding.
		{"ok tdx with claim nonce", testRemoteAttestationCMW, testFreshnessNonce,
			func(context.Context, *cmw.Record, string) (*attestation.Result, []byte, error) {
				return tdxResult, append(append([]byte(nil), binding...), claimNonce...), nil
			}, nil, want{status: StatusValid, stored: true, format: "tdx", result: tdxResult,
				claimNonce: base64.RawURLEncoding.EncodeToString(claimNonce)}},
		// The binding is checked when the order is finalized, so evidence
		// with any binding validates the challenge.
		{"ok binding checked at finalize", testRemoteAttestationCMW, testFreshnessNonce,
			func(context.Context, *cmw.Record, string) (*attestation.Result, []byte, error) {
				return csResult, make([]byte, 32), nil
			}, nil, want{status: StatusValid, stored: true, format: "confidential-space", result: csResult}},
		{"ok empty payload", nil, testFreshnessNonce, nil, nil, want{status: StatusPending}},
		{"ok empty object", []byte(" {} "), testFreshnessNonce, nil, nil, want{status: StatusPending}},
		{"fail no nonce", testRemoteAttestationCMW, "", nil, nil, want{status: StatusPending, err: "has no freshness nonce"}},
		{"fail malformed", []byte(`["application/eat+jwt"]`), testFreshnessNonce, nil, nil,
			want{status: StatusPending, err: "must have 2 or 3 elements"}},
		{"fail invalid evidence", testRemoteAttestationCMW, testFreshnessNonce,
			func(context.Context, *cmw.Record, string) (*attestation.Result, []byte, error) {
				return nil, nil, attestation.Invalidf("attestation token dbgstat is %q", "enabled")
			}, nil, want{status: StatusInvalid, errType: "badAttestationStatement", errDetail: `attestation token dbgstat is "enabled"`}},
		{"fail verifier", testRemoteAttestationCMW, testFreshnessNonce,
			func(context.Context, *cmw.Record, string) (*attestation.Result, []byte, error) {
				return nil, nil, errors.New("error fetching tdx collateral")
			}, nil, want{status: StatusPending, err: "error verifying remote attestation"}},
		{"fail bound size", testRemoteAttestationCMW, testFreshnessNonce,
			func(context.Context, *cmw.Record, string) (*attestation.Result, []byte, error) {
				return csResult, binding[:16], nil
			}, nil, want{status: StatusPending, err: "binds 16 bytes"}},
		// The challenge is requested under an authorization from the URL; the
		// attestation must not land on one that does not hold the challenge.
		{"fail challenge of another authorization", testRemoteAttestationCMW, testFreshnessNonce,
			func(context.Context, *cmw.Record, string) (*attestation.Result, []byte, error) {
				return csResult, binding, nil
			}, func(az *Authorization) { az.Challenges = []*Challenge{{ID: "otherChID"}} },
			want{status: StatusPending, err: "does not belong to authorization"}},
		{"fail authorization of another account", testRemoteAttestationCMW, testFreshnessNonce,
			func(context.Context, *cmw.Record, string) (*attestation.Result, []byte, error) {
				return csResult, binding, nil
			}, func(az *Authorization) { az.AccountID = "otherAccID" },
			want{status: StatusPending, err: "does not belong to authorization"}},
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
					az := &Authorization{
						ID: id, AccountID: "accID", Identifier: Identifier{Type: RemoteAttestation, Value: "measured_boot"},
						Challenges: []*Challenge{{ID: "chID"}},
					}
					if tt.az != nil {
						tt.az(az)
					}
					return az, nil
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
				AccountID:       "accID",
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
			assert.Equal(t, tt.want.format, ch.PayloadFormat)
			require.NotNil(t, updatedAz)
			require.NotNil(t, updatedAz.Attestation)
			att := updatedAz.Attestation
			assert.Equal(t, "remote-attest-01", att.Challenge)
			assert.Equal(t, "measured_boot", att.Hint)
			assert.Equal(t, testFreshnessNonce, att.FreshnessNonce)
			assert.Equal(t, keyAuth, att.KeyAuthorization)
			assert.Len(t, att.BindingDigest, 64)
			assert.Equal(t, tt.want.claimNonce, att.ClaimNonce)
			assert.Nil(t, att.Account, "the account is added at finalize")
			assert.Equal(t, tt.want.result, att.Result)
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
	newAtt := func(keyAuth string, csr *x509.CertificateRequest) *webhook.Attestation {
		return &webhook.Attestation{
			Challenge:        "remote-attest-01",
			KeyAuthorization: keyAuth,
			BindingDigest:    hex.EncodeToString(testBinding(keyAuth, csr)),
		}
	}
	att := newAtt("nonce.thumbprint", csr)
	otherKeyAtt := newAtt("nonce.thumbprint", otherCSR)
	// The binding is stored with one key authorization but was computed with
	// another, as evidence replayed from another challenge or account would be.
	replayedAtt := newAtt("nonce.thumbprint", csr)
	replayedAtt.KeyAuthorization = "other-nonce.other-thumbprint"

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
		{"fail attestation of another key", map[string]*Authorization{"az1": {}, "az2": {Attestation: otherKeyAtt}}, nil,
			"csr does not match the attested key"},
		{"fail replayed evidence", map[string]*Authorization{"az1": {}, "az2": {Attestation: replayedAtt}}, nil,
			"csr does not match the attested key"},
		{"fail attestation without key authorization", map[string]*Authorization{"az1": {Attestation: &webhook.Attestation{}}, "az2": {}}, nil,
			"csr does not match the attested key"},
		// A remote-attestation authorization made valid without its
		// challenge's attestation (a lost update, a challenge requested under
		// another authorization) fails closed.
		{"fail remote attestation without attestation", map[string]*Authorization{
			"az1": {Identifier: Identifier{Type: RemoteAttestation}}, "az2": {},
		}, nil, "has no attestation for its remote-attestation identifier"},
		// Every attested key is checked, not only the first one found.
		{"fail second fingerprint", map[string]*Authorization{"az1": {Fingerprint: fp}, "az2": {Fingerprint: otherFP}}, nil,
			"csr does not match the attested key"},
		{"fail attestation after fingerprint", map[string]*Authorization{"az1": {Fingerprint: fp}, "az2": {Attestation: otherKeyAtt}}, nil,
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
// identifier is remote-attestation: the CSR names nothing, the binding is
// checked against the CSR's key, and the attestation, with the account and its
// EAB key, reaches the template data and the bodies of the webhook requests.
func TestOrder_Finalize_remoteAttestation(t *testing.T) {
	csr, _ := mustCSR(t, "")
	newAtt := func() *webhook.Attestation {
		return &webhook.Attestation{
			Challenge:        "remote-attest-01",
			KeyAuthorization: "nonce.thumbprint",
			BindingDigest:    hex.EncodeToString(testBinding("nonce.thumbprint", csr)),
			ClaimNonce:       "claim",
			Result:           &attestation.Result{Format: attestation.FormatTDX, TDX: &attestation.TDX{MRTD: "aa"}},
		}
	}

	newOrder := func() *Order {
		return &Order{
			ID:               "orderID",
			AccountID:        "accID",
			ProvisionerID:    "provID",
			Status:           StatusReady,
			ExpiresAt:        time.Now().Add(time.Hour),
			Identifiers:      []Identifier{{Type: RemoteAttestation}},
			AuthorizationIDs: []string{"azID"},
		}
	}
	newDB := func(eak *ExternalAccountKey, eakErr error) *MockDB {
		return &MockDB{
			MockGetAuthorization: func(_ context.Context, id string) (*Authorization, error) {
				return &Authorization{ID: id, Status: StatusValid, Attestation: newAtt()}, nil
			},
			MockGetExternalAccountKeyByAccountID: func(_ context.Context, provisionerID, accountID string) (*ExternalAccountKey, error) {
				assert.Equal(t, "provID", provisionerID)
				assert.Equal(t, "accID", accountID)
				return eak, eakErr
			},
			MockCreateCertificate: func(_ context.Context, cert *Certificate) error {
				cert.ID = "certID"
				return nil
			},
			MockUpdateOrder: func(context.Context, *Order) error { return nil },
		}
	}
	newProv := func(requireEAB bool) *MockProvisioner {
		return &MockProvisioner{
			MauthorizeSign: func(context.Context, string) ([]provisioner.SignOption, error) {
				return []provisioner.SignOption{&provisioner.WebhookController{}}, nil
			},
			MgetOptions:    func() *provisioner.Options { return nil },
			MisEABRequired: func() bool { return requireEAB },
		}
	}
	prov, eabProv := newProv(false), newProv(true)
	signAndCheck := func(t *testing.T, wantAccount *webhook.AttestationAccount) *mockSignAuth {
		leaf, intermediate := &x509.Certificate{Raw: []byte("leaf")}, &x509.Certificate{Raw: []byte("intermediate")}
		return &mockSignAuth{
			signWithContext: func(ctx context.Context, _ *x509.CertificateRequest, _ provisioner.SignOptions, opts ...provisioner.SignOption) ([]*x509.Certificate, error) {
				var wc *provisioner.WebhookController
				for _, o := range opts {
					if c, ok := o.(*provisioner.WebhookController); ok {
						wc = c
					}
				}
				require.NotNil(t, wc)
				want := newAtt()
				want.Account = wantAccount
				data, ok := wc.TemplateData.(x509util.TemplateData)
				require.True(t, ok)
				assert.Equal(t, want, data["Attestation"])
				assert.Empty(t, data[x509util.SANsKey])

				req := &webhook.RequestBody{}
				require.NoError(t, wc.Enrich(ctx, req))
				assert.Equal(t, want, req.Attestation)
				return []*x509.Certificate{leaf, intermediate}, nil
			},
		}
	}

	t.Run("ok without eab", func(t *testing.T) {
		// A provisioner without EAB never reads the key, which some databases
		// report as missing with an error.
		o := newOrder()
		require.NoError(t, o.Finalize(context.Background(), newDB(nil, errors.New("not found")), csr, signAndCheck(t, &webhook.AttestationAccount{ID: "accID"}), prov))
		assert.Equal(t, StatusValid, o.Status)
		assert.Equal(t, "certID", o.CertificateID)
	})

	t.Run("ok with eab", func(t *testing.T) {
		eak := &ExternalAccountKey{ID: "eakID", Reference: "machine-1", AccountID: "accID"}
		o := newOrder()
		require.NoError(t, o.Finalize(context.Background(), newDB(eak, nil), csr, signAndCheck(t, &webhook.AttestationAccount{
			ID: "accID", ExternalAccountKeyID: "eakID", Reference: "machine-1",
		}), eabProv))
		assert.Equal(t, StatusValid, o.Status)
	})

	t.Run("fail eab lookup", func(t *testing.T) {
		err := newOrder().Finalize(context.Background(), newDB(nil, errors.New("force")), csr, &mockSignAuth{}, eabProv)
		assert.ErrorContains(t, err, "error getting the external account key")
	})

	t.Run("fail other key", func(t *testing.T) {
		other, _ := mustCSR(t, "")
		err := newOrder().Finalize(context.Background(), newDB(nil, nil), other, &mockSignAuth{}, prov)
		assert.ErrorContains(t, err, "csr does not match the attested key")
	})

	t.Run("fail common name", func(t *testing.T) {
		// The order names nothing, so the CSR cannot name anything either.
		named := mustCSRWithKeyOf(t, csr, "workload.example.com")
		err := newOrder().Finalize(context.Background(), newDB(nil, nil), named, &mockSignAuth{}, prov)
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
