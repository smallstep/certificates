package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/acme/db/nosql"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/authority/provisioner/wire"
	nosqlDB "github.com/smallstep/nosql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/minica"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/x509util"
)

const (
	baseURL      = "test.ca.smallstep.com"
	linkerPrefix = "acme"
)

func newWireProvisionerWithOptions(t *testing.T, options *provisioner.Options) *provisioner.ACME {
	t.Helper()
	prov := &provisioner.ACME{
		Type:    "ACME",
		Name:    "test@acme-<test>provisioner.com",
		Options: options,
		Challenges: []provisioner.ACMEChallenge{
			provisioner.WIREOIDC_01,
			provisioner.WIREDPOP_01,
		},
	}

	err := prov.Init(provisioner.Config{
		Claims: config.GlobalProvisionerClaims,
	})
	require.NoError(t, err)

	return prov
}

// TODO(hs): replace with test CA server + acmez based test client for
// more realistic integration test?
func TestWireIntegration(t *testing.T) {
	accessTokenSignerJWK, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
	require.NoError(t, err)

	accessTokenSignerPEMBlock, err := pemutil.Serialize(accessTokenSignerJWK.Public().Key)
	require.NoError(t, err)
	accessTokenSignerPEMBytes := pem.EncodeToMemory(accessTokenSignerPEMBlock)

	accessTokenSigner, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(accessTokenSignerJWK.Algorithm),
		Key:       accessTokenSignerJWK,
	}, new(jose.SignerOptions))
	require.NoError(t, err)

	oidcTokenSignerJWK, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
	require.NoError(t, err)
	oidcTokenSigner, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(oidcTokenSignerJWK.Algorithm),
		Key:       oidcTokenSignerJWK,
	}, new(jose.SignerOptions))
	require.NoError(t, err)

	prov := newWireProvisionerWithOptions(t, &provisioner.Options{
		X509: &provisioner.X509Options{
			Template: `{
				"subject": {
					"organization": "WireTest",
					"commonName": {{ toJson .Oidc.name }}
				},
				"uris": [{{ toJson .Oidc.preferred_username }}, {{ toJson .Dpop.sub }}],
				"keyUsage": ["digitalSignature"],
				"extKeyUsage": ["clientAuth"]
			}`,
		},
		Wire: &wire.Options{
			OIDC: &wire.OIDCOptions{
				Provider: &wire.Provider{
					IssuerURL:   "https://issuer.example.com",
					AuthURL:     "",
					TokenURL:    "",
					JWKSURL:     "",
					UserInfoURL: "",
					Algorithms:  []string{"ES256"},
				},
				Config: &wire.Config{
					ClientID:                   "integration test",
					SignatureAlgorithms:        []string{"ES256"},
					SkipClientIDCheck:          true,
					SkipExpiryCheck:            true,
					SkipIssuerCheck:            true,
					InsecureSkipSignatureCheck: true, // NOTE: this skips actual token verification
					Now:                        time.Now,
				},
				TransformTemplate: "",
			},
			DPOP: &wire.DPOPOptions{
				SigningKey: accessTokenSignerPEMBytes,
			},
		},
	})

	// mock provisioner and linker
	ctx := context.Background()
	ctx = acme.NewProvisionerContext(ctx, prov)
	ctx = acme.NewLinkerContext(ctx, acme.NewLinker(baseURL, linkerPrefix))

	// create temporary BoltDB file
	file, err := os.CreateTemp(os.TempDir(), "integration-db-")
	require.NoError(t, err)

	t.Log("database file name:", file.Name())
	dbFn := file.Name()
	err = file.Close()
	require.NoError(t, err)

	// open BoltDB
	rawDB, err := nosqlDB.New(nosqlDB.BBoltDriver, dbFn)
	require.NoError(t, err)

	// create tables
	db, err := nosql.New(rawDB)
	require.NoError(t, err)

	// make DB available to handlers
	ctx = acme.NewDatabaseContext(ctx, db)

	// simulate signed payloads by making the signing key available in ctx
	jwk, err := jose.GenerateJWK("OKP", "", "EdDSA", "sig", "", 0)
	require.NoError(t, err)

	ed25519PrivKey, ok := jwk.Key.(ed25519.PrivateKey)
	require.True(t, ok)

	dpopSigner, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(jwk.Algorithm),
		Key:       jwk,
	}, new(jose.SignerOptions))
	require.NoError(t, err)

	ed25519PubKey, ok := ed25519PrivKey.Public().(ed25519.PublicKey)
	require.True(t, ok)

	jwk.Key = ed25519PubKey
	ctx = context.WithValue(ctx, jwkContextKey, jwk)

	// get directory
	dir := func(ctx context.Context) (dir Directory) {
		req := httptest.NewRequest(http.MethodGet, "/foo/bar", http.NoBody)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		GetDirectory(w, req)
		res := w.Result()
		require.Equal(t, http.StatusOK, res.StatusCode)

		body, err := io.ReadAll(res.Body)
		require.NoError(t, err)

		err = json.Unmarshal(bytes.TrimSpace(body), &dir)
		require.NoError(t, err)

		return
	}(ctx)
	t.Log("directory:", dir)

	// get nonce
	nonce := func(ctx context.Context) (nonce string) {
		req := httptest.NewRequest(http.MethodGet, dir.NewNonce, http.NoBody).WithContext(ctx)
		w := httptest.NewRecorder()
		addNonce(GetNonce)(w, req)
		res := w.Result()
		require.Equal(t, http.StatusNoContent, res.StatusCode)

		nonce = res.Header["Replay-Nonce"][0]
		return
	}(ctx)
	t.Log("nonce:", nonce)

	// create new account
	acc := func(ctx context.Context) (acc *acme.Account) {
		// create payload
		nar := &NewAccountRequest{
			Contact: []string{"foo", "bar"},
		}
		rawNar, err := json.Marshal(nar)
		require.NoError(t, err)

		// create account
		ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: rawNar})
		req := httptest.NewRequest(http.MethodGet, dir.NewAccount, http.NoBody).WithContext(ctx)
		w := httptest.NewRecorder()
		NewAccount(w, req)

		res := w.Result()
		require.Equal(t, http.StatusCreated, res.StatusCode)

		body, err := io.ReadAll(res.Body)
		defer res.Body.Close()
		require.NoError(t, err)

		err = json.Unmarshal(bytes.TrimSpace(body), &acc)
		require.NoError(t, err)

		locationParts := strings.Split(res.Header["Location"][0], "/")
		acc, err = db.GetAccount(ctx, locationParts[len(locationParts)-1])
		require.NoError(t, err)

		return
	}(ctx)
	ctx = context.WithValue(ctx, accContextKey, acc)
	t.Log("account ID:", acc.ID)

	// new order
	order := func(ctx context.Context) (order *acme.Order) {
		mockMustAuthority(t, &mockCA{})
		nor := &NewOrderRequest{
			Identifiers: []acme.Identifier{
				{
					Type:  "wireapp-user",
					Value: `{"name": "Smith, Alice M (QA)", "domain": "example.com", "handle": "wireapp://%40alice.smith.qa@example.com"}`,
				},
				{
					Type:  "wireapp-device",
					Value: `{"name": "Smith, Alice M (QA)", "domain": "example.com", "client-id": "wireapp://lJGYPz0ZRq2kvc_XpdaDlA!ed416ce8ecdd9fad@example.com", "handle": "wireapp://%40alice.smith.qa@example.com"}`,
				},
			},
		}
		b, err := json.Marshal(nor)
		require.NoError(t, err)

		ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: b})
		req := httptest.NewRequest("POST", "https://random.local/", http.NoBody)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()
		NewOrder(w, req)

		res := w.Result()
		require.Equal(t, http.StatusCreated, res.StatusCode)

		body, err := io.ReadAll(res.Body)
		defer res.Body.Close()
		require.NoError(t, err)

		err = json.Unmarshal(bytes.TrimSpace(body), &order)
		require.NoError(t, err)

		order, err = db.GetOrder(ctx, order.ID)
		require.NoError(t, err)

		return
	}(ctx)
	t.Log("authzs IDs:", order.AuthorizationIDs)

	// get authorization
	getAuthz := func(ctx context.Context, authzID string) (az *acme.Authorization) {
		chiCtx := chi.NewRouteContext()
		chiCtx.URLParams.Add("authzID", authzID)
		ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)

		req := httptest.NewRequest(http.MethodGet, "https://random.local/", http.NoBody).WithContext(ctx)
		w := httptest.NewRecorder()
		GetAuthorization(w, req)

		res := w.Result()
		require.Equal(t, http.StatusOK, res.StatusCode)

		body, err := io.ReadAll(res.Body)
		defer res.Body.Close()
		require.NoError(t, err)

		err = json.Unmarshal(bytes.TrimSpace(body), &az)
		require.NoError(t, err)

		az, err = db.GetAuthorization(ctx, authzID)
		require.NoError(t, err)

		return
	}
	var azs []*acme.Authorization
	for _, azID := range order.AuthorizationIDs {
		az := getAuthz(ctx, azID)
		azs = append(azs, az)
		for _, challenge := range az.Challenges {
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("chID", challenge.ID)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)

			var payload []byte
			switch challenge.Type {
			case acme.WIREDPOP01:
				dpopBytes, err := json.Marshal(struct {
					jose.Claims
					Challenge string `json:"chal,omitempty"`
					Handle    string `json:"handle,omitempty"`
					Nonce     string `json:"nonce,omitempty"`
					HTU       string `json:"htu,omitempty"`
				}{
					Claims: jose.Claims{
						Subject: "wireapp://lJGYPz0ZRq2kvc_XpdaDlA!ed416ce8ecdd9fad@example.com",
					},
					Challenge: "token",
					Handle:    "wireapp://%40alice.smith.qa@example.com",
					Nonce:     "nonce",
					HTU:       "http://issuer.example.com",
				})
				require.NoError(t, err)
				dpop, err := dpopSigner.Sign(dpopBytes)
				require.NoError(t, err)
				proof, err := dpop.CompactSerialize()
				require.NoError(t, err)
				tokenBytes, err := json.Marshal(struct {
					jose.Claims
					Challenge string `json:"chal,omitempty"`
					Cnf       struct {
						Kid string `json:"kid,omitempty"`
					} `json:"cnf"`
					Proof      string `json:"proof,omitempty"`
					ClientID   string `json:"client_id"`
					APIVersion int    `json:"api_version"`
					Scope      string `json:"scope"`
				}{
					Claims: jose.Claims{
						Issuer:   "http://issuer.example.com",
						Audience: []string{"test"},
						Expiry:   jose.NewNumericDate(time.Now().Add(1 * time.Minute)),
					},
					Challenge: "token",
					Cnf: struct {
						Kid string `json:"kid,omitempty"`
					}{
						Kid: jwk.KeyID,
					},
					Proof:      proof,
					ClientID:   "wireapp://lJGYPz0ZRq2kvc_XpdaDlA!ed416ce8ecdd9fad@example.com",
					APIVersion: 5,
					Scope:      "wire_client_id",
				})

				require.NoError(t, err)
				signed, err := accessTokenSigner.Sign(tokenBytes)
				require.NoError(t, err)
				accessToken, err := signed.CompactSerialize()
				require.NoError(t, err)

				p, err := json.Marshal(struct {
					AccessToken string `json:"access_token"`
				}{
					AccessToken: accessToken,
				})
				require.NoError(t, err)
				payload = p
			case acme.WIREOIDC01:
				keyAuth, err := acme.KeyAuthorization("token", jwk)
				require.NoError(t, err)
				tokenBytes, err := json.Marshal(struct {
					jose.Claims
					Name              string `json:"name,omitempty"`
					PreferredUsername string `json:"preferred_username,omitempty"`
					KeyAuth           string `json:"keyauth"`
				}{
					Claims: jose.Claims{
						Issuer:   "https://issuer.example.com",
						Audience: []string{"test"},
						Expiry:   jose.NewNumericDate(time.Now().Add(1 * time.Minute)),
					},
					Name:              "Alice Smith",
					PreferredUsername: "wireapp://%40alice_wire@wire.com",
					KeyAuth:           keyAuth,
				})
				require.NoError(t, err)
				signed, err := oidcTokenSigner.Sign(tokenBytes)
				require.NoError(t, err)
				idToken, err := signed.CompactSerialize()
				require.NoError(t, err)
				p, err := json.Marshal(struct {
					IDToken string `json:"id_token"`
				}{
					IDToken: idToken,
				})
				require.NoError(t, err)
				payload = p
			default:
				require.Fail(t, "unexpected challenge payload type")
			}

			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: payload})

			req := httptest.NewRequest(http.MethodGet, "https://random.local/", http.NoBody).WithContext(ctx)
			w := httptest.NewRecorder()
			GetChallenge(w, req)

			res := w.Result()
			require.Equal(t, http.StatusOK, res.StatusCode)

			body, err := io.ReadAll(res.Body)
			defer res.Body.Close() //nolint:gocritic // close the body
			require.NoError(t, err)

			err = json.Unmarshal(bytes.TrimSpace(body), &challenge)
			require.NoError(t, err)

			t.Log("challenge:", challenge.ID, challenge.Status)
		}
	}

	// get/validate challenge simulation
	updateAz := func(ctx context.Context, az *acme.Authorization) (updatedAz *acme.Authorization) {
		now := clock.Now().Format(time.RFC3339)
		for _, challenge := range az.Challenges {
			challenge.Status = acme.StatusValid
			challenge.ValidatedAt = now
			err := db.UpdateChallenge(ctx, challenge)
			if err != nil {
				t.Error("updating challenge", challenge.ID, ":", err)
			}
		}

		updatedAz, err = db.GetAuthorization(ctx, az.ID)
		require.NoError(t, err)

		return
	}
	for _, az := range azs {
		updatedAz := updateAz(ctx, az)
		for _, challenge := range updatedAz.Challenges {
			t.Log("updated challenge:", challenge.ID, challenge.Status)
			switch challenge.Type {
			case acme.WIREOIDC01:
				err = db.CreateOidcToken(ctx, order.ID, map[string]any{"name": "Smith, Alice M (QA)", "preferred_username": "wireapp://%40alice.smith.qa@example.com"})
				require.NoError(t, err)
			case acme.WIREDPOP01:
				err = db.CreateDpopToken(ctx, order.ID, map[string]any{"sub": "wireapp://lJGYPz0ZRq2kvc_XpdaDlA!ed416ce8ecdd9fad@example.com"})
				require.NoError(t, err)
			default:
				require.Fail(t, "unexpected challenge type")
			}
		}
	}

	// get order
	updatedOrder := func(ctx context.Context) (updatedOrder *acme.Order) {
		chiCtx := chi.NewRouteContext()
		chiCtx.URLParams.Add("ordID", order.ID)
		ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)

		req := httptest.NewRequest(http.MethodGet, "https://random.local/", http.NoBody).WithContext(ctx)
		w := httptest.NewRecorder()
		GetOrder(w, req)

		res := w.Result()
		require.Equal(t, http.StatusOK, res.StatusCode)

		body, err := io.ReadAll(res.Body)
		defer res.Body.Close()
		require.NoError(t, err)

		err = json.Unmarshal(bytes.TrimSpace(body), &updatedOrder)
		require.NoError(t, err)

		require.Equal(t, acme.StatusReady, updatedOrder.Status)

		return
	}(ctx)
	t.Log("updated order status:", updatedOrder.Status)

	// finalize order
	finalizedOrder := func(ctx context.Context) (finalizedOrder *acme.Order) {
		ca, err := minica.New(minica.WithName("WireTestCA"))
		require.NoError(t, err)
		mockMustAuthority(t, &mockCASigner{
			signer: func(csr *x509.CertificateRequest, signOpts provisioner.SignOptions, extraOpts ...provisioner.SignOption) ([]*x509.Certificate, error) {
				var (
					certOptions []x509util.Option
				)
				for _, op := range extraOpts {
					if k, ok := op.(provisioner.CertificateOptions); ok {
						certOptions = append(certOptions, k.Options(signOpts)...)
					}
				}

				x509utilTemplate, err := x509util.NewCertificate(csr, certOptions...)
				require.NoError(t, err)

				template := x509utilTemplate.GetCertificate()
				require.NotNil(t, template)

				cert, err := ca.Sign(template)
				require.NoError(t, err)

				u1, err := url.Parse("wireapp://%40alice.smith.qa@example.com")
				require.NoError(t, err)
				u2, err := url.Parse("wireapp://lJGYPz0ZRq2kvc_XpdaDlA%21ed416ce8ecdd9fad@example.com")
				require.NoError(t, err)
				assert.Equal(t, []*url.URL{u1, u2}, cert.URIs)
				assert.Equal(t, "Smith, Alice M (QA)", cert.Subject.CommonName)

				return []*x509.Certificate{cert, ca.Intermediate}, nil
			},
		})

		qUserID, err := url.Parse("wireapp://lJGYPz0ZRq2kvc_XpdaDlA!ed416ce8ecdd9fad@example.com")
		require.NoError(t, err)

		qUserName, err := url.Parse("wireapp://%40alice.smith.qa@example.com")
		require.NoError(t, err)

		_, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		csrTemplate := &x509.CertificateRequest{
			Subject: pkix.Name{
				Organization: []string{"example.com"},
				ExtraNames: []pkix.AttributeTypeAndValue{
					{
						Type:  asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 3, 1, 241},
						Value: "Smith, Alice M (QA)",
					},
				},
			},
			URIs: []*url.URL{
				qUserName,
				qUserID,
			},
			SignatureAlgorithm: x509.PureEd25519,
		}

		csr, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, priv)
		require.NoError(t, err)

		fr := FinalizeRequest{CSR: base64.RawURLEncoding.EncodeToString(csr)}
		frRaw, err := json.Marshal(fr)
		require.NoError(t, err)

		ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: frRaw})

		chiCtx := chi.NewRouteContext()
		chiCtx.URLParams.Add("ordID", order.ID)
		ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)

		req := httptest.NewRequest(http.MethodGet, "https://random.local/", http.NoBody).WithContext(ctx)
		w := httptest.NewRecorder()
		FinalizeOrder(w, req)

		res := w.Result()
		require.Equal(t, http.StatusOK, res.StatusCode)

		body, err := io.ReadAll(res.Body)
		defer res.Body.Close()
		require.NoError(t, err)

		err = json.Unmarshal(bytes.TrimSpace(body), &finalizedOrder)
		require.NoError(t, err)

		require.Equal(t, acme.StatusValid, finalizedOrder.Status)

		finalizedOrder, err = db.GetOrder(ctx, order.ID)
		require.NoError(t, err)

		return
	}(ctx)
	t.Log("finalized order status:", finalizedOrder.Status)
}

type mockCASigner struct {
	signer func(*x509.CertificateRequest, provisioner.SignOptions, ...provisioner.SignOption) ([]*x509.Certificate, error)
}

func (m *mockCASigner) SignWithContext(_ context.Context, cr *x509.CertificateRequest, opts provisioner.SignOptions, signOpts ...provisioner.SignOption) ([]*x509.Certificate, error) {
	if m.signer == nil {
		return nil, errors.New("unimplemented")
	}
	return m.signer(cr, opts, signOpts...)
}

func (m *mockCASigner) AreSANsAllowed(ctx context.Context, sans []string) error {
	return nil
}

func (m *mockCASigner) IsRevoked(sn string) (bool, error) {
	return false, nil
}

func (m *mockCASigner) Revoke(ctx context.Context, opts *authority.RevokeOptions) error {
	return nil
}

func (m *mockCASigner) LoadProvisionerByName(string) (provisioner.Interface, error) {
	return nil, nil
}

func (m *mockCASigner) GetBackdate() *time.Duration {
	return nil
}
