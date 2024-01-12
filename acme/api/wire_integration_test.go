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
	"errors"
	"io"
	"math/big"
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
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/authority/provisioner/wire"
	nosqlDB "github.com/smallstep/nosql"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/jose"
)

const (
	baseURL      = "test.ca.smallstep.com"
	linkerPrefix = "acme"
)

func newWireProvisionerWithOptions(t *testing.T, options *provisioner.Options) *provisioner.ACME {
	p := newProvWithOptions(options)
	a, ok := p.(*provisioner.ACME)
	if !ok {
		t.Fatal("not a valid ACME provisioner")
	}
	a.Challenges = []provisioner.ACMEChallenge{
		provisioner.WIREOIDC_01,
		provisioner.WIREDPOP_01,
	}
	return a
}

func TestWireIntegration(t *testing.T) {
	fakeKey := `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA5c+4NKZSNQcR1T8qN6SjwgdPZQ0Ge12Ylx/YeGAJ35k=
-----END PUBLIC KEY-----`
	prov := newWireProvisionerWithOptions(t, &provisioner.Options{
		Wire: &wire.Options{
			OIDC: &wire.OIDCOptions{
				Provider: &wire.Provider{
					IssuerURL:   "https://issuer.example.com",
					AuthURL:     "",
					TokenURL:    "",
					JWKSURL:     "",
					UserInfoURL: "",
					Algorithms:  []string{},
				},
				Config: &wire.Config{
					ClientID:                   "integration test",
					SignatureAlgorithms:        []string{},
					SkipClientIDCheck:          true,
					SkipExpiryCheck:            true,
					SkipIssuerCheck:            true,
					InsecureSkipSignatureCheck: true,
					Now:                        time.Now,
				},
			},
			DPOP: &wire.DPOPOptions{
				SigningKey: []byte(fakeKey),
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
					Type:  "wireapp-id",
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
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: nil})

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
		mockMustAuthority(t, &mockCASigner{
			signer: func(*x509.CertificateRequest, provisioner.SignOptions, ...provisioner.SignOption) ([]*x509.Certificate, error) {
				return []*x509.Certificate{
					{SerialNumber: big.NewInt(2)},
				}, nil
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

		// TODO(hs): move these to a more appropriate place and/or provide more realistic value
		err = db.CreateDpopToken(ctx, order.ID, map[string]any{"fake-dpop": "dpop-value"})
		require.NoError(t, err)
		err = db.CreateOidcToken(ctx, order.ID, map[string]any{"fake-oidc": "oidc-value"})
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

func (m *mockCASigner) Sign(cr *x509.CertificateRequest, opts provisioner.SignOptions, signOpts ...provisioner.SignOption) ([]*x509.Certificate, error) {
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
