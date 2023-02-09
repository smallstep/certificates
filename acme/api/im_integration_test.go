package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
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

	"github.com/go-chi/chi"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/acme/db/nosql"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/provisioner"
	nosqlDB "github.com/smallstep/nosql"
	"go.step.sm/crypto/jose"
)

const (
	baseURL      = "test.ca.smallstep.com"
	linkerPrefix = "acme"
)

func TestIMIntegration(t *testing.T) {
	ctx := context.Background()

	// mock provisioner and linker
	ctx = acme.NewProvisionerContext(ctx, newProvWithOptions(&provisioner.Options{
		OIDC: &provisioner.OIDCOptions{
			Provider: provisioner.ProviderJSON{
				IssuerURL:   "",
				AuthURL:     "",
				TokenURL:    "",
				JWKSURL:     "",
				UserInfoURL: "",
				Algorithms:  []string{},
			},
			Config: provisioner.ConfigJSON{
				ClientID:                   "integration test",
				SupportedSigningAlgs:       []string{},
				SkipClientIDCheck:          true,
				SkipExpiryCheck:            true,
				SkipIssuerCheck:            true,
				InsecureSkipSignatureCheck: true,
				Now:                        time.Now,
			},
		},
		DPOP: &provisioner.DPOPOptions{
			ValidationExecPath: "true", // true will always exit with code 0
		},
	}))
	ctx = acme.NewLinkerContext(ctx, acme.NewLinker(baseURL, linkerPrefix))

	// create temporary BoltDB file
	file, err := os.CreateTemp(os.TempDir(), "integration-db-")
	if err != nil {
		t.Fatal("opening temporary database file:", err)
	}
	t.Log("database file name:", file.Name())
	dbFn := file.Name()
	err = file.Close()
	if err != nil {
		t.Error("closing database file:", err)
	}

	// open BoltDB
	rawDB, err := nosqlDB.New(nosqlDB.BBoltDriver, dbFn)
	if err != nil {
		t.Fatal("establishing raw db connection:", err)
	}

	// create tables
	db, err := nosql.New(rawDB)
	if err != nil {
		t.Fatal("establishing db connection:", err)
	}

	// make DB available to handlers
	ctx = acme.NewDatabaseContext(ctx, db)

	// simulate signed payloads by making the signing key available in ctx
	jwk, err := jose.GenerateJWK("OKP", "", "EdDSA", "sig", "", 0)
	if err != nil {
		t.Fatal("generating key:", err)
	}
	ed25519PrivKey, ok := jwk.Key.(ed25519.PrivateKey)
	if !ok {
		t.Fatal("failed to generate private key")
	}
	ed25519PubKey, ok := ed25519PrivKey.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("failed to extract public key")
	}
	jwk.Key = ed25519PubKey
	ctx = context.WithValue(ctx, jwkContextKey, jwk)

	// get directory
	dir := func(ctx context.Context) (dir Directory) {
		req := httptest.NewRequest(http.MethodGet, "/foo/bar", nil)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		GetDirectory(w, req)
		res := w.Result()
		if res.StatusCode != 200 {
			t.Errorf("expected 200, got %d", res.StatusCode)
		}

		body, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal("failed to read the response body:", err)
		}

		err = json.Unmarshal(bytes.TrimSpace(body), &dir)
		if err != nil {
			t.Fatal("unmarshal response body:", err)
		}
		return
	}(ctx)
	t.Log("directory:", dir)

	// get nonce
	nonce := func(ctx context.Context) (nonce string) {
		req := httptest.NewRequest(http.MethodGet, dir.NewNonce, nil).WithContext(ctx)
		w := httptest.NewRecorder()
		addNonce(GetNonce)(w, req)
		res := w.Result()
		if res.StatusCode != http.StatusNoContent {
			t.Errorf("expected %d, got %d", http.StatusNoContent, res.StatusCode)
		}

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
		if err != nil {
			t.Fatal("marshal nar:", err)
		}
		ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: rawNar})

		// create account
		req := httptest.NewRequest(http.MethodGet, dir.NewAccount, nil).WithContext(ctx)
		w := httptest.NewRecorder()
		NewAccount(w, req)

		res := w.Result()
		if res.StatusCode != http.StatusCreated {
			t.Errorf("expected %d, got %d", http.StatusCreated, res.StatusCode)
		}

		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			t.Fatal("read account payload:", err)
		}

		err = json.Unmarshal(bytes.TrimSpace(body), &acc)
		if err != nil {
			t.Fatal("unmarshal account:", err)
		}

		locationParts := strings.Split(res.Header["Location"][0], "/")
		acc, err = db.GetAccount(ctx, locationParts[len(locationParts)-1])
		if err != nil {
			t.Fatal("get account from DB:", err)
		}

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
					Value: `{"name": "Smith, Alice M (QA)", "domain": "example.com", "client-id": "impp:wireapp=75d73550-16e0-4027-abfd-0137e32180cc/ed416ce8ecdd9fad@example.com", "handle": "impp:wireapp=alice.smith.qa@example.com"}`,
				},
			},
		}
		b, err := json.Marshal(nor)
		if err != nil {
			t.Fatal("marshal new order request: ", err)
		}

		ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: b})

		req := httptest.NewRequest("POST", "https://random.local/", nil)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()
		NewOrder(w, req)

		res := w.Result()
		if res.StatusCode != http.StatusCreated {
			t.Errorf("expected %d, got %d", http.StatusCreated, res.StatusCode)
		}

		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			t.Fatal("read account payload:", err)
		}

		err = json.Unmarshal(bytes.TrimSpace(body), &order)
		if err != nil {
			t.Fatal("unmarshal order:", err)
		}

		order, err = db.GetOrder(ctx, order.ID)
		if err != nil {
			t.Fatal("get order from DB:", err)
		}

		return
	}(ctx)
	t.Log("authzs IDs:", order.AuthorizationIDs)

	// get authorization
	getAuthz := func(ctx context.Context, authzID string) (az *acme.Authorization) {
		chiCtx := chi.NewRouteContext()
		chiCtx.URLParams.Add("authzID", authzID)
		ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)

		req := httptest.NewRequest(http.MethodGet, "https://random.local/", nil).WithContext(ctx)
		w := httptest.NewRecorder()
		GetAuthorization(w, req)

		res := w.Result()
		if res.StatusCode != http.StatusOK {
			t.Errorf("expected %d, got %d", http.StatusOK, res.StatusCode)
		}

		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			t.Fatal("read account payload:", err)
		}

		err = json.Unmarshal(bytes.TrimSpace(body), &az)
		if err != nil {
			t.Fatal("unmarshal account:", err)
		}

		az, err = db.GetAuthorization(ctx, authzID)
		if err != nil {
			t.Fatal("update authorization from DB")
		}

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

			req := httptest.NewRequest(http.MethodGet, "https://random.local/", nil).WithContext(ctx)
			w := httptest.NewRecorder()
			GetChallenge(w, req)

			res := w.Result()
			if res.StatusCode != http.StatusOK {
				t.Errorf("expected %d, got %d", http.StatusOK, res.StatusCode)
			}

			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				t.Fatal("read challenge payload:", err)
			}

			err = json.Unmarshal(bytes.TrimSpace(body), &challenge)
			if err != nil {
				t.Fatal("unmarshal challenge:", err)
			}

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
		if err != nil {
			t.Fatal("update authorization from DB", err)
		}

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

		req := httptest.NewRequest(http.MethodGet, "https://random.local/", nil).WithContext(ctx)
		w := httptest.NewRecorder()
		GetOrder(w, req)

		res := w.Result()
		if res.StatusCode != http.StatusOK {
			t.Errorf("expected %d, got %d", http.StatusOK, res.StatusCode)
		}

		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			t.Fatal("read account payload:", err)
		}

		err = json.Unmarshal(bytes.TrimSpace(body), &updatedOrder)
		if err != nil {
			t.Fatal("unmarshal order:", err)
		}

		if updatedOrder.Status != acme.StatusReady {
			t.Errorf("expected %s, got %s", acme.StatusReady, updatedOrder.Status)
		}

		return
	}(ctx)
	t.Log("updated order status:", updatedOrder.Status)

	// finalise order
	finalizedOrder := func(ctx context.Context) (finalizedOrder *acme.Order) {
		mockMustAuthority(t, &mockCASigner{
			signer: func(*x509.CertificateRequest, provisioner.SignOptions, ...provisioner.SignOption) ([]*x509.Certificate, error) {
				return []*x509.Certificate{
					{SerialNumber: big.NewInt(2)},
				}, nil
			},
		})

		qUserID, err := url.Parse("impp:wireapp=75d73550-16e0-4027-abfd-0137e32180cc/ed416ce8ecdd9fad@example.com")
		if err != nil {
			t.Fatal("parse user ID URI", err)
		}
		_ = qUserID
		qUserName, err := url.Parse("impp:wireapp=alice.smith.qa@example.com")
		if err != nil {
			t.Fatal("parse user name URI", err)
		}
		_ = qUserName
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal("generate key:", err)
		}

		csrTemplate := &x509.CertificateRequest{
			Subject: pkix.Name{
				Organization: []string{"example.com"},
				CommonName:   "Smith, Alice M (QA)",
			},
			URIs: []*url.URL{
				qUserName,
				qUserID,
			},
			SignatureAlgorithm: x509.PureEd25519,
		}
		csr, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, priv)
		if err != nil {
			t.Fatal("create CSR from template:", err)
		}

		fr := FinalizeRequest{CSR: base64.RawURLEncoding.EncodeToString(csr)}
		frRaw, err := json.Marshal(fr)
		if err != nil {
			t.Fatal("encode finalize request:", err)
		}

		ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: frRaw})

		chiCtx := chi.NewRouteContext()
		chiCtx.URLParams.Add("ordID", order.ID)
		ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)

		req := httptest.NewRequest(http.MethodGet, "https://random.local/", nil).WithContext(ctx)
		w := httptest.NewRecorder()
		FinalizeOrder(w, req)

		res := w.Result()
		if res.StatusCode != http.StatusOK {
			t.Errorf("expected %d, got %d", http.StatusOK, res.StatusCode)
		}

		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			t.Fatal("read account payload:", err)
		}

		err = json.Unmarshal(bytes.TrimSpace(body), &finalizedOrder)
		if err != nil {
			t.Fatal("unmarshal order:", err)
		}

		if finalizedOrder.Status != acme.StatusValid {
			t.Errorf("expected %s, got %s", acme.StatusValid, finalizedOrder.Status)
		}

		finalizedOrder, err = db.GetOrder(ctx, order.ID)
		if err != nil {
			t.Fatal("get order from DB:", err)
		}

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
