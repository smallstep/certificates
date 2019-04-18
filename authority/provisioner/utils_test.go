package provisioner

import (
	"crypto"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/smallstep/cli/crypto/randutil"
	"github.com/smallstep/cli/jose"
)

var testAudiences = Audiences{
	Sign:   []string{"https://ca.smallstep.com/sign", "https://ca.smallstep.com/1.0/sign"},
	Revoke: []string{"https://ca.smallstep.com/revoke", "https://ca.smallstep.com/1.0/revoke"},
}

func must(args ...interface{}) []interface{} {
	if l := len(args); l > 0 && args[l-1] != nil {
		if err, ok := args[l-1].(error); ok {
			panic(err)
		}
	}
	return args
}

func generateJSONWebKey() (*jose.JSONWebKey, error) {
	jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
	if err != nil {
		return nil, err
	}
	fp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	jwk.KeyID = string(hex.EncodeToString(fp))
	return jwk, nil
}

func generateJSONWebKeySet(n int) (jose.JSONWebKeySet, error) {
	var keySet jose.JSONWebKeySet
	for i := 0; i < n; i++ {
		key, err := generateJSONWebKey()
		if err != nil {
			return jose.JSONWebKeySet{}, err
		}
		keySet.Keys = append(keySet.Keys, *key)
	}
	return keySet, nil
}

func encryptJSONWebKey(jwk *jose.JSONWebKey) (*jose.JSONWebEncryption, error) {
	b, err := json.Marshal(jwk)
	if err != nil {
		return nil, err
	}
	salt, err := randutil.Salt(jose.PBKDF2SaltSize)
	if err != nil {
		return nil, err
	}
	opts := new(jose.EncrypterOptions)
	opts.WithContentType(jose.ContentType("jwk+json"))
	recipient := jose.Recipient{
		Algorithm:  jose.PBES2_HS256_A128KW,
		Key:        []byte("password"),
		PBES2Count: jose.PBKDF2Iterations,
		PBES2Salt:  salt,
	}
	encrypter, err := jose.NewEncrypter(jose.DefaultEncAlgorithm, recipient, opts)
	if err != nil {
		return nil, err
	}
	return encrypter.Encrypt(b)
}

func decryptJSONWebKey(key string) (*jose.JSONWebKey, error) {
	enc, err := jose.ParseEncrypted(key)
	if err != nil {
		return nil, err
	}
	b, err := enc.Decrypt([]byte("password"))
	if err != nil {
		return nil, err
	}
	jwk := new(jose.JSONWebKey)
	if err := json.Unmarshal(b, jwk); err != nil {
		return nil, err
	}
	return jwk, nil
}

func generateJWK() (*JWK, error) {
	name, err := randutil.Alphanumeric(10)
	if err != nil {
		return nil, err
	}
	jwk, err := generateJSONWebKey()
	if err != nil {
		return nil, err
	}
	jwe, err := encryptJSONWebKey(jwk)
	if err != nil {
		return nil, err
	}
	public := jwk.Public()
	encrypted, err := jwe.CompactSerialize()
	if err != nil {
		return nil, err
	}
	claimer, err := NewClaimer(nil, globalProvisionerClaims)
	if err != nil {
		return nil, err
	}
	return &JWK{
		Name:         name,
		Type:         "JWK",
		Key:          &public,
		EncryptedKey: encrypted,
		Claims:       &globalProvisionerClaims,
		audiences:    testAudiences,
		claimer:      claimer,
	}, nil
}

func generateOIDC() (*OIDC, error) {
	name, err := randutil.Alphanumeric(10)
	if err != nil {
		return nil, err
	}
	clientID, err := randutil.Alphanumeric(10)
	if err != nil {
		return nil, err
	}
	issuer, err := randutil.Alphanumeric(10)
	if err != nil {
		return nil, err
	}
	jwk, err := generateJSONWebKey()
	if err != nil {
		return nil, err
	}
	claimer, err := NewClaimer(nil, globalProvisionerClaims)
	if err != nil {
		return nil, err
	}
	return &OIDC{
		Name:                  name,
		Type:                  "OIDC",
		ClientID:              clientID,
		ConfigurationEndpoint: "https://example.com/.well-known/openid-configuration",
		Claims:                &globalProvisionerClaims,
		configuration: openIDConfiguration{
			Issuer:    issuer,
			JWKSetURI: "https://example.com/.well-known/jwks",
		},
		keyStore: &keyStore{
			keySet: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{*jwk}},
			expiry: time.Now().Add(24 * time.Hour),
		},
		claimer: claimer,
	}, nil
}

func generateGCP() (*GCP, error) {
	name, err := randutil.Alphanumeric(10)
	if err != nil {
		return nil, err
	}
	serviceAccount, err := randutil.Alphanumeric(10)
	if err != nil {
		return nil, err
	}
	jwk, err := generateJSONWebKey()
	if err != nil {
		return nil, err
	}
	claimer, err := NewClaimer(nil, globalProvisionerClaims)
	if err != nil {
		return nil, err
	}
	return &GCP{
		Type:            "GCP",
		Name:            name,
		ServiceAccounts: []string{serviceAccount},
		Claims:          &globalProvisionerClaims,
		claimer:         claimer,
		keyStore: &keyStore{
			keySet: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{*jwk}},
			expiry: time.Now().Add(24 * time.Hour),
		},
	}, nil
}

func generateCollection(nJWK, nOIDC int) (*Collection, error) {
	col := NewCollection(testAudiences)
	for i := 0; i < nJWK; i++ {
		p, err := generateJWK()
		if err != nil {
			return nil, err
		}
		col.Store(p)
	}
	for i := 0; i < nOIDC; i++ {
		p, err := generateOIDC()
		if err != nil {
			return nil, err
		}
		col.Store(p)
	}
	return col, nil
}

func generateSimpleToken(iss, aud string, jwk *jose.JSONWebKey) (string, error) {
	return generateToken("subject", iss, aud, "name@smallstep.com", []string{"test.smallstep.com"}, time.Now(), jwk)
}

func generateToken(sub, iss, aud string, email string, sans []string, iat time.Time, jwk *jose.JSONWebKey) (string, error) {
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: jwk.Key},
		new(jose.SignerOptions).WithType("JWT").WithHeader("kid", jwk.KeyID),
	)
	if err != nil {
		return "", err
	}

	id, err := randutil.ASCII(64)
	if err != nil {
		return "", err
	}

	claims := struct {
		jose.Claims
		Email string   `json:"email"`
		SANS  []string `json:"sans"`
	}{
		Claims: jose.Claims{
			ID:        id,
			Subject:   sub,
			Issuer:    iss,
			IssuedAt:  jose.NewNumericDate(iat),
			NotBefore: jose.NewNumericDate(iat),
			Expiry:    jose.NewNumericDate(iat.Add(5 * time.Minute)),
			Audience:  []string{aud},
		},
		Email: email,
		SANS:  sans,
	}
	return jose.Signed(sig).Claims(claims).CompactSerialize()
}

func generateGCPToken(sub, iss, aud, instanceID, instanceName, projectID, zone string, iat time.Time, jwk *jose.JSONWebKey) (string, error) {
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: jwk.Key},
		new(jose.SignerOptions).WithType("JWT").WithHeader("kid", jwk.KeyID),
	)
	if err != nil {
		return "", err
	}

	claims := gcpPayload{
		Claims: jose.Claims{
			Subject:   sub,
			Issuer:    iss,
			IssuedAt:  jose.NewNumericDate(iat),
			NotBefore: jose.NewNumericDate(iat),
			Expiry:    jose.NewNumericDate(iat.Add(5 * time.Minute)),
			Audience:  []string{aud},
		},
		AuthorizedParty: sub,
		Email:           "foo@developer.gserviceaccount.com",
		EmailVerified:   true,
		Google: gcpGooglePayload{
			ComputeEngine: gcpComputeEnginePayload{
				InstanceID:                instanceID,
				InstanceName:              instanceName,
				InstanceCreationTimestamp: jose.NewNumericDate(iat.Add(-24 * time.Hour)),
				ProjectID:                 projectID,
				ProjectNumber:             1234567890,
				Zone:                      zone,
			},
		},
	}
	return jose.Signed(sig).Claims(claims).CompactSerialize()
}

func parseToken(token string) (*jose.JSONWebToken, *jose.Claims, error) {
	tok, err := jose.ParseSigned(token)
	if err != nil {
		return nil, nil, err
	}
	claims := new(jose.Claims)
	if err := tok.UnsafeClaimsWithoutVerification(claims); err != nil {
		return nil, nil, err
	}
	return tok, claims, nil
}

func generateJWKServer(n int) *httptest.Server {
	hits := struct {
		Hits int `json:"hits"`
	}{}
	writeJSON := func(w http.ResponseWriter, v interface{}) {
		b, err := json.Marshal(v)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(b)
	}
	getPublic := func(ks jose.JSONWebKeySet) jose.JSONWebKeySet {
		var ret jose.JSONWebKeySet
		for _, k := range ks.Keys {
			ret.Keys = append(ret.Keys, k.Public())
		}
		return ret
	}

	defaultKeySet := must(generateJSONWebKeySet(2))[0].(jose.JSONWebKeySet)
	srv := httptest.NewUnstartedServer(nil)
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Hits++
		switch r.RequestURI {
		case "/error":
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		case "/hits":
			writeJSON(w, hits)
		case "/openid-configuration", "/.well-known/openid-configuration":
			writeJSON(w, openIDConfiguration{Issuer: "the-issuer", JWKSetURI: srv.URL + "/jwks_uri"})
		case "/random":
			keySet := must(generateJSONWebKeySet(2))[0].(jose.JSONWebKeySet)
			w.Header().Add("Cache-Control", "max-age=5")
			writeJSON(w, getPublic(keySet))
		case "/private":
			writeJSON(w, defaultKeySet)
		default:
			w.Header().Add("Cache-Control", "max-age=5")
			writeJSON(w, getPublic(defaultKeySet))
		}
	})

	srv.Start()
	return srv
}
