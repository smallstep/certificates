package provisioner

import (
	"crypto"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/smallstep/cli/crypto/randutil"
	"github.com/smallstep/cli/jose"
)

var testAudiences = []string{
	"https://ca.smallstep.com/sign",
	"https://ca.smallsteomcom/1.0/sign",
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
		keySet.Keys = append(keySet.Keys, key.Public())
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
	return &JWK{
		Name:         name,
		Type:         "JWK",
		Key:          &public,
		EncryptedKey: encrypted,
		Claims:       &globalProvisionerClaims,
		audiences:    testAudiences,
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
	return generateToken("subject", iss, aud, []string{"test.smallstep.com"}, jwk)
	// return generateToken("the-sub", []string{"test.smallstep.com"}, jwk.KeyID, iss, aud, "testdata/root_ca.crt", now, now.Add(5*time.Minute), jwk)
}

func generateToken(sub, iss, aud string, sans []string, jwk *jose.JSONWebKey) (string, error) {
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

	now := time.Now()
	claims := struct {
		jose.Claims
		SANS []string `json:"sans"`
	}{
		Claims: jose.Claims{
			ID:        id,
			Subject:   sub,
			Issuer:    iss,
			NotBefore: jose.NewNumericDate(now),
			Expiry:    jose.NewNumericDate(now.Add(5 * time.Minute)),
			Audience:  []string{aud},
		},
		SANS: sans,
	}
	return jose.Signed(sig).Claims(claims).CompactSerialize()
}
