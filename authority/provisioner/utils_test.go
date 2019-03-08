package provisioner

import (
	"crypto"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/smallstep/cli/crypto/randutil"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/cli/token"
	"github.com/smallstep/cli/token/provision"
)

var testAudiences = []string{
	"https://ca.smallstep.com/sign",
	"https://ca.smallsteomcom/1.0/sign",
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
		configuration: openIDConfiguration{
			Issuer:    issuer,
			JWKSetURI: "https://example.com/.well-known/jwks",
		},
		keyStore: &keyStore{
			keys:   jose.JSONWebKeySet{Keys: []jose.JSONWebKey{*jwk}},
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
	now := time.Now()
	return generateToken("the-sub", []string{"test.smallstep.com"}, jwk.KeyID, iss, aud, "testdata/root_ca.crt", now, now.Add(5*time.Minute), jwk)
}

func generateToken(sub string, sans []string, kid, iss, aud, root string, notBefore, notAfter time.Time, jwk *jose.JSONWebKey) (string, error) {
	// A random jwt id will be used to identify duplicated tokens
	jwtID, err := randutil.Hex(64) // 256 bits
	if err != nil {
		return "", err
	}

	tokOptions := []token.Options{
		token.WithJWTID(jwtID),
		token.WithKid(kid),
		token.WithIssuer(iss),
		token.WithAudience(aud),
	}
	if len(root) > 0 {
		tokOptions = append(tokOptions, token.WithRootCA(root))
	}

	// If there are no SANs then add the 'subject' (common-name) as the only SAN.
	if len(sans) == 0 {
		sans = []string{sub}
	}

	tokOptions = append(tokOptions, token.WithSANS(sans))
	if !notBefore.IsZero() || !notAfter.IsZero() {
		if notBefore.IsZero() {
			notBefore = time.Now()
		}
		if notAfter.IsZero() {
			notAfter = notBefore.Add(token.DefaultValidity)
		}
		tokOptions = append(tokOptions, token.WithValidity(notBefore, notAfter))
	}

	tok, err := provision.New(sub, tokOptions...)
	if err != nil {
		return "", err
	}

	return tok.SignedString(jwk.Algorithm, jwk.Key)
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
