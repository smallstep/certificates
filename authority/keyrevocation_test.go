package authority

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/pemutil"
	"golang.org/x/crypto/ocsp"

	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/db"
)

func assertStatus(t *testing.T, err error, code int, prefix string) {
	t.Helper()
	require.Error(t, err)
	var sc render.StatusCodedError
	require.True(t, errors.As(err, &sc), "error does not implement StatusCodedError interface")
	assert.Equal(t, code, sc.StatusCode())
	assert.Contains(t, err.Error(), prefix)
}

func revokedKeysDB(revoked ...[]byte) *db.MockAuthDB {
	fps := map[string]bool{}
	for _, spki := range revoked {
		fps[db.KeyFingerprint(spki)] = true
	}
	return &db.MockAuthDB{
		MIsRevoked:    func(string) (bool, error) { return false, nil },
		MIsKeyRevoked: func(fp string) (bool, error) { return fps[fp], nil },
	}
}

func TestAuthority_IsKeyRevoked(t *testing.T) {
	a := testAuthority(t)

	a.db = revokedKeysDB([]byte("revoked"))
	got, err := a.IsKeyRevoked([]byte("revoked"))
	require.NoError(t, err)
	assert.True(t, got)
	got, err = a.IsKeyRevoked([]byte("other"))
	require.NoError(t, err)
	assert.False(t, got)
	got, err = a.IsKeyRevoked(nil)
	require.NoError(t, err)
	assert.False(t, got)

	// A database without key revocation has no revoked keys.
	a.db = struct{ db.AuthDB }{&db.MockAuthDB{}}
	got, err = a.IsKeyRevoked([]byte("revoked"))
	require.NoError(t, err)
	assert.False(t, got)
}

func TestAuthority_authorizeRenew_revokedKey(t *testing.T) {
	fooCrt, err := pemutil.ReadCertificate("testdata/certs/foo.crt")
	require.NoError(t, err)
	fooCrt.NotAfter = time.Now().Add(time.Hour)

	t.Run("fail/key revoked", func(t *testing.T) {
		a := testAuthority(t)
		a.db = revokedKeysDB(fooCrt.RawSubjectPublicKeyInfo)
		_, err := a.authorizeRenew(context.Background(), fooCrt)
		assertStatus(t, err, http.StatusUnauthorized, "authority.authorizeRenew: certificate key has been revoked")
	})

	t.Run("fail/key revoked, certificate expired", func(t *testing.T) {
		expired := *fooCrt
		expired.NotAfter = time.Now().Add(-time.Hour)
		a := testAuthority(t)
		a.db = revokedKeysDB(fooCrt.RawSubjectPublicKeyInfo)
		_, err := a.authorizeRenew(context.Background(), &expired)
		assertStatus(t, err, http.StatusUnauthorized, "authority.authorizeRenew: certificate key has been revoked")
	})

	t.Run("fail/IsKeyRevoked error", func(t *testing.T) {
		a := testAuthority(t)
		a.db = &db.MockAuthDB{
			MIsRevoked:    func(string) (bool, error) { return false, nil },
			MIsKeyRevoked: func(string) (bool, error) { return false, errors.New("force") },
		}
		_, err := a.authorizeRenew(context.Background(), fooCrt)
		assertStatus(t, err, http.StatusInternalServerError, "authority.authorizeRenew: force")
	})

	t.Run("ok/other key revoked", func(t *testing.T) {
		a := testAuthority(t)
		a.db = revokedKeysDB([]byte("another key"))
		_, err := a.authorizeRenew(context.Background(), fooCrt)
		require.NoError(t, err)
	})
}

func TestAuthority_Rekey_revokedKey(t *testing.T) {
	fooCrt, err := pemutil.ReadCertificate("testdata/certs/foo.crt")
	require.NoError(t, err)
	fooCrt.NotAfter = time.Now().Add(time.Hour)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	newSPKI, err := x509.MarshalPKIXPublicKey(priv.Public())
	require.NoError(t, err)

	a := testAuthority(t)
	a.db = revokedKeysDB(newSPKI)
	_, err = a.RenewContext(context.Background(), fooCrt, priv.Public())
	assertStatus(t, err, http.StatusForbidden, "authority.Rekey: the new key has been revoked")
}

func TestAuthority_Sign_revokedKey(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csr := getCSR(t, priv)

	a := testAuthority(t)
	a.db = revokedKeysDB(csr.RawSubjectPublicKeyInfo)
	_, err = a.SignWithContext(context.Background(), csr, provisioner.SignOptions{})
	assertStatus(t, err, http.StatusForbidden, "authority.Sign: the key in the certificate request has been revoked")

	a.db = &db.MockAuthDB{
		MIsRevoked:    func(string) (bool, error) { return false, nil },
		MIsKeyRevoked: func(string) (bool, error) { return false, errors.New("force") },
	}
	_, err = a.SignWithContext(context.Background(), csr, provisioner.SignOptions{})
	assertStatus(t, err, http.StatusInternalServerError, "authority.Sign: force")
}

func TestAuthority_revoke_recordsKey(t *testing.T) {
	crt := generateCertificate(t, "test.smallstep.com", []string{"test.smallstep.com"})
	fp := db.KeyFingerprint(crt.RawSubjectPublicKeyInfo)

	newDB := func(revokedKeys map[string]*db.RevokedCertificateInfo, revokeKeyErr error) *db.MockAuthDB {
		return &db.MockAuthDB{
			MRevoke: func(*db.RevokedCertificateInfo) error { return nil },
			MRevokeKey: func(fp string, rci *db.RevokedCertificateInfo) error {
				if revokeKeyErr != nil {
					return revokeKeyErr
				}
				revokedKeys[fp] = rci
				return nil
			},
		}
	}

	t.Run("keyCompromise revokes the key", func(t *testing.T) {
		keys := map[string]*db.RevokedCertificateInfo{}
		a := testAuthority(t)
		a.db = newDB(keys, nil)
		rci := &db.RevokedCertificateInfo{Serial: crt.SerialNumber.String(), ReasonCode: ocsp.KeyCompromise}
		require.NoError(t, a.revoke(crt, rci))
		assert.Equal(t, map[string]*db.RevokedCertificateInfo{fp: rci}, keys)
	})

	for name, rci := range map[string]*db.RevokedCertificateInfo{
		"unspecified": {Serial: "1", ReasonCode: ocsp.Unspecified},
		"superseded":  {Serial: "1", ReasonCode: ocsp.Superseded},
	} {
		t.Run(name+" revokes only the certificate", func(t *testing.T) {
			keys := map[string]*db.RevokedCertificateInfo{}
			a := testAuthority(t)
			a.db = newDB(keys, nil)
			require.NoError(t, a.revoke(crt, rci))
			assert.Empty(t, keys)
		})
	}

	t.Run("keyCompromise without the certificate revokes only the serial", func(t *testing.T) {
		keys := map[string]*db.RevokedCertificateInfo{}
		a := testAuthority(t)
		a.db = newDB(keys, nil)
		require.NoError(t, a.revoke(nil, &db.RevokedCertificateInfo{Serial: "1", ReasonCode: ocsp.KeyCompromise}))
		assert.Empty(t, keys)
	})

	t.Run("key already revoked", func(t *testing.T) {
		a := testAuthority(t)
		a.db = newDB(nil, db.ErrAlreadyExists)
		require.NoError(t, a.revoke(crt, &db.RevokedCertificateInfo{Serial: "1", ReasonCode: ocsp.KeyCompromise}))
	})

	t.Run("error revoking the key", func(t *testing.T) {
		a := testAuthority(t)
		a.db = newDB(nil, errors.New("force"))
		err := a.revoke(crt, &db.RevokedCertificateInfo{Serial: "1", ReasonCode: ocsp.KeyCompromise})
		assert.EqualError(t, err, "error revoking certificate key: force")
	})

	t.Run("error revoking the certificate skips the key", func(t *testing.T) {
		keys := map[string]*db.RevokedCertificateInfo{}
		a := testAuthority(t)
		mdb := newDB(keys, nil)
		mdb.MRevoke = func(*db.RevokedCertificateInfo) error { return db.ErrAlreadyExists }
		a.db = mdb
		err := a.revoke(crt, &db.RevokedCertificateInfo{Serial: "1", ReasonCode: ocsp.KeyCompromise})
		assert.ErrorIs(t, err, db.ErrAlreadyExists)
		assert.Empty(t, keys)
	})
}
