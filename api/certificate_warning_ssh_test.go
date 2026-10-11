package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/x509util"
	"golang.org/x/crypto/ssh"

	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/cas/apiv1"
	"github.com/smallstep/certificates/logging"
)

func TestIssuerValidityWarnings_SSHIdentity(t *testing.T) {
	f := newWarningAuthority(t, "")
	_, identityKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	csr, err := x509util.CreateCertificateRequest("warning.example", []string{"warning.example"}, identityKey)
	require.NoError(t, err)
	_, sshKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshPublicKey, err := ssh.NewPublicKey(sshKey.Public())
	require.NoError(t, err)
	sshOptions := &provisioner.SignSSHOptions{
		CertType: provisioner.SSHHostCert, KeyID: "warning.example", Principals: []string{"warning.example"},
		ValidAfter: NewTimeDuration(f.now), ValidBefore: NewTimeDuration(f.now.Add(72 * time.Hour)),
	}

	var original SSHSignResponse
	for _, identity := range []bool{true, false} {
		t.Run("sign identity="+strconv.FormatBool(identity), func(t *testing.T) {
			request := SSHSignRequest{
				PublicKey: sshPublicKey.Marshal(), OTT: f.token(t, "/ssh/sign", sshOptions),
				CertType: sshOptions.CertType, KeyID: sshOptions.KeyID, Principals: sshOptions.Principals,
				ValidAfter: sshOptions.ValidAfter, ValidBefore: sshOptions.ValidBefore,
			}
			if identity {
				request.IdentityCSR = NewCertificateRequest(csr)
			}
			r := f.request(t, "/ssh/sign", request, nil)
			logger, hook := logtest.NewNullLogger()
			w := httptest.NewRecorder()
			logging.NewLoggerHandler("test", &logging.Logger{Logger: logger}, http.HandlerFunc(SSHSign)).ServeHTTP(w, r)
			require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
			var response SSHSignResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
			require.NotNil(t, response.Certificate.Certificate)
			checker := &ssh.CertChecker{}
			require.NoError(t, checker.CheckCert("warning.example", response.Certificate.Certificate))
			assert.Equal(t, uint64(f.now.Add(72*time.Hour).Unix()), response.Certificate.ValidBefore)
			require.Len(t, hook.AllEntries(), 1)
			if identity {
				require.Len(t, response.IdentityCertificate, 2)
				assertIssuedWarning(t, response.IdentityCertificate[0].Certificate, f.issuer, f.root, response.Warnings)
				assert.Equal(t, identityKey.Public(), response.IdentityCertificate[0].PublicKey)
				assert.Equal(t, logrus.WarnLevel, hook.LastEntry().Level)
				assert.Equal(t, response.Warnings, hook.LastEntry().Data["certificate-warnings"])
				original = response
			} else {
				assert.Empty(t, response.IdentityCertificate)
				assert.Empty(t, response.Warnings)
				assert.NotContains(t, hook.LastEntry().Data, "certificate-warnings")
				assert.Equal(t, logrus.InfoLevel, hook.LastEntry().Level)
			}
		})
	}
	require.NotNil(t, original.Certificate.Certificate)

	for _, operation := range []string{"renew", "rekey"} {
		for _, identity := range []bool{true, false} {
			t.Run(operation+" identity="+strconv.FormatBool(identity), func(t *testing.T) {
				path := "/ssh/" + operation
				claims := jose.Claims{
					ID: uuid.NewString(), Issuer: "sshpop", Subject: strconv.FormatUint(original.Certificate.Serial, 10),
					Audience:  []string{"https://warning.example" + path + "#sshpop/sshpop"},
					NotBefore: jose.NewNumericDate(f.now), Expiry: jose.NewNumericDate(f.now.Add(time.Minute)),
				}
				token := warningToken(t, sshKey, new(jose.SignerOptions).WithType("JWT").WithHeader("sshpop", base64.StdEncoding.EncodeToString(original.Certificate.Marshal())), claims)
				var body any = SSHRenewRequest{OTT: token}
				var handler http.Handler = http.HandlerFunc(SSHRenew)
				wantKey := sshPublicKey
				if operation == "rekey" {
					_, newKey, err := ed25519.GenerateKey(rand.Reader)
					require.NoError(t, err)
					wantKey, err = ssh.NewPublicKey(newKey.Public())
					require.NoError(t, err)
					body, handler = SSHRekeyRequest{OTT: token, PublicKey: wantKey.Marshal()}, http.HandlerFunc(SSHRekey)
				}
				var peer *x509.Certificate
				if identity {
					peer = original.IdentityCertificate[0].Certificate
				}
				r := f.request(t, path, body, peer)
				logger, hook := logtest.NewNullLogger()
				w := httptest.NewRecorder()
				logging.NewLoggerHandler("test", &logging.Logger{Logger: logger}, handler).ServeHTTP(w, r)
				require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
				var cert *ssh.Certificate
				var certs []Certificate
				var warnings []apiv1.CertificateWarning
				if operation == "renew" {
					var response SSHRenewResponse
					require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
					cert, certs, warnings = response.Certificate.Certificate, response.IdentityCertificate, response.Warnings
				} else {
					var response SSHRekeyResponse
					require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
					cert, certs, warnings = response.Certificate.Certificate, response.IdentityCertificate, response.Warnings
				}
				require.NotNil(t, cert)
				checker := &ssh.CertChecker{}
				require.NoError(t, checker.CheckCert("warning.example", cert))
				assert.Equal(t, wantKey.Marshal(), cert.Key.Marshal())
				assert.Equal(t, original.Certificate.ValidBefore-original.Certificate.ValidAfter, cert.ValidBefore-cert.ValidAfter)
				assert.Greater(t, cert.ValidBefore, uint64(f.root.NotAfter.Unix()))
				require.Len(t, hook.AllEntries(), 1)
				if identity {
					require.Len(t, certs, 2)
					assertIssuedWarning(t, certs[0].Certificate, f.issuer, f.root, warnings)
					assert.Equal(t, identityKey.Public(), certs[0].PublicKey)
					assert.Equal(t, logrus.WarnLevel, hook.LastEntry().Level)
					assert.Equal(t, warnings, hook.LastEntry().Data["certificate-warnings"])
				} else {
					assert.Empty(t, certs)
					assert.Empty(t, warnings)
					assert.Equal(t, logrus.InfoLevel, hook.LastEntry().Level)
					assert.NotContains(t, hook.LastEntry().Data, "certificate-warnings")
				}
			})
		}
	}
}
