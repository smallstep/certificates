package provisioner

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/smallstep/certificates/webhook"
	"github.com/smallstep/linkedca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/kms/softkms"
	"go.step.sm/crypto/minica"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/x509util"
)

func generateSCEP(t *testing.T) *SCEP {
	t.Helper()

	ca, err := minica.New()
	require.NoError(t, err)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cert, err := ca.Sign(&x509.Certificate{
		Subject:   pkix.Name{CommonName: "SCEP decrypter"},
		PublicKey: key.Public(),
	})
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: cert.Raw,
	})

	block, err := pemutil.Serialize(key, pemutil.WithPassword([]byte("password")))
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(block)

	p := &SCEP{
		Type:                          "SCEP",
		Name:                          "scep",
		ChallengePassword:             "password123",
		MinimumPublicKeyLength:        0,
		DecrypterCertificate:          certPEM,
		DecrypterKeyPEM:               keyPEM,
		DecrypterKeyPassword:          "password",
		EncryptionAlgorithmIdentifier: 0,
	}
	require.NoError(t, p.Init(Config{Claims: globalProvisionerClaims}))
	return p

}

func Test_challengeValidationController_Validate(t *testing.T) {
	dummyCSR := &x509.CertificateRequest{
		Raw: []byte{1},
	}
	type request struct {
		ProvisionerName string                          `json:"provisionerName,omitempty"`
		Request         *webhook.X509CertificateRequest `json:"x509CertificateRequest,omitempty"`
		Challenge       string                          `json:"scepChallenge"`
		TransactionID   string                          `json:"scepTransactionID"`
	}
	type response struct {
		Allow bool `json:"allow"`
		Data  any  `json:"data"`
	}
	nokServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := &request{}
		err := json.NewDecoder(r.Body).Decode(req)
		require.NoError(t, err)
		assert.Equal(t, "my-scep-provisioner", req.ProvisionerName)
		assert.Equal(t, "not-allowed", req.Challenge)
		assert.Equal(t, "transaction-1", req.TransactionID)
		b, err := json.Marshal(response{Allow: false})
		require.NoError(t, err)
		w.WriteHeader(200)
		w.Write(b)
	}))
	okServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := &request{}
		err := json.NewDecoder(r.Body).Decode(req)
		require.NoError(t, err)
		assert.Equal(t, "my-scep-provisioner", req.ProvisionerName)
		assert.Equal(t, "challenge", req.Challenge)
		assert.Equal(t, "transaction-1", req.TransactionID)
		if assert.NotNil(t, req.Request) {
			assert.Equal(t, []byte{1}, req.Request.Raw)
		}
		resp := response{Allow: true}
		if r.Header.Get("X-Smallstep-Webhook-Id") == "webhook-id-2" {
			resp.Data = map[string]any{
				"ID":    "2adcbfec-5e4a-4b93-8913-640e24faf101",
				"Email": "admin@example.com",
			}
		}
		b, err := json.Marshal(resp)
		require.NoError(t, err)
		w.WriteHeader(200)
		w.Write(b)
	}))
	t.Cleanup(func() {
		nokServer.Close()
		okServer.Close()
	})
	type fields struct {
		client   *http.Client
		webhooks []*Webhook
	}
	type args struct {
		provisionerName string
		challenge       string
		transactionID   string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   x509util.TemplateData
		expErr error
	}{
		{
			name:   "fail/no-webhook",
			fields: fields{http.DefaultClient, nil},
			args:   args{"my-scep-provisioner", "no-webhook", "transaction-1"},
			expErr: errors.New("webhook server did not allow request"),
		},
		{
			name: "fail/wrong-cert-type",
			fields: fields{http.DefaultClient, []*Webhook{
				{
					Kind:     linkedca.Webhook_SCEPCHALLENGE.String(),
					CertType: linkedca.Webhook_SSH.String(),
				},
			}},
			args:   args{"my-scep-provisioner", "wrong-cert-type", "transaction-1"},
			expErr: errors.New("webhook server did not allow request"),
		},
		{
			name: "fail/wrong-secret-value",
			fields: fields{http.DefaultClient, []*Webhook{
				{
					ID:       "webhook-id-1",
					Name:     "webhook-name-1",
					Secret:   "{{}}",
					Kind:     linkedca.Webhook_SCEPCHALLENGE.String(),
					CertType: linkedca.Webhook_X509.String(),
					URL:      okServer.URL,
				},
			}},
			args: args{
				provisionerName: "my-scep-provisioner",
				challenge:       "wrong-secret-value",
				transactionID:   "transaction-1",
			},
			expErr: errors.New("failed executing webhook request: illegal base64 data at input byte 0"),
		},
		{
			name: "fail/not-allowed",
			fields: fields{http.DefaultClient, []*Webhook{
				{
					ID:       "webhook-id-1",
					Name:     "webhook-name-1",
					Secret:   "MTIzNAo=",
					Kind:     linkedca.Webhook_SCEPCHALLENGE.String(),
					CertType: linkedca.Webhook_X509.String(),
					URL:      nokServer.URL,
				},
			}},
			args: args{
				provisionerName: "my-scep-provisioner",
				challenge:       "not-allowed",
				transactionID:   "transaction-1",
			},
			expErr: errors.New("webhook server did not allow request"),
		},
		{
			name: "ok",
			fields: fields{http.DefaultClient, []*Webhook{
				{
					ID:       "webhook-id-1",
					Name:     "webhook-name-1",
					Secret:   "MTIzNAo=",
					Kind:     linkedca.Webhook_SCEPCHALLENGE.String(),
					CertType: linkedca.Webhook_X509.String(),
					URL:      okServer.URL,
				},
			}},
			args: args{
				provisionerName: "my-scep-provisioner",
				challenge:       "challenge",
				transactionID:   "transaction-1",
			},
			want: x509util.TemplateData{
				x509util.WebhooksKey: map[string]any{
					"webhook-name-1": nil,
				},
			},
		},
		{
			name: "ok with data",
			fields: fields{http.DefaultClient, []*Webhook{
				{
					ID:       "webhook-id-2",
					Name:     "webhook-name-2",
					Secret:   "MTIzNAo=",
					Kind:     linkedca.Webhook_SCEPCHALLENGE.String(),
					CertType: linkedca.Webhook_X509.String(),
					URL:      okServer.URL,
				},
			}},
			args: args{
				provisionerName: "my-scep-provisioner",
				challenge:       "challenge",
				transactionID:   "transaction-1",
			},
			want: x509util.TemplateData{
				x509util.WebhooksKey: map[string]any{
					"webhook-name-2": map[string]any{
						"ID":    "2adcbfec-5e4a-4b93-8913-640e24faf101",
						"Email": "admin@example.com",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newChallengeValidationController(tt.fields.client, nil, tt.fields.webhooks)
			ctx := context.Background()
			got, err := c.Validate(ctx, dummyCSR, tt.args.provisionerName, tt.args.challenge, tt.args.transactionID)
			if tt.expErr != nil {
				assert.EqualError(t, err, tt.expErr.Error())
				return
			}
			assert.NoError(t, err)
			data := x509util.TemplateData{}
			for _, o := range got {
				if m, ok := o.(TemplateDataModifier); ok {
					m.Modify(data)
				} else {
					t.Errorf("Validate() got = %T, want TemplateDataModifier", o)
				}
			}
			assert.Equal(t, tt.want, data)
		})
	}
}

func TestController_isCertTypeOK(t *testing.T) {
	assert.True(t, isCertTypeOK(&Webhook{CertType: linkedca.Webhook_X509.String()}))
	assert.True(t, isCertTypeOK(&Webhook{CertType: linkedca.Webhook_ALL.String()}))
	assert.True(t, isCertTypeOK(&Webhook{CertType: ""}))
	assert.False(t, isCertTypeOK(&Webhook{CertType: linkedca.Webhook_SSH.String()}))
}

func Test_selectValidationMethod(t *testing.T) {
	tests := []struct {
		name string
		p    *SCEP
		want validationMethod
	}{
		{"webhooks", &SCEP{
			Name: "SCEP",
			Type: "SCEP",
			Options: &Options{
				Webhooks: []*Webhook{
					{
						Kind: linkedca.Webhook_SCEPCHALLENGE.String(),
					},
				},
			},
		}, "webhook"},
		{"challenge", &SCEP{
			Name:              "SCEP",
			Type:              "SCEP",
			ChallengePassword: "pass",
		}, "static"},
		{"challenge-with-different-webhook", &SCEP{
			Name: "SCEP",
			Type: "SCEP",
			Options: &Options{
				Webhooks: []*Webhook{
					{
						Kind: linkedca.Webhook_AUTHORIZING.String(),
					},
				},
			},
			ChallengePassword: "pass",
		}, "static"},
		{"none", &SCEP{
			Name: "SCEP",
			Type: "SCEP",
		}, "none"},
		{"none-with-different-webhook", &SCEP{
			Name: "SCEP",
			Type: "SCEP",
			Options: &Options{
				Webhooks: []*Webhook{
					{
						Kind: linkedca.Webhook_AUTHORIZING.String(),
					},
				},
			},
		}, "none"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.p.Init(Config{Claims: globalProvisionerClaims})
			require.NoError(t, err)
			got := tt.p.selectValidationMethod()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSCEP_ValidateChallenge(t *testing.T) {
	dummyCSR := &x509.CertificateRequest{
		Raw: []byte{1},
	}
	type request struct {
		ProvisionerName string                          `json:"provisionerName,omitempty"`
		Request         *webhook.X509CertificateRequest `json:"x509CertificateRequest,omitempty"`
		Challenge       string                          `json:"scepChallenge"`
		TransactionID   string                          `json:"scepTransactionID"`
	}
	type response struct {
		Allow bool `json:"allow"`
		Data  any  `json:"data"`
	}
	okServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := &request{}
		err := json.NewDecoder(r.Body).Decode(req)
		require.NoError(t, err)
		assert.Equal(t, "SCEP", req.ProvisionerName)
		assert.Equal(t, "webhook-challenge", req.Challenge)
		assert.Equal(t, "webhook-transaction-1", req.TransactionID)
		if assert.NotNil(t, req.Request) {
			assert.Equal(t, []byte{1}, req.Request.Raw)
		}
		resp := response{Allow: true}
		if r.Header.Get("X-Smallstep-Webhook-Id") == "webhook-id-2" {
			resp.Data = map[string]any{
				"ID":    "2adcbfec-5e4a-4b93-8913-640e24faf101",
				"Email": "admin@example.com",
			}
		}
		b, err := json.Marshal(resp)
		require.NoError(t, err)
		w.WriteHeader(200)
		w.Write(b)
	}))
	t.Cleanup(okServer.Close)
	type args struct {
		challenge     string
		transactionID string
	}
	tests := []struct {
		name   string
		p      *SCEP
		server *httptest.Server
		args   args
		want   x509util.TemplateData
		expErr error
	}{
		{"ok/webhooks", &SCEP{
			Name: "SCEP",
			Type: "SCEP",
			Options: &Options{
				Webhooks: []*Webhook{
					{
						ID:       "webhook-id-1",
						Name:     "webhook-name-1",
						Secret:   "MTIzNAo=",
						Kind:     linkedca.Webhook_SCEPCHALLENGE.String(),
						CertType: linkedca.Webhook_X509.String(),
						URL:      okServer.URL,
					},
				},
			},
		}, okServer, args{"webhook-challenge", "webhook-transaction-1"}, x509util.TemplateData{
			x509util.WebhooksKey: map[string]any{
				"webhook-name-1": nil,
			},
		}, nil},
		{"ok/with-data", &SCEP{
			Name: "SCEP",
			Type: "SCEP",
			Options: &Options{
				Webhooks: []*Webhook{
					{
						ID:       "webhook-id-1",
						Name:     "webhook-name-1",
						Secret:   "MTIzNAo=",
						Kind:     linkedca.Webhook_SCEPCHALLENGE.String(),
						CertType: linkedca.Webhook_X509.String(),
						URL:      okServer.URL,
					},
					{
						ID:       "webhook-id-2",
						Name:     "webhook-name-2",
						Secret:   "MTIzNAo=",
						Kind:     linkedca.Webhook_SCEPCHALLENGE.String(),
						CertType: linkedca.Webhook_X509.String(),
						URL:      okServer.URL,
					},
				},
			},
		}, okServer, args{"webhook-challenge", "webhook-transaction-1"}, x509util.TemplateData{
			x509util.WebhooksKey: map[string]any{
				"webhook-name-1": nil,
				"webhook-name-2": map[string]any{
					"ID":    "2adcbfec-5e4a-4b93-8913-640e24faf101",
					"Email": "admin@example.com",
				},
			},
		}, nil},
		{"fail/webhooks-secret-configuration", &SCEP{
			Name: "SCEP",
			Type: "SCEP",
			Options: &Options{
				Webhooks: []*Webhook{
					{
						ID:       "webhook-id-1",
						Name:     "webhook-name-1",
						Secret:   "{{}}",
						Kind:     linkedca.Webhook_SCEPCHALLENGE.String(),
						CertType: linkedca.Webhook_X509.String(),
						URL:      okServer.URL,
					},
				},
			},
		}, nil, args{"webhook-challenge", "webhook-transaction-1"}, nil, errors.New("failed executing webhook request: illegal base64 data at input byte 0")},
		{"ok/static-challenge", &SCEP{
			Name:              "SCEP",
			Type:              "SCEP",
			Options:           &Options{},
			ChallengePassword: "secret-static-challenge",
		}, nil, args{"secret-static-challenge", "static-transaction-1"}, x509util.TemplateData{}, nil},
		{"fail/wrong-static-challenge", &SCEP{
			Name:              "SCEP",
			Type:              "SCEP",
			Options:           &Options{},
			ChallengePassword: "secret-static-challenge",
		}, nil, args{"the-wrong-challenge-secret", "static-transaction-1"}, nil, errors.New("invalid challenge password provided")},
		{"ok/no-challenge", &SCEP{
			Name:              "SCEP",
			Type:              "SCEP",
			Options:           &Options{},
			ChallengePassword: "",
		}, nil, args{"", "static-transaction-1"}, x509util.TemplateData{}, nil},
		{"fail/no-challenge-but-provided", &SCEP{
			Name:              "SCEP",
			Type:              "SCEP",
			Options:           &Options{},
			ChallengePassword: "",
		}, nil, args{"a-challenge-value", "static-transaction-1"}, nil, errors.New("invalid challenge password provided")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.p.Init(Config{Claims: globalProvisionerClaims, WebhookClient: http.DefaultClient})
			require.NoError(t, err)
			ctx := context.Background()

			got, err := tt.p.ValidateChallenge(ctx, dummyCSR, tt.args.challenge, tt.args.transactionID)
			if tt.expErr != nil {
				assert.EqualError(t, err, tt.expErr.Error())
				return
			}
			assert.NoError(t, err)
			data := x509util.TemplateData{}
			for _, o := range got {
				if m, ok := o.(TemplateDataModifier); ok {
					m.Modify(data)
				} else {
					t.Errorf("Validate() got = %T, want TemplateDataModifier", o)
				}
			}
			assert.Equal(t, tt.want, data)
		})
	}
}

func TestSCEP_Init(t *testing.T) {
	serialize := func(key crypto.PrivateKey, password string) []byte {
		var opts []pemutil.Options
		if password == "" {
			opts = append(opts, pemutil.WithPasswordPrompt("no password", func(s string) ([]byte, error) {
				return nil, nil
			}))
		} else {
			opts = append(opts, pemutil.WithPassword([]byte("password")))
		}
		block, err := pemutil.Serialize(key, opts...)
		require.NoError(t, err)
		return pem.EncodeToMemory(block)
	}

	ca, err := minica.New()
	require.NoError(t, err)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	badKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cert, err := ca.Sign(&x509.Certificate{
		Subject:   pkix.Name{CommonName: "SCEP decryptor"},
		PublicKey: key.Public(),
	})
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: cert.Raw,
	})
	certPEMWithIntermediate := append(pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: cert.Raw,
	}), pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: ca.Intermediate.Raw,
	})...)

	keyPEM := serialize(key, "password")
	keyPEMNoPassword := serialize(key, "")
	badKeyPEM := serialize(badKey, "password")

	tmp := t.TempDir()
	path := filepath.Join(tmp, "rsa.priv")
	pathNoPassword := filepath.Join(tmp, "rsa.key")

	require.NoError(t, os.WriteFile(path, keyPEM, 0600))
	require.NoError(t, os.WriteFile(pathNoPassword, keyPEMNoPassword, 0600))

	type args struct {
		config Config
	}
	tests := []struct {
		name    string
		s       *SCEP
		args    args
		wantErr bool
	}{
		{"ok", &SCEP{
			Type:                          "SCEP",
			Name:                          "scep",
			ChallengePassword:             "password123",
			MinimumPublicKeyLength:        0,
			DecrypterCertificate:          certPEM,
			DecrypterKeyPEM:               keyPEM,
			DecrypterKeyPassword:          "password",
			EncryptionAlgorithmIdentifier: 0,
		}, args{Config{Claims: globalProvisionerClaims}}, false},
		{"ok no password", &SCEP{
			Type:                          "SCEP",
			Name:                          "scep",
			ChallengePassword:             "password123",
			MinimumPublicKeyLength:        0,
			DecrypterCertificate:          certPEM,
			DecrypterKeyPEM:               keyPEMNoPassword,
			DecrypterKeyPassword:          "",
			EncryptionAlgorithmIdentifier: 1,
		}, args{Config{Claims: globalProvisionerClaims}}, false},
		{"ok with uri", &SCEP{
			Type:                          "SCEP",
			Name:                          "scep",
			ChallengePassword:             "password123",
			MinimumPublicKeyLength:        1024,
			DecrypterCertificate:          certPEM,
			DecrypterKeyURI:               "softkms:path=" + path,
			DecrypterKeyPassword:          "password",
			EncryptionAlgorithmIdentifier: 2,
		}, args{Config{Claims: globalProvisionerClaims}}, false},
		{"ok with uri no password", &SCEP{
			Type:                          "SCEP",
			Name:                          "scep",
			ChallengePassword:             "password123",
			MinimumPublicKeyLength:        2048,
			DecrypterCertificate:          certPEM,
			DecrypterKeyURI:               "softkms:path=" + pathNoPassword,
			DecrypterKeyPassword:          "",
			EncryptionAlgorithmIdentifier: 3,
		}, args{Config{Claims: globalProvisionerClaims}}, false},
		{"ok with SCEPKeyManager", &SCEP{
			Type:                          "SCEP",
			Name:                          "scep",
			ChallengePassword:             "password123",
			MinimumPublicKeyLength:        2048,
			DecrypterCertificate:          certPEM,
			DecrypterKeyURI:               "softkms:path=" + pathNoPassword,
			DecrypterKeyPassword:          "",
			EncryptionAlgorithmIdentifier: 4,
		}, args{Config{Claims: globalProvisionerClaims, SCEPKeyManager: &softkms.SoftKMS{}}}, false},
		{"ok intermediate", &SCEP{
			Type:                          "SCEP",
			Name:                          "scep",
			ChallengePassword:             "password123",
			MinimumPublicKeyLength:        0,
			DecrypterCertificate:          nil,
			DecrypterKeyPEM:               nil,
			DecrypterKeyPassword:          "",
			EncryptionAlgorithmIdentifier: 0,
		}, args{Config{Claims: globalProvisionerClaims}}, false},
		{"fail type", &SCEP{
			Type:                          "",
			Name:                          "scep",
			ChallengePassword:             "password123",
			MinimumPublicKeyLength:        0,
			DecrypterCertificate:          certPEM,
			DecrypterKeyPEM:               keyPEM,
			DecrypterKeyPassword:          "password",
			EncryptionAlgorithmIdentifier: 0,
		}, args{Config{Claims: globalProvisionerClaims}}, true},
		{"fail name", &SCEP{
			Type:                          "SCEP",
			Name:                          "",
			ChallengePassword:             "password123",
			MinimumPublicKeyLength:        0,
			DecrypterCertificate:          certPEM,
			DecrypterKeyPEM:               keyPEM,
			DecrypterKeyPassword:          "password",
			EncryptionAlgorithmIdentifier: 0,
		}, args{Config{Claims: globalProvisionerClaims}}, true},
		{"fail minimumPublicKeyLength", &SCEP{
			Type:                          "SCEP",
			Name:                          "scep",
			ChallengePassword:             "password123",
			MinimumPublicKeyLength:        2001,
			DecrypterCertificate:          certPEM,
			DecrypterKeyPEM:               keyPEM,
			DecrypterKeyPassword:          "password",
			EncryptionAlgorithmIdentifier: 0,
		}, args{Config{Claims: globalProvisionerClaims}}, true},
		{"fail encryptionAlgorithmIdentifier", &SCEP{
			Type:                          "SCEP",
			Name:                          "scep",
			ChallengePassword:             "password123",
			MinimumPublicKeyLength:        0,
			DecrypterCertificate:          certPEM,
			DecrypterKeyPEM:               keyPEM,
			DecrypterKeyPassword:          "password",
			EncryptionAlgorithmIdentifier: 5,
		}, args{Config{Claims: globalProvisionerClaims}}, true},
		{"fail negative encryptionAlgorithmIdentifier", &SCEP{
			Type:                          "SCEP",
			Name:                          "scep",
			ChallengePassword:             "password123",
			MinimumPublicKeyLength:        0,
			DecrypterCertificate:          certPEM,
			DecrypterKeyPEM:               keyPEM,
			DecrypterKeyPassword:          "password",
			EncryptionAlgorithmIdentifier: -1,
		}, args{Config{Claims: globalProvisionerClaims}}, true},
		{"fail key decode", &SCEP{
			Type:                          "SCEP",
			Name:                          "scep",
			ChallengePassword:             "password123",
			MinimumPublicKeyLength:        0,
			DecrypterCertificate:          certPEM,
			DecrypterKeyPEM:               []byte("not a pem"),
			DecrypterKeyPassword:          "password",
			EncryptionAlgorithmIdentifier: 0,
		}, args{Config{Claims: globalProvisionerClaims}}, true},
		{"fail certificate decode", &SCEP{
			Type:                          "SCEP",
			Name:                          "scep",
			ChallengePassword:             "password123",
			MinimumPublicKeyLength:        0,
			DecrypterCertificate:          []byte("not a pem"),
			DecrypterKeyPEM:               keyPEM,
			DecrypterKeyPassword:          "password",
			EncryptionAlgorithmIdentifier: 0,
		}, args{Config{Claims: globalProvisionerClaims}}, true},
		{"fail certificate with intermediate", &SCEP{
			Type:                   "SCEP",
			Name:                   "scep",
			ChallengePassword:      "password123",
			MinimumPublicKeyLength: 0,
			DecrypterCertificate:   certPEMWithIntermediate,
			DecrypterKeyPEM:        keyPEM,
			DecrypterKeyPassword:   "password",
		}, args{Config{Claims: globalProvisionerClaims}}, true},
		{"fail decrypter password", &SCEP{
			Type:                          "SCEP",
			Name:                          "scep",
			ChallengePassword:             "password123",
			MinimumPublicKeyLength:        0,
			DecrypterCertificate:          certPEM,
			DecrypterKeyPEM:               keyPEM,
			DecrypterKeyPassword:          "badpassword",
			EncryptionAlgorithmIdentifier: 0,
		}, args{Config{Claims: globalProvisionerClaims}}, true},
		{"fail uri", &SCEP{
			Type:                          "SCEP",
			Name:                          "scep",
			ChallengePassword:             "password123",
			MinimumPublicKeyLength:        0,
			DecrypterCertificate:          certPEM,
			DecrypterKeyURI:               "softkms:path=missing.key",
			DecrypterKeyPassword:          "password",
			EncryptionAlgorithmIdentifier: 0,
		}, args{Config{Claims: globalProvisionerClaims}}, true},
		{"fail uri password", &SCEP{
			Type:                          "SCEP",
			Name:                          "scep",
			ChallengePassword:             "password123",
			MinimumPublicKeyLength:        0,
			DecrypterCertificate:          certPEM,
			DecrypterKeyURI:               "softkms:path=" + path,
			DecrypterKeyPassword:          "badpassword",
			EncryptionAlgorithmIdentifier: 0,
		}, args{Config{Claims: globalProvisionerClaims}}, true},
		{"fail uri type", &SCEP{
			Type:                          "SCEP",
			Name:                          "scep",
			ChallengePassword:             "password123",
			MinimumPublicKeyLength:        0,
			DecrypterCertificate:          certPEM,
			DecrypterKeyURI:               "foo:path=" + path,
			DecrypterKeyPassword:          "password",
			EncryptionAlgorithmIdentifier: 0,
		}, args{Config{Claims: globalProvisionerClaims}}, true},
		{"fail missing certificate", &SCEP{
			Type:                          "SCEP",
			Name:                          "scep",
			ChallengePassword:             "password123",
			MinimumPublicKeyLength:        0,
			DecrypterCertificate:          nil,
			DecrypterKeyPEM:               keyPEM,
			DecrypterKeyPassword:          "password",
			EncryptionAlgorithmIdentifier: 0,
		}, args{Config{Claims: globalProvisionerClaims}}, true},
		{"fail key match", &SCEP{
			Type:                          "SCEP",
			Name:                          "scep",
			ChallengePassword:             "password123",
			MinimumPublicKeyLength:        0,
			DecrypterCertificate:          certPEM,
			DecrypterKeyPEM:               badKeyPEM,
			DecrypterKeyPassword:          "password",
			EncryptionAlgorithmIdentifier: 0,
		}, args{Config{Claims: globalProvisionerClaims}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.s.Init(tt.args.config); (err != nil) != tt.wantErr {
				t.Errorf("SCEP.Init() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSCEP_Getters(t *testing.T) {
	p := generateSCEP(t)
	assert.Equal(t, "scep/scep", p.GetID())
	assert.Equal(t, "scep", p.GetName())
	assert.Equal(t, TypeSCEP, p.GetType())
	kid, key, ok := p.GetEncryptedKey()
	if kid != "" || key != "" || ok == true {
		t.Errorf("ACME.GetEncryptedKey() = (%v, %v, %v), want (%v, %v, %v)", kid, key, ok, "", "", false)
	}
	tokenID, err := p.GetTokenID("token")
	assert.Empty(t, tokenID)
	assert.Equal(t, ErrTokenFlowNotSupported, err)
}
