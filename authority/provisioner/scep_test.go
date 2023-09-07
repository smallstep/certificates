package provisioner

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.step.sm/linkedca"
)

func Test_challengeValidationController_Validate(t *testing.T) {
	type request struct {
		Challenge     string `json:"scepChallenge"`
		TransactionID string `json:"scepTransactionID"`
	}
	type response struct {
		Allow bool `json:"allow"`
	}
	nokServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := &request{}
		err := json.NewDecoder(r.Body).Decode(req)
		require.NoError(t, err)
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
		assert.Equal(t, "challenge", req.Challenge)
		assert.Equal(t, "transaction-1", req.TransactionID)
		b, err := json.Marshal(response{Allow: true})
		require.NoError(t, err)
		w.WriteHeader(200)
		w.Write(b)
	}))
	type fields struct {
		client   *http.Client
		webhooks []*Webhook
	}
	type args struct {
		challenge     string
		transactionID string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		server *httptest.Server
		expErr error
	}{
		{
			name:   "fail/no-webhook",
			fields: fields{http.DefaultClient, nil},
			args:   args{"no-webhook", "transaction-1"},
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
			args:   args{"wrong-cert-type", "transaction-1"},
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
				challenge:     "wrong-secret-value",
				transactionID: "transaction-1",
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
				challenge:     "not-allowed",
				transactionID: "transaction-1",
			},
			server: nokServer,
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
				challenge:     "challenge",
				transactionID: "transaction-1",
			},
			server: okServer,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newChallengeValidationController(tt.fields.client, tt.fields.webhooks)

			if tt.server != nil {
				defer tt.server.Close()
			}

			ctx := context.Background()
			err := c.Validate(ctx, nil, tt.args.challenge, tt.args.transactionID)

			if tt.expErr != nil {
				assert.EqualError(t, err, tt.expErr.Error())
				return
			}

			assert.NoError(t, err)
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
	type request struct {
		Challenge     string `json:"scepChallenge"`
		TransactionID string `json:"scepTransactionID"`
	}
	type response struct {
		Allow bool `json:"allow"`
	}
	okServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := &request{}
		err := json.NewDecoder(r.Body).Decode(req)
		require.NoError(t, err)
		assert.Equal(t, "webhook-challenge", req.Challenge)
		assert.Equal(t, "webhook-transaction-1", req.TransactionID)
		b, err := json.Marshal(response{Allow: true})
		require.NoError(t, err)
		w.WriteHeader(200)
		w.Write(b)
	}))
	type args struct {
		challenge     string
		transactionID string
	}
	tests := []struct {
		name   string
		p      *SCEP
		server *httptest.Server
		args   args
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
		}, okServer, args{"webhook-challenge", "webhook-transaction-1"},
			nil,
		},
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
		}, nil, args{"webhook-challenge", "webhook-transaction-1"},
			errors.New("failed executing webhook request: illegal base64 data at input byte 0"),
		},
		{"ok/static-challenge", &SCEP{
			Name:              "SCEP",
			Type:              "SCEP",
			Options:           &Options{},
			ChallengePassword: "secret-static-challenge",
		}, nil, args{"secret-static-challenge", "static-transaction-1"},
			nil,
		},
		{"fail/wrong-static-challenge", &SCEP{
			Name:              "SCEP",
			Type:              "SCEP",
			Options:           &Options{},
			ChallengePassword: "secret-static-challenge",
		}, nil, args{"the-wrong-challenge-secret", "static-transaction-1"},
			errors.New("invalid challenge password provided"),
		},
		{"ok/no-challenge", &SCEP{
			Name:              "SCEP",
			Type:              "SCEP",
			Options:           &Options{},
			ChallengePassword: "",
		}, nil, args{"", "static-transaction-1"},
			nil,
		},
		{"fail/no-challenge-but-provided", &SCEP{
			Name:              "SCEP",
			Type:              "SCEP",
			Options:           &Options{},
			ChallengePassword: "",
		}, nil, args{"a-challenge-value", "static-transaction-1"},
			errors.New("invalid challenge password provided"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			if tt.server != nil {
				defer tt.server.Close()
			}

			err := tt.p.Init(Config{Claims: globalProvisionerClaims, WebhookClient: http.DefaultClient})
			require.NoError(t, err)
			ctx := context.Background()

			err = tt.p.ValidateChallenge(ctx, nil, tt.args.challenge, tt.args.transactionID)
			if tt.expErr != nil {
				assert.EqualError(t, err, tt.expErr.Error())
				return
			}

			assert.NoError(t, err)
		})
	}
}
