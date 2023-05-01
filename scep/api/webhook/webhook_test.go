package webhook

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

	"github.com/smallstep/certificates/authority/provisioner"
)

func TestController_Validate(t *testing.T) {
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
		webhooks []*provisioner.Webhook
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
			name: "fail/no-scep-webhook",
			fields: fields{http.DefaultClient, []*provisioner.Webhook{
				{
					Kind: linkedca.Webhook_AUTHORIZING.String(),
				},
			}},
			args:   args{"no-scep-webhook", "transaction-1"},
			expErr: errors.New("webhook server did not allow request"),
		},
		{
			name: "fail/wrong-cert-type",
			fields: fields{http.DefaultClient, []*provisioner.Webhook{
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
			fields: fields{http.DefaultClient, []*provisioner.Webhook{
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
			fields: fields{http.DefaultClient, []*provisioner.Webhook{
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
			fields: fields{http.DefaultClient, []*provisioner.Webhook{
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
			c := &Controller{
				client:   tt.fields.client,
				webhooks: tt.fields.webhooks,
			}

			if tt.server != nil {
				defer tt.server.Close()
			}

			ctx := context.Background()
			err := c.Validate(ctx, tt.args.challenge, tt.args.transactionID)
			if tt.expErr != nil {
				assert.EqualError(t, err, tt.expErr.Error())
				return
			}

			assert.NoError(t, err)
		})
	}
}

func TestController_isCertTypeOK(t *testing.T) {
	c := &Controller{}
	assert.True(t, c.isCertTypeOK(&provisioner.Webhook{CertType: linkedca.Webhook_X509.String()}))
	assert.True(t, c.isCertTypeOK(&provisioner.Webhook{CertType: linkedca.Webhook_ALL.String()}))
	assert.True(t, c.isCertTypeOK(&provisioner.Webhook{CertType: ""}))
	assert.False(t, c.isCertTypeOK(&provisioner.Webhook{CertType: linkedca.Webhook_SSH.String()}))
}
