package authority

import (
	"context"

	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/webhook"
)

type mockWebhookController struct {
	enrichErr    error
	authorizeErr error
	templateData provisioner.WebhookSetter
	respData     map[string]any
}

var _ webhookController = &mockWebhookController{}

func (wc *mockWebhookController) Enrich(context.Context, *webhook.RequestBody) error {
	for key, data := range wc.respData {
		wc.templateData.SetWebhook(key, data)
	}

	return wc.enrichErr
}

func (wc *mockWebhookController) Authorize(context.Context, *webhook.RequestBody) error {
	return wc.authorizeErr
}
