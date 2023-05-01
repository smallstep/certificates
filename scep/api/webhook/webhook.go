package webhook

import (
	"context"
	"fmt"
	"net/http"

	"go.step.sm/linkedca"

	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/webhook"
)

// Controller controls webhook execution
type Controller struct {
	client   *http.Client
	webhooks []*provisioner.Webhook
}

// New returns a new SCEP webhook Controller
func New(webhooks []*provisioner.Webhook) (*Controller, error) {
	return &Controller{
		client:   http.DefaultClient,
		webhooks: webhooks,
	}, nil
}

// Validate executes zero or more configured webhooks to
// validate the SCEP challenge. If at least one of indicates
// the challenge value is accepted, validation succeeds. Other
// webhooks will not be executed. If none of the webhooks
// indicates the challenge is accepted, an error is
// returned.
func (c *Controller) Validate(ctx context.Context, challenge, transactionID string) error {
	for _, wh := range c.webhooks {
		if wh.Kind != linkedca.Webhook_SCEPCHALLENGE.String() {
			continue
		}
		if !c.isCertTypeOK(wh) {
			continue
		}
		req := &webhook.RequestBody{
			SCEPChallenge:     challenge,
			SCEPTransactionID: transactionID,
		}
		resp, err := wh.DoWithContext(ctx, c.client, req, nil) // TODO(hs): support templated URL? Requires some refactoring
		if err != nil {
			return fmt.Errorf("failed executing webhook request: %w", err)
		}
		if resp.Allow {
			return nil // return early when response is positive
		}
	}

	return provisioner.ErrWebhookDenied
}

// isCertTypeOK returns whether or not the webhook can be used
// with the SCEP challenge validation webhook controller.
func (c *Controller) isCertTypeOK(wh *provisioner.Webhook) bool {
	if wh.CertType == linkedca.Webhook_ALL.String() || wh.CertType == "" {
		return true
	}
	return linkedca.Webhook_X509.String() == wh.CertType
}
