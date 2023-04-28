package webhook

import (
	"net/http"

	"go.step.sm/linkedca"

	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/webhook"
)

type Controller struct {
	client   *http.Client
	webhooks []*provisioner.Webhook
}

func New(webhooks []*provisioner.Webhook) (*Controller, error) {
	return &Controller{
		client:   http.DefaultClient,
		webhooks: webhooks,
	}, nil
}

func (c *Controller) Validate(challenge string) error {
	if c == nil {
		return nil
	}
	for _, wh := range c.webhooks {
		if wh.Kind != linkedca.Webhook_SCEPCHALLENGE.String() {
			continue
		}
		if !c.isCertTypeOK(wh) {
			continue
		}
		req := &webhook.RequestBody{
			SCEPChallenge: challenge,
		}
		resp, err := wh.Do(c.client, req, nil) // TODO(hs): support templated URL?
		if err != nil {
			return err
		}
		if !resp.Allow {
			return provisioner.ErrWebhookDenied
		}
	}
	return nil
}

func (c *Controller) isCertTypeOK(wh *provisioner.Webhook) bool {
	return linkedca.Webhook_X509.String() == wh.CertType
}
