package authority

import "github.com/smallstep/certificates/webhook"

type webhookController interface {
	Enrich(*webhook.RequestBody) error
	Authorize(*webhook.RequestBody) error
}
