package authority

import (
	"context"

	"github.com/smallstep/certificates/webhook"
)

type webhookController interface {
	Enrich(context.Context, *webhook.RequestBody) error
	Authorize(context.Context, *webhook.RequestBody) error
}
