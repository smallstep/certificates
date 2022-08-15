package api

import "net/http"

// WebhookAdminResponder is the interface responsible for writing webhook admin
// responses.
type WebhookAdminResponder interface {
	CreateProvisionerWebhook(w http.ResponseWriter, r *http.Request)
	GetProvisionerWebhooks(w http.ResponseWriter, r *http.Request)
	DeleteProvisionerWebhook(w http.ResponseWriter, r *http.Request)
}

// webhoookAdminResponder implements WebhookAdminResponder
type webhookAdminResponder struct{}

// NewWebhookAdminResponder returns a new WebhookAdminResponder
func NewWebhookAdminResponder() WebhookAdminResponder {
	return &webhookAdminResponder{}
}

func (war *webhookAdminResponder) CreateProvisionerWebhook(w http.ResponseWriter, r *http.Request) {
	// ctx := r.Context()

	// auth := mustAuthority(ctx)

}

func (war *webhookAdminResponder) DeleteProvisionerWebhook(w http.ResponseWriter, r *http.Request) {

}

func (war *webhookAdminResponder) GetProvisionerWebhooks(w http.ResponseWriter, r *http.Request) {

}
