package api

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"

	"github.com/go-chi/chi"
	"github.com/smallstep/certificates/api/read"
	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority/admin"
	"go.step.sm/crypto/randutil"
	"go.step.sm/linkedca"
)

// WebhookAdminResponder is the interface responsible for writing webhook admin
// responses.
type WebhookAdminResponder interface {
	CreateProvisionerWebhook(w http.ResponseWriter, r *http.Request)
	UpdateProvisionerWebhook(w http.ResponseWriter, r *http.Request)
	DeleteProvisionerWebhook(w http.ResponseWriter, r *http.Request)
}

// webhoookAdminResponder implements WebhookAdminResponder
type webhookAdminResponder struct{}

// NewWebhookAdminResponder returns a new WebhookAdminResponder
func NewWebhookAdminResponder() WebhookAdminResponder {
	return &webhookAdminResponder{}
}

func validateWebhook(webhook *linkedca.Webhook) error {
	if webhook == nil {
		return nil
	}

	// name
	if webhook.Name == "" {
		return admin.NewError(admin.ErrorBadRequestType, "webhook name is required")
	}

	// url
	parsedURL, err := url.Parse(webhook.Url)
	if err != nil {
		return admin.NewError(admin.ErrorBadRequestType, "webhook url is invalid")
	}
	if parsedURL.Host == "" {
		return admin.NewError(admin.ErrorBadRequestType, "webhook url is invalid")
	}
	if parsedURL.Scheme != "https" {
		return admin.NewError(admin.ErrorBadRequestType, "webhook url must use https")
	}
	if parsedURL.User != nil {
		return admin.NewError(admin.ErrorBadRequestType, "webhook url may not contain username or password")
	}

	// kind
	if webhook.Kind != linkedca.Webhook_ENRICHING {
		return admin.NewError(admin.ErrorBadRequestType, "webhook kind is invalid")
	}

	// multiple authentication methods
	if webhook.BearerToken != "" && (webhook.Username != "" || webhook.Password != "") {
		return admin.NewError(admin.ErrorBadRequestType, "webhook cannot use both bearer and basic authentication")
	}

	return nil
}

func (war *webhookAdminResponder) CreateProvisionerWebhook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	prov := linkedca.MustProvisionerFromContext(ctx)

	var newWebhook = new(linkedca.Webhook)
	if err := read.ProtoJSON(r.Body, newWebhook); err != nil {
		render.Error(w, err)
		return
	}

	if err := validateWebhook(newWebhook); err != nil {
		render.Error(w, err)
		return
	}

	// verify the name is unique
	for _, wh := range prov.Webhooks {
		if wh.Name == newWebhook.Name {
			err := admin.NewError(admin.ErrorConflictType, "provisioner %s already has a webhook with the name %s", prov.Name, newWebhook.Name)
			render.Error(w, err)
			return
		}
	}

	secret, err := randutil.Bytes(64)
	if err != nil {
		render.Error(w, admin.WrapErrorISE(err, "error generating webhook secret"))
		return
	}
	newWebhook.Secret = base64.StdEncoding.EncodeToString(secret)

	prov.Webhooks = append(prov.Webhooks, newWebhook)

	auth := mustAuthority(ctx)
	if err := auth.UpdateProvisioner(ctx, prov); err != nil {
		if isBadRequest(err) {
			render.Error(w, admin.WrapError(admin.ErrorBadRequestType, err, "error creating provisioner webhook"))
			return
		}

		render.Error(w, admin.WrapErrorISE(err, "error creating provisioner webhook"))
		return
	}

	render.ProtoJSONStatus(w, newWebhook, http.StatusCreated)
}

func (war *webhookAdminResponder) DeleteProvisionerWebhook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	prov := linkedca.MustProvisionerFromContext(ctx)

	webhookName := chi.URLParam(r, "webhookName")

	found := false
	for i, wh := range prov.Webhooks {
		if wh.Name == webhookName {
			prov.Webhooks = append(prov.Webhooks[0:i], prov.Webhooks[i+1:]...)
			found = true
			break
		}
	}
	if !found {
		render.JSONStatus(w, DeleteResponse{Status: "ok"}, http.StatusOK)
		return
	}

	auth := mustAuthority(ctx)
	if err := auth.UpdateProvisioner(ctx, prov); err != nil {
		if isBadRequest(err) {
			render.Error(w, admin.WrapError(admin.ErrorBadRequestType, err, "error deleting provisioner webhook"))
			return
		}

		render.Error(w, admin.WrapErrorISE(err, "error deleting provisioner webhook"))
		return
	}

	render.JSONStatus(w, DeleteResponse{Status: "ok"}, http.StatusOK)
}

func (war *webhookAdminResponder) UpdateProvisionerWebhook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	prov := linkedca.MustProvisionerFromContext(ctx)

	var newWebhook = new(linkedca.Webhook)
	if err := read.ProtoJSON(r.Body, newWebhook); err != nil {
		render.Error(w, err)
		return
	}

	if err := validateWebhook(newWebhook); err != nil {
		render.Error(w, err)
		return
	}

	found := false
	for i, wh := range prov.Webhooks {
		if wh.Name == newWebhook.Name {
			newWebhook.Secret = wh.Secret
			prov.Webhooks[i] = newWebhook
			found = true
			break
		}
	}
	if !found {
		msg := fmt.Sprintf("provisioner %s has no webhook with the name %s", prov.Name, newWebhook.Name)
		err := admin.NewError(admin.ErrorNotFoundType, msg)
		render.Error(w, err)
		return
	}

	auth := mustAuthority(ctx)
	if err := auth.UpdateProvisioner(ctx, prov); err != nil {
		if isBadRequest(err) {
			render.Error(w, admin.WrapError(admin.ErrorBadRequestType, err, "error updating provisioner webhook"))
			return
		}

		render.Error(w, admin.WrapErrorISE(err, "error updating provisioner webhook"))
		return
	}

	render.ProtoJSONStatus(w, newWebhook, http.StatusCreated)
}
