package api

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"
	"github.com/smallstep/certificates/api/read"
	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/linkedca"
	"go.step.sm/crypto/randutil"
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
	if _, ok := linkedca.Webhook_Kind_name[int32(webhook.Kind)]; !ok || webhook.Kind == linkedca.Webhook_NO_KIND {
		return admin.NewError(admin.ErrorBadRequestType, "webhook kind %q is invalid", webhook.Kind)
	}

	return nil
}

func (war *webhookAdminResponder) CreateProvisionerWebhook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	auth := mustAuthority(ctx)
	prov := linkedca.MustProvisionerFromContext(ctx)

	var newWebhook = new(linkedca.Webhook)
	if err := read.ProtoJSON(r.Body, newWebhook); err != nil {
		render.Error(w, r, err)
		return
	}

	if err := validateWebhook(newWebhook); err != nil {
		render.Error(w, r, err)
		return
	}
	if newWebhook.Secret != "" {
		err := admin.NewError(admin.ErrorBadRequestType, "webhook secret must not be set")
		render.Error(w, r, err)
		return
	}
	if newWebhook.Id != "" {
		err := admin.NewError(admin.ErrorBadRequestType, "webhook ID must not be set")
		render.Error(w, r, err)
		return
	}

	id, err := randutil.UUIDv4()
	if err != nil {
		render.Error(w, r, admin.WrapErrorISE(err, "error generating webhook id"))
		return
	}
	newWebhook.Id = id

	// verify the name is unique
	for _, wh := range prov.Webhooks {
		if wh.Name == newWebhook.Name {
			err := admin.NewError(admin.ErrorConflictType, "provisioner %q already has a webhook with the name %q", prov.Name, newWebhook.Name)
			render.Error(w, r, err)
			return
		}
	}

	secret, err := randutil.Bytes(64)
	if err != nil {
		render.Error(w, r, admin.WrapErrorISE(err, "error generating webhook secret"))
		return
	}
	newWebhook.Secret = base64.StdEncoding.EncodeToString(secret)

	prov.Webhooks = append(prov.Webhooks, newWebhook)

	if err := auth.UpdateProvisioner(ctx, prov); err != nil {
		if isBadRequest(err) {
			render.Error(w, r, admin.WrapError(admin.ErrorBadRequestType, err, "error creating provisioner webhook"))
			return
		}

		render.Error(w, r, admin.WrapErrorISE(err, "error creating provisioner webhook"))
		return
	}

	render.ProtoJSONStatus(w, newWebhook, http.StatusCreated)
}

func (war *webhookAdminResponder) DeleteProvisionerWebhook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	auth := mustAuthority(ctx)
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
		render.JSONStatus(w, r, DeleteResponse{Status: "ok"}, http.StatusOK)
		return
	}

	if err := auth.UpdateProvisioner(ctx, prov); err != nil {
		if isBadRequest(err) {
			render.Error(w, r, admin.WrapError(admin.ErrorBadRequestType, err, "error deleting provisioner webhook"))
			return
		}

		render.Error(w, r, admin.WrapErrorISE(err, "error deleting provisioner webhook"))
		return
	}

	render.JSONStatus(w, r, DeleteResponse{Status: "ok"}, http.StatusOK)
}

func (war *webhookAdminResponder) UpdateProvisionerWebhook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	auth := mustAuthority(ctx)
	prov := linkedca.MustProvisionerFromContext(ctx)

	var newWebhook = new(linkedca.Webhook)
	if err := read.ProtoJSON(r.Body, newWebhook); err != nil {
		render.Error(w, r, err)
		return
	}

	if err := validateWebhook(newWebhook); err != nil {
		render.Error(w, r, err)
		return
	}

	found := false
	for i, wh := range prov.Webhooks {
		if wh.Name != newWebhook.Name {
			continue
		}
		if newWebhook.Secret != "" && newWebhook.Secret != wh.Secret {
			err := admin.NewError(admin.ErrorBadRequestType, "webhook secret cannot be updated")
			render.Error(w, r, err)
			return
		}
		newWebhook.Secret = wh.Secret
		if newWebhook.Id != "" && newWebhook.Id != wh.Id {
			err := admin.NewError(admin.ErrorBadRequestType, "webhook ID cannot be updated")
			render.Error(w, r, err)
			return
		}
		newWebhook.Id = wh.Id
		prov.Webhooks[i] = newWebhook
		found = true
		break
	}
	if !found {
		msg := fmt.Sprintf("provisioner %q has no webhook with the name %q", prov.Name, newWebhook.Name)
		err := admin.NewError(admin.ErrorNotFoundType, "%s", msg)
		render.Error(w, r, err)
		return
	}

	if err := auth.UpdateProvisioner(ctx, prov); err != nil {
		if isBadRequest(err) {
			render.Error(w, r, admin.WrapError(admin.ErrorBadRequestType, err, "error updating provisioner webhook"))
			return
		}

		render.Error(w, r, admin.WrapErrorISE(err, "error updating provisioner webhook"))
		return
	}

	// Return a copy without the signing secret. Include the client-supplied
	// auth secrets since those may have been updated in this request and we
	// should show in the response that they changed
	whResponse := &linkedca.Webhook{
		Id:                   newWebhook.Id,
		Name:                 newWebhook.Name,
		Url:                  newWebhook.Url,
		Kind:                 newWebhook.Kind,
		CertType:             newWebhook.CertType,
		Auth:                 newWebhook.Auth,
		DisableTlsClientAuth: newWebhook.DisableTlsClientAuth,
	}
	render.ProtoJSONStatus(w, whResponse, http.StatusCreated)
}
