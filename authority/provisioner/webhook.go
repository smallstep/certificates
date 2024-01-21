package provisioner

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"text/template"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/templates"
	"github.com/smallstep/certificates/webhook"
	"go.step.sm/linkedca"
)

var ErrWebhookDenied = errors.New("webhook server did not allow request")

type WebhookSetter interface {
	SetWebhook(string, any)
}

type WebhookController struct {
	client       *http.Client
	webhooks     []*Webhook
	certType     linkedca.Webhook_CertType
	options      []webhook.RequestBodyOption
	TemplateData WebhookSetter
}

// Enrich fetches data from remote servers and adds returned data to the
// templateData
func (wc *WebhookController) Enrich(req *webhook.RequestBody) error {
	if wc == nil {
		return nil
	}

	// Apply extra options in the webhook controller
	for _, fn := range wc.options {
		if err := fn(req); err != nil {
			return err
		}
	}

	for _, wh := range wc.webhooks {
		if wh.Kind != linkedca.Webhook_ENRICHING.String() {
			continue
		}
		if !wc.isCertTypeOK(wh) {
			continue
		}
		resp, err := wh.Do(wc.client, req, wc.TemplateData)
		if err != nil {
			return err
		}
		if !resp.Allow {
			return ErrWebhookDenied
		}
		wc.TemplateData.SetWebhook(wh.Name, resp.Data)
	}
	return nil
}

// Authorize checks that all remote servers allow the request
func (wc *WebhookController) Authorize(req *webhook.RequestBody) error {
	if wc == nil {
		return nil
	}

	// Apply extra options in the webhook controller
	for _, fn := range wc.options {
		if err := fn(req); err != nil {
			return err
		}
	}

	for _, wh := range wc.webhooks {
		if wh.Kind != linkedca.Webhook_AUTHORIZING.String() {
			continue
		}
		if !wc.isCertTypeOK(wh) {
			continue
		}
		resp, err := wh.Do(wc.client, req, wc.TemplateData)
		if err != nil {
			return err
		}
		if !resp.Allow {
			return ErrWebhookDenied
		}
	}
	return nil
}

func (wc *WebhookController) isCertTypeOK(wh *Webhook) bool {
	if wc.certType == linkedca.Webhook_ALL {
		return true
	}
	if wh.CertType == linkedca.Webhook_ALL.String() || wh.CertType == "" {
		return true
	}
	return wc.certType.String() == wh.CertType
}

type Webhook struct {
	ID                   string `json:"id"`
	Name                 string `json:"name"`
	URL                  string `json:"url"`
	Kind                 string `json:"kind"`
	DisableTLSClientAuth bool   `json:"disableTLSClientAuth,omitempty"`
	CertType             string `json:"certType"`
	Secret               string `json:"-"`
	BearerToken          string `json:"-"`
	BasicAuth            struct {
		Username string
		Password string
	} `json:"-"`
}

func (w *Webhook) Do(client *http.Client, reqBody *webhook.RequestBody, data any) (*webhook.ResponseBody, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	return w.DoWithContext(ctx, client, reqBody, data)
}

func (w *Webhook) DoWithContext(ctx context.Context, client *http.Client, reqBody *webhook.RequestBody, data any) (*webhook.ResponseBody, error) {
	tmpl, err := template.New("url").Funcs(templates.StepFuncMap()).Parse(w.URL)
	if err != nil {
		return nil, err
	}
	buf := &bytes.Buffer{}
	if err := tmpl.Execute(buf, data); err != nil {
		return nil, err
	}
	url := buf.String()

	/*
		Sending the token to the webhook server is a security risk. A K8sSA
		token can be reused multiple times. The webhook can misuse it to get
		fake certificates. A webhook can misuse any other token to get its own
		certificate before responding.
		switch tmpl := data.(type) {
		case x509util.TemplateData:
			reqBody.Token = tmpl[x509util.TokenKey]
		case sshutil.TemplateData:
			reqBody.Token = tmpl[sshutil.TokenKey]
		}
	*/

	reqBody.Timestamp = time.Now()

	reqBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	retries := 1
retry:

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(reqBytes))
	if err != nil {
		return nil, err
	}

	secret, err := base64.StdEncoding.DecodeString(w.Secret)
	if err != nil {
		return nil, err
	}
	h := hmac.New(sha256.New, secret)
	h.Write(reqBytes)
	sig := h.Sum(nil)
	req.Header.Set("X-Smallstep-Signature", hex.EncodeToString(sig))
	req.Header.Set("X-Smallstep-Webhook-ID", w.ID)

	if w.BearerToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", w.BearerToken))
	} else if w.BasicAuth.Username != "" || w.BasicAuth.Password != "" {
		req.SetBasicAuth(w.BasicAuth.Username, w.BasicAuth.Password)
	}

	if w.DisableTLSClientAuth {
		transport, ok := client.Transport.(*http.Transport)
		if !ok {
			return nil, errors.New("client transport is not a *http.Transport")
		}
		transport = transport.Clone()
		tlsConfig := transport.TLSClientConfig.Clone()
		tlsConfig.GetClientCertificate = nil
		tlsConfig.Certificates = nil
		transport.TLSClientConfig = tlsConfig
		client = &http.Client{
			Transport: transport,
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		} else if retries > 0 {
			retries--
			time.Sleep(time.Second)
			goto retry
		}
		return nil, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Failed to close body of response from %s", w.URL)
		}
	}()
	if resp.StatusCode >= 500 && retries > 0 {
		retries--
		time.Sleep(time.Second)
		goto retry
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("Webhook server responded with %d", resp.StatusCode)
	}

	respBody := &webhook.ResponseBody{}
	if err := json.NewDecoder(resp.Body).Decode(respBody); err != nil {
		return nil, err
	}

	return respBody, nil
}
