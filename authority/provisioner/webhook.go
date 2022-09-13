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
)

type Webhook struct {
	ID                   string `json:"id"`
	Name                 string `json:"name"`
	URL                  string `json:"url"`
	Kind                 string `json:"kind"`
	DisableTLSClientAuth bool   `json:"disableTLSClientAuth,omitempty"`
	SigningSecret        string `json:"-"`
	BearerToken          string `json:"-"`
	BasicAuth            struct {
		Username string
		Password string
	} `json:"-"`
}

type sshRequest struct {
	Key        []byte
	Type       string
	KeyID      string
	Principals []string
}

func (w *Webhook) Do(ctx context.Context, client *http.Client, reqBody *webhook.RequestBody, data map[string]interface{}) (*webhook.ResponseBody, error) {
	tmpl, err := template.New("url").Funcs(templates.StepFuncMap()).Parse(w.URL)
	if err != nil {
		return nil, err
	}
	buf := &bytes.Buffer{}
	if err := tmpl.Execute(buf, data); err != nil {
		return nil, err
	}
	url := buf.String()

	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	retries := 1
retry:
	reqBody.Timestamp = time.Now()

	reqBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(reqBytes))
	if err != nil {
		return nil, err
	}

	secret, err := base64.StdEncoding.DecodeString(w.SigningSecret)
	if err != nil {
		return nil, err
	}
	sig := hmac.New(sha256.New, secret).Sum(reqBytes)
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
		if err == context.DeadlineExceeded {
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
