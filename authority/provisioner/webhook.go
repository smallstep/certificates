package provisioner

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"text/template"
	"time"

	"github.com/smallstep/certificates/templates"
	"go.step.sm/crypto/sshutil"
)

type Webhook struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	URL           string `json:"url"`
	Kind          string `json:"kind"`
	SigningSecret string `json:"-"`
	BearerToken   string `json:"-"`
	BasicAuth     struct {
		Username string
		Password string
	} `json:"-"`
}

type webhookRequestBody struct {
	Timestamp string                     `json:"timestamp"`
	X509_CSR  []byte                     `json:"csr,omitempty"`
	SSH_CR    sshutil.CertificateRequest `json:"ssh_cr,omitempty"`
}

type webhookResponseBody struct {
	Data map[string]interface{} `json:"data"`
}

func (w *Webhook) Do(ctx context.Context, client *http.Client, certReq interface{}, data map[string]interface{}) (map[string]interface{}, error) {
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
	reqBody := &webhookRequestBody{
		Timestamp: time.Now().Format(time.RFC3339Nano),
	}
	switch r := certReq.(type) {
	case *x509.CertificateRequest:
		if r != nil {
			reqBody.X509_CSR = r.Raw
		}
	case sshutil.CertificateRequest:
		reqBody.SSH_CR = r
	}

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
	if resp.StatusCode >= 500 {
		if retries > 0 {
			retries--
			time.Sleep(time.Second)
			goto retry
		}
		return nil, fmt.Errorf("Webhook server responded with %d", resp.StatusCode)
	}

	respBody := &webhookResponseBody{
		Data: map[string]interface{}{},
	}
	if err := json.NewDecoder(resp.Body).Decode(respBody); err != nil {
		return nil, err
	}

	return respBody.Data, nil
}
