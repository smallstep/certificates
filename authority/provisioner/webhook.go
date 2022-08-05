package provisioner

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"text/template"
	"time"

	"github.com/smallstep/certificates/templates"
)

type Webhook struct {
	Name          string `json:"name"`
	URL           string `json:"url"`
	BearerToken   string `json:"-"`
	Username      string `json:"-"`
	Password      string `json:"-"`
	SigningSecret []byte `json:"-"`
}

type webhookRequestBody struct {
	Timestamp string `json:"timstamp"`
	CSR       []byte `json:"csr"`
}

type webhookResponseBody struct {
	Data map[string]interface{} `json:"data"`
}

func (w *Webhook) Do(ctx context.Context, client *http.Client, csr *x509.CertificateRequest, data map[string]interface{}) (map[string]interface{}, error) {
	tmpl, err := template.New("url").Funcs(templates.StepFuncMap()).Parse(w.URL)
	if err != nil {
		return nil, err
	}
	buf := &bytes.Buffer{}
	if err := tmpl.Execute(buf, data); err != nil {
		return nil, err
	}
	url := buf.String()

	retries := 1
retry:
	reqBody := &webhookRequestBody{
		Timestamp: time.Now().Format(time.RFC3339Nano),
		CSR:       csr.Raw,
	}

	reqBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(reqBytes))
	if err != nil {
		return nil, err
	}

	sig := hmac.New(sha256.New, w.SigningSecret).Sum(reqBytes)
	req.Header.Set("X-Smallstep-Signature", hex.EncodeToString(sig))

	if w.BearerToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", w.BearerToken))
	} else if w.Username != "" || w.Password != "" {
		req.SetBasicAuth(w.Username, w.Password)
	}

	// TODO get request ID from context

	resp, err := client.Do(req)
	if err != nil {
		if retries > 0 {
			retries--
			goto retry
		}
		return nil, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Failed to close body of response from %s", w.URL)
		}
	}()

	respBody := &webhookResponseBody{
		Data: map[string]interface{}{},
	}
	if err := json.NewDecoder(resp.Body).Decode(respBody); err != nil {
		return nil, err
	}

	return respBody.Data, nil
}
