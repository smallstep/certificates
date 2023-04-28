package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/ryboe/q"
)

type Controller struct {
	client  *http.Client
	webhook *Webhook
}

func New(options ...ControllerOption) (*Controller, error) {
	c := &Controller{
		client:  http.DefaultClient,
		webhook: &Webhook{},
	}
	for _, apply := range options {
		if err := apply(c); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (c *Controller) Validate(challenge string) (bool, error) {
	req := &Request{
		Challenge: challenge,
	}
	client := c.client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := c.webhook.Do(client, req)
	if err != nil {
		q.Q(err)
		return false, fmt.Errorf("failed performing webhook request: %w", err)
	}

	if resp == nil {
		return false, nil
	}

	return true, nil
}

type Webhook struct {
	URL                  string
	DisableTLSClientAuth bool
	Secret               string
	BearerToken          string
	BasicAuth            struct {
		Username string
		Password string
	}
}

func (w *Webhook) Do(client *http.Client, req *Request) (*Response, error) {

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	retries := 1
retry:

	r, err := http.NewRequestWithContext(ctx, "POST", w.URL, bytes.NewReader(reqBytes))
	if err != nil {
		return nil, err
	}

	if w.Secret != "" {
		secret, err := base64.StdEncoding.DecodeString(w.Secret)
		if err != nil {
			return nil, err
		}
		sig := hmac.New(sha256.New, secret).Sum(reqBytes)
		r.Header.Set("X-Smallstep-Signature", hex.EncodeToString(sig))
		//req.Header.Set("X-Smallstep-Webhook-ID", w.ID)
	}

	if w.BearerToken != "" {
		r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", w.BearerToken))
	} else if w.BasicAuth.Username != "" || w.BasicAuth.Password != "" {
		r.SetBasicAuth(w.BasicAuth.Username, w.BasicAuth.Password)
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

	resp, err := client.Do(r)
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
			// TODO: return this error instead of (just) logging?
			log.Printf("failed to close body of response from %s", w.URL)
		}
	}()

	if resp.StatusCode >= 500 && retries > 0 {
		retries--
		time.Sleep(time.Second)
		goto retry
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("webhook server responded with %d", resp.StatusCode)
	}

	respBody := &Response{}
	// TODO: decide on the JSON structure for the response (if any); HTTP status code may be enough.
	// if err := json.NewDecoder(resp.Body).Decode(respBody); err != nil {
	// 	return nil, err
	// }

	return respBody, nil
}

type Request struct {
	Challenge string `json:"challenge"`
}

type Response struct {
	// TODO: define expected response format? Or do we consider 200 OK enough?
	Allow bool `json:"allow"`
}
