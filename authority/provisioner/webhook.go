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

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/templates"
	"go.step.sm/crypto/sshutil"
	"golang.org/x/crypto/ssh"
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

// ssh.Certificate but the Key and SignatureKey are marshaled
type sshCert struct {
	Nonce    []byte
	Key      []byte
	Serial   uint64
	CertType uint32
	//nolint:revive // field name matches ssh.Certificate
	KeyId           string
	ValidPrincipals []string
	ValidAfter      uint64
	ValidBefore     uint64
	Permissions     ssh.Permissions
	Reserved        []byte
	SignatureKey    []byte
	Signature       *ssh.Signature
}

type webhookRequestBody struct {
	Timestamp string `json:"timestamp"`
	//nolint:revive // acronyms can use all caps
	X509_CSR []byte `json:"csr,omitempty"`
	//nolint:revive // acronyms can use all caps
	SSH_CR         *sshRequest       `json:"ssh_cr,omitempty"`
	Certificate    *x509.Certificate `json:"certificate,omitempty"`
	SSHCertificate *sshCert          `json:"ssh_certificate,omitempty"`
}

type WebhookResponseBody struct {
	Data  map[string]interface{} `json:"data"`
	Allow bool                   `json:"allow"`
}

func (w *Webhook) Do(ctx context.Context, client *http.Client, certReq interface{}, data map[string]interface{}) (*WebhookResponseBody, error) {
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
		reqBody.SSH_CR = &sshRequest{
			Type:       r.Type,
			KeyID:      r.KeyID,
			Principals: r.Principals,
		}
		if r.Key != nil {
			reqBody.SSH_CR.Key = r.Key.Marshal()
		}
	case *x509.Certificate:
		reqBody.Certificate = r
	case *ssh.Certificate:
		reqBody.SSHCertificate = &sshCert{
			Nonce:           r.Nonce,
			Key:             r.Key.Marshal(),
			Serial:          r.Serial,
			CertType:        r.CertType,
			KeyId:           r.KeyId,
			ValidPrincipals: r.ValidPrincipals,
			ValidAfter:      r.ValidAfter,
			ValidBefore:     r.ValidBefore,
			Permissions:     r.Permissions,
			Reserved:        r.Reserved,
			Signature:       r.Signature,
		}
		if r.Key != nil {
			reqBody.SSHCertificate.Key = r.Key.Marshal()
		}
		if r.SignatureKey != nil {
			reqBody.SSHCertificate.SignatureKey = r.SignatureKey.Marshal()
		}
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

	respBody := &WebhookResponseBody{
		Data: map[string]interface{}{},
	}
	if err := json.NewDecoder(resp.Body).Decode(respBody); err != nil {
		return nil, err
	}

	return respBody, nil
}
