package provisioner

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
)

const (
	k8sSATokenReviewPath = "/apis/authentication.k8s.io/v1/tokenreviews"
	k8sSAServiceToken    = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	k8sSAServiceCA       = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	k8sSAMaxResponseSize = 1 << 20
)

type k8sSATokenReviewer interface {
	Review(ctx context.Context, token string, audiences []string) (*k8sSATokenReviewStatus, error)
}

type k8sSATokenReviewSpec struct {
	Token     string   `json:"token"`
	Audiences []string `json:"audiences,omitempty"`
}

type k8sSATokenReviewUser struct {
	Username string              `json:"username"`
	UID      string              `json:"uid,omitempty"`
	Groups   []string            `json:"groups,omitempty"`
	Extra    map[string][]string `json:"extra,omitempty"`
}

type k8sSATokenReviewStatus struct {
	Authenticated bool                 `json:"authenticated"`
	User          k8sSATokenReviewUser `json:"user,omitempty"`
	Audiences     []string             `json:"audiences,omitempty"`
	Error         string               `json:"error,omitempty"`
}

type k8sSATokenReview struct {
	APIVersion string                  `json:"apiVersion"`
	Kind       string                  `json:"kind"`
	Spec       k8sSATokenReviewSpec    `json:"spec"`
	Status     *k8sSATokenReviewStatus `json:"status,omitempty"`
}

type inClusterK8sSATokenReviewer struct {
	client    *http.Client
	url       string
	tokenFile string
}

func newInClusterK8sSATokenReviewer() (*inClusterK8sSATokenReviewer, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	if host == "" {
		return nil, errors.New("KUBERNETES_SERVICE_HOST is not set")
	}
	port := os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS")
	if port == "" {
		port = os.Getenv("KUBERNETES_SERVICE_PORT")
	}
	if port == "" {
		return nil, errors.New("KUBERNETES_SERVICE_PORT_HTTPS and KUBERNETES_SERVICE_PORT are not set")
	}

	u := &url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(host, port),
		Path:   k8sSATokenReviewPath,
	}
	return newK8sSATokenReviewer(u.String(), k8sSAServiceCA, k8sSAServiceToken)
}

func newK8sSATokenReviewer(apiURL, caFile, tokenFile string) (*inClusterK8sSATokenReviewer, error) {
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, errors.Wrap(err, "error reading Kubernetes service account CA")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("error parsing Kubernetes service account CA")
	}
	if _, err := os.Stat(tokenFile); err != nil {
		return nil, errors.Wrap(err, "error accessing Kubernetes reviewer token")
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots,
	}

	return &inClusterK8sSATokenReviewer{
		client: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("redirects are not allowed for Kubernetes TokenReview requests")
			},
		},
		url:       apiURL,
		tokenFile: tokenFile,
	}, nil
}

func (r *inClusterK8sSATokenReviewer) Review(ctx context.Context, token string, audiences []string) (*k8sSATokenReviewStatus, error) {
	reviewerToken, err := os.ReadFile(r.tokenFile)
	if err != nil {
		return nil, errors.Wrap(err, "error reading Kubernetes reviewer token")
	}
	credential := strings.TrimSpace(string(reviewerToken))
	if credential == "" {
		return nil, errors.New("Kubernetes reviewer token is empty")
	}

	payload, err := json.Marshal(k8sSATokenReview{
		APIVersion: "authentication.k8s.io/v1",
		Kind:       "TokenReview",
		Spec: k8sSATokenReviewSpec{
			Token:     token,
			Audiences: audiences,
		},
	})
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling Kubernetes TokenReview request")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(payload))
	if err != nil {
		return nil, errors.Wrap(err, "error creating Kubernetes TokenReview request")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+credential)
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "error sending Kubernetes TokenReview request")
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("Kubernetes TokenReview API returned HTTP status %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, k8sSAMaxResponseSize+1))
	if err != nil {
		return nil, errors.Wrap(err, "error reading Kubernetes TokenReview response")
	}
	if len(body) > k8sSAMaxResponseSize {
		return nil, errors.New("Kubernetes TokenReview response is too large")
	}

	var review k8sSATokenReview
	if err := json.Unmarshal(body, &review); err != nil {
		return nil, errors.Wrap(err, "error decoding Kubernetes TokenReview response")
	}
	if review.Status == nil {
		return nil, errors.New("Kubernetes TokenReview response does not contain status")
	}

	return review.Status, nil
}

func parseK8sSAUsername(username string) (namespace, serviceAccount string, ok bool) {
	parts := strings.Split(username, ":")
	if len(parts) != 4 || parts[0] != "system" || parts[1] != "serviceaccount" || parts[2] == "" || parts[3] == "" {
		return "", "", false
	}
	return parts[2], parts[3], true
}

func matchesK8sSAAudience(expected, actual []string) bool {
	for _, want := range expected {
		for _, got := range actual {
			if want == got {
				return true
			}
		}
	}
	return false
}
