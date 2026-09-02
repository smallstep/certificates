package provisioner

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInClusterK8sSATokenReviewer_Review(t *testing.T) {
	const (
		presentedToken = "presented-service-account-token"
		reviewerToken  = "token-reviewer-credential"
		rotatedToken   = "rotated-token-reviewer-credential"
		audience       = "https://ca.example.com/1.0/sign"
	)

	var expectedCredential atomic.Value
	expectedCredential.Store(reviewerToken)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "Bearer "+expectedCredential.Load().(string), r.Header.Get("Authorization"))
		require.Equal(t, "application/json", r.Header.Get("Content-Type"))

		var review k8sSATokenReview
		require.NoError(t, json.NewDecoder(r.Body).Decode(&review))
		require.Equal(t, "authentication.k8s.io/v1", review.APIVersion)
		require.Equal(t, "TokenReview", review.Kind)
		require.Equal(t, presentedToken, review.Spec.Token)
		require.Equal(t, []string{audience}, review.Spec.Audiences)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		require.NoError(t, json.NewEncoder(w).Encode(k8sSATokenReview{
			APIVersion: "authentication.k8s.io/v1",
			Kind:       "TokenReview",
			Status: &k8sSATokenReviewStatus{
				Authenticated: true,
				Audiences:     []string{audience},
				User: k8sSATokenReviewUser{
					Username: "system:serviceaccount:payments:issuer",
					UID:      "f0e1d2c3",
				},
			},
		}))
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.crt")
	tokenFile := filepath.Join(dir, "token")
	require.NoError(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: server.Certificate().Raw,
	}), 0o600))
	require.NoError(t, os.WriteFile(tokenFile, []byte(reviewerToken+"\n"), 0o600))

	reviewer, err := newK8sSATokenReviewer(server.URL, caFile, tokenFile)
	require.NoError(t, err)
	status, err := reviewer.Review(context.Background(), presentedToken, []string{audience})
	require.NoError(t, err)
	require.True(t, status.Authenticated)
	require.Equal(t, []string{audience}, status.Audiences)
	require.Equal(t, "system:serviceaccount:payments:issuer", status.User.Username)
	require.Equal(t, "f0e1d2c3", status.User.UID)

	expectedCredential.Store(rotatedToken)
	require.NoError(t, os.WriteFile(tokenFile, []byte(rotatedToken+"\n"), 0o600))
	_, err = reviewer.Review(context.Background(), presentedToken, []string{audience})
	require.NoError(t, err)
}

func TestNewInClusterK8sSATokenReviewer(t *testing.T) {
	t.Run("missing-host", func(t *testing.T) {
		t.Setenv("KUBERNETES_SERVICE_HOST", "")
		t.Setenv("KUBERNETES_SERVICE_PORT_HTTPS", "")
		t.Setenv("KUBERNETES_SERVICE_PORT", "")

		_, err := newInClusterK8sSATokenReviewer()
		require.ErrorContains(t, err, "KUBERNETES_SERVICE_HOST is not set")
	})

	t.Run("missing-port", func(t *testing.T) {
		t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
		t.Setenv("KUBERNETES_SERVICE_PORT_HTTPS", "")
		t.Setenv("KUBERNETES_SERVICE_PORT", "")

		_, err := newInClusterK8sSATokenReviewer()
		require.ErrorContains(t, err, "KUBERNETES_SERVICE_PORT_HTTPS and KUBERNETES_SERVICE_PORT are not set")
	})
}

func TestInClusterK8sSATokenReviewer_ReviewErrors(t *testing.T) {
	tests := map[string]struct {
		status int
		body   string
		prefix string
	}{
		"http-status": {
			status: http.StatusForbidden,
			body:   `{}`,
			prefix: "Kubernetes TokenReview API returned HTTP status 403 Forbidden",
		},
		"invalid-json": {
			status: http.StatusOK,
			body:   `{`,
			prefix: "error decoding Kubernetes TokenReview response",
		},
		"missing-status": {
			status: http.StatusOK,
			body:   `{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview"}`,
			prefix: "Kubernetes TokenReview response does not contain status",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			t.Cleanup(server.Close)

			tokenFile := filepath.Join(t.TempDir(), "token")
			require.NoError(t, os.WriteFile(tokenFile, []byte("reviewer-token"), 0o600))
			reviewer := &inClusterK8sSATokenReviewer{
				client:    server.Client(),
				url:       server.URL,
				tokenFile: tokenFile,
			}

			_, err := reviewer.Review(context.Background(), "presented-token", []string{"step-ca"})
			require.Error(t, err)
			require.ErrorContains(t, err, tt.prefix)
		})
	}
}

func TestInClusterK8sSATokenReviewer_ReviewRejectsLargeResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, k8sSAMaxResponseSize+1))
	}))
	t.Cleanup(server.Close)

	tokenFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("reviewer-token"), 0o600))
	reviewer := &inClusterK8sSATokenReviewer{
		client:    server.Client(),
		url:       server.URL,
		tokenFile: tokenFile,
	}

	_, err := reviewer.Review(context.Background(), "presented-token", []string{"step-ca"})
	require.ErrorContains(t, err, "Kubernetes TokenReview response is too large")
}

func TestParseK8sSAUsername(t *testing.T) {
	namespace, serviceAccount, ok := parseK8sSAUsername("system:serviceaccount:payments:issuer")
	require.True(t, ok)
	require.Equal(t, "payments", namespace)
	require.Equal(t, "issuer", serviceAccount)

	for _, username := range []string{
		"",
		"alice",
		"system:serviceaccount::issuer",
		"system:serviceaccount:payments:",
		"system:user:payments:issuer",
	} {
		_, _, ok := parseK8sSAUsername(username)
		require.False(t, ok, username)
	}
}

func TestMatchesK8sSAAudience(t *testing.T) {
	require.True(t, matchesK8sSAAudience([]string{"sign", "legacy-sign"}, []string{"sign"}))
	require.False(t, matchesK8sSAAudience([]string{"sign"}, nil))
	require.False(t, matchesK8sSAAudience([]string{"sign"}, []string{"kubernetes"}))
}
