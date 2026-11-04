package provisioner

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/smallstep/certificates/webhook"
	"github.com/stretchr/testify/require"
)

func TestRedactWebhookURLError(t *testing.T) {
	const name = "test-webhook"

	// path and query are marked, not shown; the webhook name is included
	err := &url.Error{Op: "Post", URL: "https://hooks.example.com/validate?token=secret", Err: errors.New("connection refused")}
	got := redactWebhookURLError(err, name)
	require.Equal(t, `webhook "test-webhook": Post "https://hooks.example.com/<redacted>?<redacted>": connection refused`, got.Error())
	require.NotContains(t, got.Error(), "token=secret")
	require.NotContains(t, got.Error(), "/validate")

	// userinfo is marked too
	withUser := &url.Error{Op: "Post", URL: "https://user:token@hooks.example.com/validate", Err: errors.New("connection refused")}
	got = redactWebhookURLError(withUser, name)
	require.Equal(t, `webhook "test-webhook": Post "https://<redacted>@hooks.example.com/<redacted>": connection refused`, got.Error())
	require.NotContains(t, got.Error(), "user:token")

	// a bare host with a root path renders without markers
	bare := &url.Error{Op: "Post", URL: "https://hooks.example.com/", Err: errors.New("connection refused")}
	require.Equal(t, `webhook "test-webhook": Post "https://hooks.example.com": connection refused`, redactWebhookURLError(bare, name).Error())

	// deadline errors keep working through the wrapper
	deadline := &url.Error{Op: "Post", URL: "https://hooks.example.com/x?token=secret", Err: context.DeadlineExceeded}
	require.ErrorIs(t, redactWebhookURLError(deadline, name), context.DeadlineExceeded)

	// fail closed when the URL cannot be parsed: no raw URL, name and cause kept
	bad := &url.Error{Op: "Post", URL: "https://hooks.example.com/val%zz?token=secret", Err: errors.New("connection refused")}
	got = redactWebhookURLError(bad, name)
	require.Equal(t, `webhook "test-webhook": Post "<redacted>": connection refused`, got.Error())
	require.NotContains(t, got.Error(), "token=secret")
	require.ErrorIs(t, got, bad.Err)

	// non-URL errors pass through unchanged, without a name prefix
	plain := errors.New("boom")
	require.Equal(t, plain, redactWebhookURLError(plain, name))
}

func TestRedactURLString(t *testing.T) {
	// a URL template with actions still parses and redacts
	require.Equal(t,
		`https://hooks.example.com/<redacted>?<redacted>`,
		redactURLString(`https://hooks.example.com/{{ .Webhooks.ScepChallenge.ID }}/validate?token=x`))
	// unparseable input fails closed
	require.Equal(t, "<redacted>", redactURLString("https://hooks.example.com/val%zz?token=x\n"))
}

func TestWebhookDoWithContextRedactsURL(t *testing.T) {
	w := &Webhook{
		Name:   "test-webhook",
		URL:    "http://127.0.0.1:1/validate?token=secret",
		Secret: base64.StdEncoding.EncodeToString([]byte("secret")),
	}

	_, err := w.DoWithContext(context.Background(), &http.Client{}, nil, &webhook.RequestBody{}, nil)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "token=secret")
	require.NotContains(t, err.Error(), "/validate")
	require.Contains(t, err.Error(), `webhook "test-webhook": Post "http://127.0.0.1:1/<redacted>?<redacted>"`)
	require.Contains(t, err.Error(), "connection refused")
}

func TestWebhookDoWithContextRedactsNewRequestError(t *testing.T) {
	// A control character in the templated URL makes NewRequestWithContext
	// fail; its error carries the raw expanded URL and must be redacted too.
	w := &Webhook{
		Name:   "test-webhook",
		URL:    "http://127.0.0.1:1/validate?token=secret\n",
		Secret: base64.StdEncoding.EncodeToString([]byte("secret")),
	}

	_, err := w.DoWithContext(context.Background(), &http.Client{}, nil, &webhook.RequestBody{}, nil)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "token=secret")
	require.Contains(t, err.Error(), `webhook "test-webhook"`)
	require.Contains(t, err.Error(), "<redacted>")
}
