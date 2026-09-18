package acme

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smallstep/certificates/authority/provisioner"
)

func TestChallengeFailFast(t *testing.T) {
	getErr := func(string) (*http.Response, error) { return nil, errors.New("no such host") }
	get404 := func(string) (*http.Response, error) {
		return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader(""))}, nil
	}
	dialErr := func(string, string, *tls.Config) (*tls.Conn, error) {
		return nil, errors.New("connection refused")
	}

	tests := []struct {
		name     string
		typ      ChallengeType
		vc       *mockClient
		prov     Provisioner // nil: no provisioner in context
		expected Status
	}{
		{"http-01/get-error/fail-fast", HTTP01, &mockClient{get: getErr}, &provisioner.ACME{ChallengeFailFast: true}, StatusInvalid},
		{"http-01/get-error/default", HTTP01, &mockClient{get: getErr}, &provisioner.ACME{}, StatusPending},
		{"http-01/get-error/no-provisioner", HTTP01, &mockClient{get: getErr}, nil, StatusPending},
		{"http-01/404/fail-fast", HTTP01, &mockClient{get: get404}, &provisioner.ACME{ChallengeFailFast: true}, StatusInvalid},
		{"http-01/404/default", HTTP01, &mockClient{get: get404}, &provisioner.ACME{}, StatusPending},
		{"tls-alpn-01/dial-error/fail-fast", TLSALPN01, &mockClient{tlsDial: dialErr}, &provisioner.ACME{ChallengeFailFast: true}, StatusInvalid},
		{"tls-alpn-01/dial-error/default", TLSALPN01, &mockClient{tlsDial: dialErr}, &provisioner.ACME{}, StatusPending},
		{"dns-01/lookup-error/fail-fast-ignored", DNS01, &mockClient{lookupTxt: func(string) ([]string, error) {
			return nil, errors.New("no such host")
		}}, &provisioner.ACME{ChallengeFailFast: true}, StatusPending},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ch := &Challenge{ID: "chID", Token: "token", Type: tc.typ, Value: "zap.internal", Status: StatusPending}
			var stored *Challenge
			db := &MockDB{
				MockUpdateChallenge: func(_ context.Context, updch *Challenge) error {
					stored = updch
					return nil
				},
			}
			ctx := NewClientContext(context.Background(), tc.vc)
			if tc.prov != nil {
				ctx = NewProvisionerContext(ctx, tc.prov)
			}

			require.NoError(t, ch.Validate(ctx, db, nil, nil))
			require.NotNil(t, stored)
			assert.Equal(t, tc.expected, stored.Status)
			assert.NotNil(t, stored.Error)
		})
	}
}
