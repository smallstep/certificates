package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetBaseUrl(t *testing.T) {
	tests := []struct {
		testFailedDescription string
		targetURL             string
		expectedResult        string
		requestPreparer       func(*http.Request)
	}{
		{
			"HTTP host pass-through failed.",
			"http://my.dummy.host",
			"http://my.dummy.host",
			nil,
		},
		{
			"HTTPS host pass-through failed.",
			"https://my.dummy.host",
			"https://my.dummy.host",
			nil,
		},
		{
			"Port pass-through failed",
			"http://host.with.port:8080",
			"http://host.with.port:8080",
			nil,
		},
		{
			"Explicit host from Request.Host was not used.",
			"http://some.target.host:8080",
			"http://proxied.host",
			func(r *http.Request) {
				r.Host = "proxied.host"
			},
		},
		{
			"Explicit forwarded protocol from request header X-Forwarded-Proto was not used.",
			"http://some.host",
			"ssl://some.host",
			func(r *http.Request) {
				r.Header.Add("X-Forwarded-Proto", "ssl")
			},
		},
		{
			"Missing Request.Host value did not result in empty string result.",
			"http://some.host",
			"",
			func(r *http.Request) {
				r.Host = ""
			},
		},
	}

	for _, test := range tests {
		request := httptest.NewRequest("GET", test.targetURL, nil)
		if test.requestPreparer != nil {
			test.requestPreparer(request)
		}
		result := baseURLFromRequest(request)
		if result != test.expectedResult {
			t.Errorf("Expected %q, but got %q", test.expectedResult, result)
		}
	}
}
