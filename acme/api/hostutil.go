package api

import (
	"net/http"
)

// baseURLFromRequest determines the base URL which should be used for constructing link URLs in e.g. the ACME directory
// result by taking the request Host, TLS and Header[X-Forwarded-Proto] values into consideration.
// If the Request.Host is an empty string, we return an empty string, to indicate that the configured
// URL values should be used instead.
// If this function returns a non-empty result, then this should be used in constructing ACME link URLs.
func baseURLFromRequest(r *http.Request) string {
	// TODO: I semantically copied the functionality of determining the protol from boulder web/relative.go
	// which allows HTTP. Previously this was always forced to be HTTPS for absolute URLs. Should this be
	// changed to also always force HTTPS protocol?
	proto := "http"
	if specifiedProto := r.Header.Get("X-Forwarded-Proto"); specifiedProto != "" {
		proto = specifiedProto
	} else if r.TLS != nil {
		proto += "s"
	}

	host := r.Host
	if host == "" {
		return ""
	}
	return proto + "://" + host
}
