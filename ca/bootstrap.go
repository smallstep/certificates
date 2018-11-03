package ca

import (
	"context"
	"net/http"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/jose"
	"gopkg.in/square/go-jose.v2/jwt"
)

type tokenClaims struct {
	SHA string `json:"sha"`
	jose.Claims
}

// Bootstrap is a helper function that initializes a client with the
// configuration in the bootstrap token.
func Bootstrap(token string) (*Client, error) {
	tok, err := jwt.ParseSigned(token)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing token")
	}
	var claims tokenClaims
	if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, errors.Wrap(err, "error parsing ott")
	}

	// Validate bootstrap token
	switch {
	case len(claims.SHA) == 0:
		return nil, errors.New("invalid bootstrap token: sha claim is not present")
	case !strings.HasPrefix(strings.ToLower(claims.Audience[0]), "http"):
		return nil, errors.New("invalid bootstrap token: aud claim is not a url")
	}

	return NewClient(claims.Audience[0], WithRootSHA256(claims.SHA))
}

// BootstrapServer is a helper function that returns an http.Server configured
// with the given address and handler, and prepared to use TLS connections. The
// certificate will automatically rotate if necessary.
//
// Usage:
//   srv, err := ca.BootstrapServer(":443", token, handler)
//   if err != nil {
//       return err
//   }
//   srv.ListenAndServeTLS("", "")
func BootstrapServer(addr, token string, handler http.Handler) (*http.Server, error) {
	client, err := Bootstrap(token)
	if err != nil {
		return nil, err
	}

	req, pk, err := CreateSignRequest(token)
	if err != nil {
		return nil, err
	}

	sign, err := client.Sign(req)
	if err != nil {
		return nil, err
	}

	tlsConfig, err := client.GetServerTLSConfig(context.Background(), sign, pk)
	if err != nil {
		return nil, err
	}

	return &http.Server{
		Addr:      addr,
		Handler:   handler,
		TLSConfig: tlsConfig,
	}, nil
}

// BootstrapClient is a helper function that using the given bootstrap token
// return an http.Client configured with a Transport prepared to do TLS
// connections using the client certificate returned by the certificate
// authority. The certificate will automatically rotate if necessary.
//
// Usage:
//   client, err := ca.BootstrapClient(token)
//   if err != nil {
//     return err
//   }
//   resp, err := client.Get("https://internal.smallstep.com")
func BootstrapClient(token string) (*http.Client, error) {
	client, err := Bootstrap(token)
	if err != nil {
		return nil, err
	}

	req, pk, err := CreateSignRequest(token)
	if err != nil {
		return nil, err
	}

	sign, err := client.Sign(req)
	if err != nil {
		return nil, err
	}

	transport, err := client.Transport(context.Background(), sign, pk)
	if err != nil {
		return nil, err
	}

	return &http.Client{
		Transport: transport,
	}, nil
}
