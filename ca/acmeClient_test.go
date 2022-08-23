package ca

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/acme"
	acmeAPI "github.com/smallstep/certificates/acme/api"
	"github.com/smallstep/certificates/api/render"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/pemutil"
)

func TestNewACMEClient(t *testing.T) {
	type test struct {
		ops      []ClientOption
		r1, r2   interface{}
		rc1, rc2 int
		err      error
	}

	srv := httptest.NewServer(nil)
	defer srv.Close()

	dir := acmeAPI.Directory{
		NewNonce:   srv.URL + "/foo",
		NewAccount: srv.URL + "/bar",
		NewOrder:   srv.URL + "/baz",
		RevokeCert: srv.URL + "/zip",
		KeyChange:  srv.URL + "/blorp",
	}
	acc := acme.Account{
		Contact:   []string{"max", "mariano"},
		Status:    "valid",
		OrdersURL: "orders-url",
	}
	tests := map[string]func(t *testing.T) test{
		"fail/client-option-error": func(t *testing.T) test {
			return test{
				ops: []ClientOption{
					func(o *clientOptions) error {
						return errors.New("force")
					},
				},
				err: errors.New("force"),
			}
		},
		"fail/get-directory": func(t *testing.T) test {
			return test{
				ops: []ClientOption{WithTransport(http.DefaultTransport)},
				r1:  acme.NewError(acme.ErrorMalformedType, "malformed request"),
				rc1: 400,
				err: errors.New("The request message was malformed"),
			}
		},
		"fail/bad-directory": func(t *testing.T) test {
			return test{
				ops: []ClientOption{WithTransport(http.DefaultTransport)},
				r1:  "foo",
				rc1: 200,
				err: errors.New("error reading http://127.0.0.1"),
			}
		},
		"fail/error-post-newAccount": func(t *testing.T) test {
			return test{
				ops: []ClientOption{WithTransport(http.DefaultTransport)},
				r1:  dir,
				rc1: 200,
				r2:  acme.NewError(acme.ErrorAccountDoesNotExistType, "account does not exist"),
				rc2: 400,
				err: errors.New("Account does not exist"),
			}
		},
		"fail/error-bad-account": func(t *testing.T) test {
			return test{
				ops: []ClientOption{WithTransport(http.DefaultTransport)},
				r1:  dir,
				rc1: 200,
				r2:  "foo",
				rc2: 200,
				err: errors.New("error reading http://127.0.0.1"),
			}
		},
		"ok": func(t *testing.T) test {
			return test{
				ops: []ClientOption{WithTransport(http.DefaultTransport)},
				r1:  dir,
				rc1: 200,
				r2:  acc,
				rc2: 200,
			}
		},
	}

	accLocation := "linkitylink"

	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)

			i := 0
			srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				assert.Equals(t, "step-http-client/1.0", req.Header.Get("User-Agent")) // check default User-Agent header
				switch {
				case i == 0:
					render.JSONStatus(w, tc.r1, tc.rc1)
					i++
				case i == 1:
					w.Header().Set("Replay-Nonce", "abc123")
					render.JSONStatus(w, []byte{}, 200)
					i++
				default:
					w.Header().Set("Location", accLocation)
					render.JSONStatus(w, tc.r2, tc.rc2)
				}
			})

			if client, err := NewACMEClient(srv.URL, []string{"max", "mariano"}, tc.ops...); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, *client.dir, dir)
					assert.NotNil(t, client.Key)
					assert.NotNil(t, client.acc)
					assert.Equals(t, client.kid, accLocation)
				}
			}
		})
	}
}

func TestACMEClient_GetDirectory(t *testing.T) {
	c := &ACMEClient{
		dir: &acmeAPI.Directory{
			NewNonce:   "/foo",
			NewAccount: "/bar",
			NewOrder:   "/baz",
			RevokeCert: "/zip",
			KeyChange:  "/blorp",
		},
	}
	dir, err := c.GetDirectory()
	assert.FatalError(t, err)
	assert.Equals(t, c.dir, dir)
}

func TestACMEClient_GetNonce(t *testing.T) {
	type test struct {
		r1  interface{}
		rc1 int
		err error
	}

	srv := httptest.NewServer(nil)
	defer srv.Close()

	dir := acmeAPI.Directory{
		NewNonce: srv.URL + "/foo",
	}
	// Retrieve transport from options.
	o := new(clientOptions)
	assert.FatalError(t, o.apply([]ClientOption{WithTransport(http.DefaultTransport)}))
	tr, err := o.getTransport(srv.URL)
	assert.FatalError(t, err)
	ac := &ACMEClient{
		client: &http.Client{
			Transport: tr,
		},
		dirLoc: srv.URL,
		dir:    &dir,
	}

	tests := map[string]func(t *testing.T) test{
		"fail/GET-nonce": func(t *testing.T) test {
			return test{
				r1:  acme.NewError(acme.ErrorMalformedType, "malformed request"),
				rc1: 400,
				err: errors.New("The request message was malformed"),
			}
		},
		"ok": func(t *testing.T) test {
			return test{
				r1:  []byte{},
				rc1: 200,
			}
		},
	}

	expectedNonce := "abc123"

	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)

			srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				assert.Equals(t, "step-http-client/1.0", req.Header.Get("User-Agent")) // check default User-Agent header
				w.Header().Set("Replay-Nonce", expectedNonce)
				render.JSONStatus(w, tc.r1, tc.rc1)
			})

			if nonce, err := ac.GetNonce(); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, expectedNonce, nonce)
				}
			}
		})
	}
}

func TestACMEClient_post(t *testing.T) {
	type test struct {
		payload  []byte
		Key      *jose.JSONWebKey
		ops      []withHeaderOption
		r1, r2   interface{}
		rc1, rc2 int
		jwkInJWS bool
		client   *ACMEClient
		err      error
	}

	srv := httptest.NewServer(nil)
	defer srv.Close()

	dir := acmeAPI.Directory{
		NewNonce: srv.URL + "/foo",
	}
	// Retrieve transport from options.
	o := new(clientOptions)
	assert.FatalError(t, o.apply([]ClientOption{WithTransport(http.DefaultTransport)}))
	tr, err := o.getTransport(srv.URL)
	assert.FatalError(t, err)
	jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
	assert.FatalError(t, err)
	acc := acme.Account{
		Contact:   []string{"max", "mariano"},
		Status:    "valid",
		OrdersURL: "orders-url",
	}
	ac := &ACMEClient{
		client: &http.Client{
			Transport: tr,
		},
		dirLoc: srv.URL,
		dir:    &dir,
		Key:    jwk,
		kid:    "foobar",
	}

	tests := map[string]func(t *testing.T) test{
		"fail/account-not-configured": func(t *testing.T) test {
			return test{
				client: &ACMEClient{},
				r1:     acme.NewError(acme.ErrorMalformedType, "malformed request"),
				rc1:    400,
				err:    errors.New("acme client not configured with account"),
			}
		},
		"fail/GET-nonce": func(t *testing.T) test {
			return test{
				client: ac,
				r1:     acme.NewError(acme.ErrorMalformedType, "malformed request"),
				rc1:    400,
				err:    errors.New("The request message was malformed"),
			}
		},
		"ok/jwk": func(t *testing.T) test {
			return test{
				client:   ac,
				r1:       []byte{},
				rc1:      200,
				r2:       acc,
				rc2:      200,
				ops:      []withHeaderOption{withJWK(ac)},
				jwkInJWS: true,
			}
		},
		"ok/kid": func(t *testing.T) test {
			return test{
				client: ac,
				r1:     []byte{},
				rc1:    200,
				r2:     acc,
				rc2:    200,
				ops:    []withHeaderOption{withKid(ac)},
			}
		},
	}

	expectedNonce := "abc123"
	url := srv.URL + "/foo"

	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)

			i := 0
			srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				assert.Equals(t, "step-http-client/1.0", req.Header.Get("User-Agent")) // check default User-Agent header

				w.Header().Set("Replay-Nonce", expectedNonce)
				if i == 0 {
					render.JSONStatus(w, tc.r1, tc.rc1)
					i++
					return
				}

				// validate jws request protected headers and body
				body, err := io.ReadAll(req.Body)
				assert.FatalError(t, err)
				jws, err := jose.ParseJWS(string(body))
				assert.FatalError(t, err)
				hdr := jws.Signatures[0].Protected

				assert.Equals(t, hdr.Nonce, expectedNonce)
				jwsURL, ok := hdr.ExtraHeaders["url"].(string)
				assert.Fatal(t, ok)
				assert.Equals(t, jwsURL, url)

				if tc.jwkInJWS {
					assert.Equals(t, hdr.JSONWebKey.KeyID, ac.Key.KeyID)
				} else {
					assert.Equals(t, hdr.KeyID, ac.kid)
				}

				render.JSONStatus(w, tc.r2, tc.rc2)
			})

			if resp, err := tc.client.post(tc.payload, url, tc.ops...); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					var res acme.Account
					assert.FatalError(t, readJSON(resp.Body, &res))
					assert.Equals(t, res, acc)
				}
			}
		})
	}
}

func TestACMEClient_NewOrder(t *testing.T) {
	type test struct {
		ops      []withHeaderOption
		r1, r2   interface{}
		rc1, rc2 int
		err      error
	}

	srv := httptest.NewServer(nil)
	defer srv.Close()

	dir := acmeAPI.Directory{
		NewNonce: srv.URL + "/foo",
		NewOrder: srv.URL + "/bar",
	}
	// Retrieve transport from options.
	o := new(clientOptions)
	assert.FatalError(t, o.apply([]ClientOption{WithTransport(http.DefaultTransport)}))
	tr, err := o.getTransport(srv.URL)
	assert.FatalError(t, err)
	jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
	assert.FatalError(t, err)
	now := time.Now().UTC().Round(time.Second)
	nor := acmeAPI.NewOrderRequest{
		Identifiers: []acme.Identifier{
			{Type: "dns", Value: "example.com"},
			{Type: "dns", Value: "acme.example.com"},
		},
		NotBefore: now,
		NotAfter:  now.Add(time.Minute),
	}
	norb, err := json.Marshal(nor)
	assert.FatalError(t, err)
	ord := acme.Order{
		Status:      "valid",
		ExpiresAt:   now, // "soon"
		FinalizeURL: "finalize-url",
	}
	ac := &ACMEClient{
		client: &http.Client{
			Transport: tr,
		},
		dirLoc: srv.URL,
		dir:    &dir,
		Key:    jwk,
		kid:    "foobar",
	}

	tests := map[string]func(t *testing.T) test{
		"fail/client-post": func(t *testing.T) test {
			return test{
				r1:  acme.NewError(acme.ErrorMalformedType, "malformed request"),
				rc1: 400,
				err: errors.New("The request message was malformed"),
			}
		},
		"fail/newOrder-error": func(t *testing.T) test {
			return test{
				r1:  []byte{},
				rc1: 200,
				r2:  acme.NewError(acme.ErrorMalformedType, "malformed request"),
				rc2: 400,
				ops: []withHeaderOption{withKid(ac)},
				err: errors.New("The request message was malformed"),
			}
		},
		"fail/bad-order": func(t *testing.T) test {
			return test{
				r1:  []byte{},
				rc1: 200,
				r2:  "foo",
				rc2: 200,
				ops: []withHeaderOption{withKid(ac)},
				err: errors.New("error reading http://127.0.0.1"),
			}
		},
		"ok": func(t *testing.T) test {
			return test{
				r1:  []byte{},
				rc1: 200,
				r2:  ord,
				rc2: 200,
				ops: []withHeaderOption{withKid(ac)},
			}
		},
	}

	expectedNonce := "abc123"

	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)

			i := 0
			srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				assert.Equals(t, "step-http-client/1.0", req.Header.Get("User-Agent")) // check default User-Agent header

				w.Header().Set("Replay-Nonce", expectedNonce)
				if i == 0 {
					render.JSONStatus(w, tc.r1, tc.rc1)
					i++
					return
				}

				// validate jws request protected headers and body
				body, err := io.ReadAll(req.Body)
				assert.FatalError(t, err)
				jws, err := jose.ParseJWS(string(body))
				assert.FatalError(t, err)
				hdr := jws.Signatures[0].Protected

				assert.Equals(t, hdr.Nonce, expectedNonce)
				jwsURL, ok := hdr.ExtraHeaders["url"].(string)
				assert.Fatal(t, ok)
				assert.Equals(t, jwsURL, dir.NewOrder)
				assert.Equals(t, hdr.KeyID, ac.kid)

				payload, err := jws.Verify(ac.Key.Public())
				assert.FatalError(t, err)
				assert.Equals(t, payload, norb)

				render.JSONStatus(w, tc.r2, tc.rc2)
			})

			if res, err := ac.NewOrder(norb); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, *res, ord)
				}
			}
		})
	}
}

func TestACMEClient_GetOrder(t *testing.T) {
	type test struct {
		r1, r2   interface{}
		rc1, rc2 int
		err      error
	}

	srv := httptest.NewServer(nil)
	defer srv.Close()

	dir := acmeAPI.Directory{
		NewNonce: srv.URL + "/foo",
	}
	// Retrieve transport from options.
	o := new(clientOptions)
	assert.FatalError(t, o.apply([]ClientOption{WithTransport(http.DefaultTransport)}))
	tr, err := o.getTransport(srv.URL)
	assert.FatalError(t, err)
	jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
	assert.FatalError(t, err)
	ord := acme.Order{
		Status:      "valid",
		ExpiresAt:   time.Now().UTC().Round(time.Second), // "soon"
		FinalizeURL: "finalize-url",
	}
	ac := &ACMEClient{
		client: &http.Client{
			Transport: tr,
		},
		dirLoc: srv.URL,
		dir:    &dir,
		Key:    jwk,
		kid:    "foobar",
	}

	tests := map[string]func(t *testing.T) test{
		"fail/client-post": func(t *testing.T) test {
			return test{
				r1:  acme.NewError(acme.ErrorMalformedType, "malformed request"),
				rc1: 400,
				err: errors.New("The request message was malformed"),
			}
		},
		"fail/getOrder-error": func(t *testing.T) test {
			return test{
				r1:  []byte{},
				rc1: 200,
				r2:  acme.NewError(acme.ErrorMalformedType, "malformed request"),
				rc2: 400,
				err: errors.New("The request message was malformed"),
			}
		},
		"fail/bad-order": func(t *testing.T) test {
			return test{
				r1:  []byte{},
				rc1: 200,
				r2:  "foo",
				rc2: 200,
				err: errors.New("error reading http://127.0.0.1"),
			}
		},
		"ok": func(t *testing.T) test {
			return test{
				r1:  []byte{},
				rc1: 200,
				r2:  ord,
				rc2: 200,
			}
		},
	}

	expectedNonce := "abc123"
	url := srv.URL + "/hullaballoo"

	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)

			i := 0
			srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				assert.Equals(t, "step-http-client/1.0", req.Header.Get("User-Agent")) // check default User-Agent header

				w.Header().Set("Replay-Nonce", expectedNonce)
				if i == 0 {
					render.JSONStatus(w, tc.r1, tc.rc1)
					i++
					return
				}

				// validate jws request protected headers and body
				body, err := io.ReadAll(req.Body)
				assert.FatalError(t, err)
				jws, err := jose.ParseJWS(string(body))
				assert.FatalError(t, err)
				hdr := jws.Signatures[0].Protected

				assert.Equals(t, hdr.Nonce, expectedNonce)
				jwsURL, ok := hdr.ExtraHeaders["url"].(string)
				assert.Fatal(t, ok)
				assert.Equals(t, jwsURL, url)
				assert.Equals(t, hdr.KeyID, ac.kid)

				payload, err := jws.Verify(ac.Key.Public())
				assert.FatalError(t, err)
				assert.Equals(t, len(payload), 0)

				render.JSONStatus(w, tc.r2, tc.rc2)
			})

			if res, err := ac.GetOrder(url); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, *res, ord)
				}
			}
		})
	}
}

func TestACMEClient_GetAuthz(t *testing.T) {
	type test struct {
		r1, r2   interface{}
		rc1, rc2 int
		err      error
	}

	srv := httptest.NewServer(nil)
	defer srv.Close()

	dir := acmeAPI.Directory{
		NewNonce: srv.URL + "/foo",
	}
	// Retrieve transport from options.
	o := new(clientOptions)
	assert.FatalError(t, o.apply([]ClientOption{WithTransport(http.DefaultTransport)}))
	tr, err := o.getTransport(srv.URL)
	assert.FatalError(t, err)
	jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
	assert.FatalError(t, err)
	az := acme.Authorization{
		Status:     "valid",
		ExpiresAt:  time.Now().UTC().Round(time.Second),
		Identifier: acme.Identifier{Type: "dns", Value: "example.com"},
	}
	ac := &ACMEClient{
		client: &http.Client{
			Transport: tr,
		},
		dirLoc: srv.URL,
		dir:    &dir,
		Key:    jwk,
		kid:    "foobar",
	}

	tests := map[string]func(t *testing.T) test{
		"fail/client-post": func(t *testing.T) test {
			return test{
				r1:  acme.NewError(acme.ErrorMalformedType, "malformed request"),
				rc1: 400,
				err: errors.New("The request message was malformed"),
			}
		},
		"fail/getChallenge-error": func(t *testing.T) test {
			return test{
				r1:  []byte{},
				rc1: 200,
				r2:  acme.NewError(acme.ErrorMalformedType, "malformed request"),
				rc2: 400,
				err: errors.New("The request message was malformed"),
			}
		},
		"fail/bad-challenge": func(t *testing.T) test {
			return test{
				r1:  []byte{},
				rc1: 200,
				r2:  "foo",
				rc2: 200,
				err: errors.New("error reading http://127.0.0.1"),
			}
		},
		"ok": func(t *testing.T) test {
			return test{
				r1:  []byte{},
				rc1: 200,
				r2:  az,
				rc2: 200,
			}
		},
	}

	expectedNonce := "abc123"
	url := srv.URL + "/hullaballoo"

	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)

			i := 0
			srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				assert.Equals(t, "step-http-client/1.0", req.Header.Get("User-Agent")) // check default User-Agent header

				w.Header().Set("Replay-Nonce", expectedNonce)
				if i == 0 {
					render.JSONStatus(w, tc.r1, tc.rc1)
					i++
					return
				}

				// validate jws request protected headers and body
				body, err := io.ReadAll(req.Body)
				assert.FatalError(t, err)
				jws, err := jose.ParseJWS(string(body))
				assert.FatalError(t, err)
				hdr := jws.Signatures[0].Protected

				assert.Equals(t, hdr.Nonce, expectedNonce)
				jwsURL, ok := hdr.ExtraHeaders["url"].(string)
				assert.Fatal(t, ok)
				assert.Equals(t, jwsURL, url)
				assert.Equals(t, hdr.KeyID, ac.kid)

				payload, err := jws.Verify(ac.Key.Public())
				assert.FatalError(t, err)
				assert.Equals(t, len(payload), 0)

				render.JSONStatus(w, tc.r2, tc.rc2)
			})

			if res, err := ac.GetAuthz(url); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, *res, az)
				}
			}
		})
	}
}

func TestACMEClient_GetChallenge(t *testing.T) {
	type test struct {
		r1, r2   interface{}
		rc1, rc2 int
		err      error
	}

	srv := httptest.NewServer(nil)
	defer srv.Close()

	dir := acmeAPI.Directory{
		NewNonce: srv.URL + "/foo",
	}
	// Retrieve transport from options.
	o := new(clientOptions)
	assert.FatalError(t, o.apply([]ClientOption{WithTransport(http.DefaultTransport)}))
	tr, err := o.getTransport(srv.URL)
	assert.FatalError(t, err)
	jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
	assert.FatalError(t, err)
	ch := acme.Challenge{
		Type:   "http-01",
		Status: "valid",
		Token:  "foo",
	}
	ac := &ACMEClient{
		client: &http.Client{
			Transport: tr,
		},
		dirLoc: srv.URL,
		dir:    &dir,
		Key:    jwk,
		kid:    "foobar",
	}

	tests := map[string]func(t *testing.T) test{
		"fail/client-post": func(t *testing.T) test {
			return test{
				r1:  acme.NewError(acme.ErrorMalformedType, "malformed request"),
				rc1: 400,
				err: errors.New("The request message was malformed"),
			}
		},
		"fail/getChallenge-error": func(t *testing.T) test {
			return test{
				r1:  []byte{},
				rc1: 200,
				r2:  acme.NewError(acme.ErrorMalformedType, "malformed request"),
				rc2: 400,
				err: errors.New("The request message was malformed"),
			}
		},
		"fail/bad-challenge": func(t *testing.T) test {
			return test{
				r1:  []byte{},
				rc1: 200,
				r2:  "foo",
				rc2: 200,
				err: errors.New("error reading http://127.0.0.1"),
			}
		},
		"ok": func(t *testing.T) test {
			return test{
				r1:  []byte{},
				rc1: 200,
				r2:  ch,
				rc2: 200,
			}
		},
	}

	expectedNonce := "abc123"
	url := srv.URL + "/hullaballoo"

	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)

			i := 0
			srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				assert.Equals(t, "step-http-client/1.0", req.Header.Get("User-Agent")) // check default User-Agent header

				w.Header().Set("Replay-Nonce", expectedNonce)
				if i == 0 {
					render.JSONStatus(w, tc.r1, tc.rc1)
					i++
					return
				}

				// validate jws request protected headers and body
				body, err := io.ReadAll(req.Body)
				assert.FatalError(t, err)
				jws, err := jose.ParseJWS(string(body))
				assert.FatalError(t, err)
				hdr := jws.Signatures[0].Protected

				assert.Equals(t, hdr.Nonce, expectedNonce)
				jwsURL, ok := hdr.ExtraHeaders["url"].(string)
				assert.Fatal(t, ok)
				assert.Equals(t, jwsURL, url)
				assert.Equals(t, hdr.KeyID, ac.kid)

				payload, err := jws.Verify(ac.Key.Public())
				assert.FatalError(t, err)

				assert.Equals(t, len(payload), 0)

				render.JSONStatus(w, tc.r2, tc.rc2)
			})

			if res, err := ac.GetChallenge(url); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, *res, ch)
				}
			}
		})
	}
}

func TestACMEClient_ValidateChallenge(t *testing.T) {
	type test struct {
		r1, r2   interface{}
		rc1, rc2 int
		err      error
	}

	srv := httptest.NewServer(nil)
	defer srv.Close()

	dir := acmeAPI.Directory{
		NewNonce: srv.URL + "/foo",
	}
	// Retrieve transport from options.
	o := new(clientOptions)
	assert.FatalError(t, o.apply([]ClientOption{WithTransport(http.DefaultTransport)}))
	tr, err := o.getTransport(srv.URL)
	assert.FatalError(t, err)
	jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
	assert.FatalError(t, err)
	ch := acme.Challenge{
		Type:   "http-01",
		Status: "valid",
		Token:  "foo",
	}
	ac := &ACMEClient{
		client: &http.Client{
			Transport: tr,
		},
		dirLoc: srv.URL,
		dir:    &dir,
		Key:    jwk,
		kid:    "foobar",
	}

	tests := map[string]func(t *testing.T) test{
		"fail/client-post": func(t *testing.T) test {
			return test{
				r1:  acme.NewError(acme.ErrorMalformedType, "malformed request"),
				rc1: 400,
				err: errors.New("The request message was malformed"),
			}
		},
		"fail/getChallenge-error": func(t *testing.T) test {
			return test{
				r1:  []byte{},
				rc1: 200,
				r2:  acme.NewError(acme.ErrorMalformedType, "malformed request"),
				rc2: 400,
				err: errors.New("The request message was malformed"),
			}
		},
		"fail/bad-challenge": func(t *testing.T) test {
			return test{
				r1:  []byte{},
				rc1: 200,
				r2:  "foo",
				rc2: 200,
				err: errors.New("error reading http://127.0.0.1"),
			}
		},
		"ok": func(t *testing.T) test {
			return test{
				r1:  []byte{},
				rc1: 200,
				r2:  ch,
				rc2: 200,
			}
		},
	}

	expectedNonce := "abc123"
	url := srv.URL + "/hullaballoo"

	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)

			i := 0
			srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				assert.Equals(t, "step-http-client/1.0", req.Header.Get("User-Agent")) // check default User-Agent header

				w.Header().Set("Replay-Nonce", expectedNonce)
				if i == 0 {
					render.JSONStatus(w, tc.r1, tc.rc1)
					i++
					return
				}

				// validate jws request protected headers and body
				body, err := io.ReadAll(req.Body)
				assert.FatalError(t, err)
				jws, err := jose.ParseJWS(string(body))
				assert.FatalError(t, err)
				hdr := jws.Signatures[0].Protected

				assert.Equals(t, hdr.Nonce, expectedNonce)
				jwsURL, ok := hdr.ExtraHeaders["url"].(string)
				assert.Fatal(t, ok)
				assert.Equals(t, jwsURL, url)
				assert.Equals(t, hdr.KeyID, ac.kid)

				payload, err := jws.Verify(ac.Key.Public())
				assert.FatalError(t, err)

				assert.Equals(t, payload, []byte("{}"))

				render.JSONStatus(w, tc.r2, tc.rc2)
			})

			if err := ac.ValidateChallenge(url); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			}
		})
	}
}

func TestACMEClient_ValidateWithPayload(t *testing.T) {
	key, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
	assert.FatalError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		assert.Equals(t, "step-http-client/1.0", req.Header.Get("User-Agent")) // check default User-Agent header

		t.Log(req.RequestURI)
		w.Header().Set("Replay-Nonce", "nonce")
		switch req.RequestURI {
		case "/nonce":
			render.JSONStatus(w, []byte{}, 200)
			return
		case "/fail-nonce":
			render.JSONStatus(w, acme.NewError(acme.ErrorMalformedType, "malformed request"), 400)
			return
		}

		// validate jws request protected headers and body
		body, err := io.ReadAll(req.Body)
		assert.FatalError(t, err)

		jws, err := jose.ParseJWS(string(body))
		assert.FatalError(t, err)

		hdr := jws.Signatures[0].Protected
		assert.Equals(t, hdr.Nonce, "nonce")

		_, ok := hdr.ExtraHeaders["url"].(string)
		assert.Fatal(t, ok)
		assert.Equals(t, hdr.KeyID, "kid")

		payload, err := jws.Verify(key.Public())
		assert.FatalError(t, err)
		assert.Equals(t, payload, []byte("the-payload"))

		switch req.RequestURI {
		case "/ok":
			render.JSONStatus(w, acme.Challenge{
				Type:   "device-attestation-01",
				Status: "valid",
				Token:  "foo",
			}, 200)
		case "/fail":
			render.JSONStatus(w, acme.NewError(acme.ErrorMalformedType, "malformed request"), 400)
		}
	}))
	defer srv.Close()

	type fields struct {
		client *http.Client
		dirLoc string
		dir    *acmeAPI.Directory
		acc    *acme.Account
		Key    *jose.JSONWebKey
		kid    string
	}
	type args struct {
		url     string
		payload []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{"ok", fields{srv.Client(), srv.URL, &acmeAPI.Directory{
			NewNonce: srv.URL + "/nonce",
		}, nil, key, "kid"}, args{srv.URL + "/ok", []byte("the-payload")}, false},
		{"fail nonce", fields{srv.Client(), srv.URL, &acmeAPI.Directory{
			NewNonce: srv.URL + "/fail-nonce",
		}, nil, key, "kid"}, args{srv.URL + "/ok", []byte("the-payload")}, true},
		{"fail payload", fields{srv.Client(), srv.URL, &acmeAPI.Directory{
			NewNonce: srv.URL + "/nonce",
		}, nil, key, "kid"}, args{srv.URL + "/fail", []byte("the-payload")}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &ACMEClient{
				client: tt.fields.client,
				dirLoc: tt.fields.dirLoc,
				dir:    tt.fields.dir,
				acc:    tt.fields.acc,
				Key:    tt.fields.Key,
				kid:    tt.fields.kid,
			}
			if err := c.ValidateWithPayload(tt.args.url, tt.args.payload); (err != nil) != tt.wantErr {
				t.Errorf("ACMEClient.ValidateWithPayload() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestACMEClient_FinalizeOrder(t *testing.T) {
	type test struct {
		r1, r2   interface{}
		rc1, rc2 int
		err      error
	}

	srv := httptest.NewServer(nil)
	defer srv.Close()

	dir := acmeAPI.Directory{
		NewNonce: srv.URL + "/foo",
	}
	// Retrieve transport from options.
	o := new(clientOptions)
	assert.FatalError(t, o.apply([]ClientOption{WithTransport(http.DefaultTransport)}))
	tr, err := o.getTransport(srv.URL)
	assert.FatalError(t, err)
	jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
	assert.FatalError(t, err)
	ord := acme.Order{
		Status:         "valid",
		ExpiresAt:      time.Now(), // "soon"
		FinalizeURL:    "finalize-url",
		CertificateURL: "cert-url",
	}
	_csr, err := pemutil.Read("../authority/testdata/certs/foo.csr")
	assert.FatalError(t, err)
	csr, ok := _csr.(*x509.CertificateRequest)
	assert.Fatal(t, ok)
	fr := acmeAPI.FinalizeRequest{CSR: base64.RawURLEncoding.EncodeToString(csr.Raw)}
	frb, err := json.Marshal(fr)
	assert.FatalError(t, err)
	ac := &ACMEClient{
		client: &http.Client{
			Transport: tr,
		},
		dirLoc: srv.URL,
		dir:    &dir,
		Key:    jwk,
		kid:    "foobar",
	}

	tests := map[string]func(t *testing.T) test{
		"fail/client-post": func(t *testing.T) test {
			return test{
				r1:  acme.NewError(acme.ErrorMalformedType, "malformed request"),
				rc1: 400,
				err: errors.New("The request message was malformed"),
			}
		},
		"fail/finalizeOrder-error": func(t *testing.T) test {
			return test{
				r1:  []byte{},
				rc1: 200,
				r2:  acme.NewError(acme.ErrorMalformedType, "malformed request"),
				rc2: 400,
				err: errors.New("The request message was malformed"),
			}
		},
		"fail/bad-order": func(t *testing.T) test {
			return test{
				r1:  []byte{},
				rc1: 200,
				r2:  "foo",
				rc2: 200,
				err: errors.New("error reading http://127.0.0.1"),
			}
		},
		"ok": func(t *testing.T) test {
			return test{
				r1:  []byte{},
				rc1: 200,
				r2:  ord,
				rc2: 200,
			}
		},
	}

	expectedNonce := "abc123"
	url := srv.URL + "/hullaballoo"

	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)

			i := 0
			srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				assert.Equals(t, "step-http-client/1.0", req.Header.Get("User-Agent")) // check default User-Agent header

				w.Header().Set("Replay-Nonce", expectedNonce)
				if i == 0 {
					render.JSONStatus(w, tc.r1, tc.rc1)
					i++
					return
				}

				// validate jws request protected headers and body
				body, err := io.ReadAll(req.Body)
				assert.FatalError(t, err)
				jws, err := jose.ParseJWS(string(body))
				assert.FatalError(t, err)
				hdr := jws.Signatures[0].Protected

				assert.Equals(t, hdr.Nonce, expectedNonce)
				jwsURL, ok := hdr.ExtraHeaders["url"].(string)
				assert.Fatal(t, ok)
				assert.Equals(t, jwsURL, url)
				assert.Equals(t, hdr.KeyID, ac.kid)

				payload, err := jws.Verify(ac.Key.Public())
				assert.FatalError(t, err)
				assert.Equals(t, payload, frb)

				render.JSONStatus(w, tc.r2, tc.rc2)
			})

			if err := ac.FinalizeOrder(url, csr); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			}
		})
	}
}

func TestACMEClient_GetAccountOrders(t *testing.T) {
	type test struct {
		r1, r2   interface{}
		rc1, rc2 int
		err      error
		client   *ACMEClient
	}

	srv := httptest.NewServer(nil)
	defer srv.Close()

	dir := acmeAPI.Directory{
		NewNonce: srv.URL + "/foo",
	}
	// Retrieve transport from options.
	o := new(clientOptions)
	assert.FatalError(t, o.apply([]ClientOption{WithTransport(http.DefaultTransport)}))
	tr, err := o.getTransport(srv.URL)
	assert.FatalError(t, err)
	jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
	assert.FatalError(t, err)
	orders := []string{"foo", "bar", "baz"}
	ac := &ACMEClient{
		client: &http.Client{
			Transport: tr,
		},
		dirLoc: srv.URL,
		dir:    &dir,
		Key:    jwk,
		kid:    "foobar",
		acc: &acme.Account{
			Contact:   []string{"max", "mariano"},
			Status:    "valid",
			OrdersURL: srv.URL + "/orders-url",
		},
	}

	tests := map[string]func(t *testing.T) test{
		"fail/account-not-configured": func(t *testing.T) test {
			return test{
				client: &ACMEClient{},
				err:    errors.New("acme client not configured with account"),
			}
		},
		"fail/client-post": func(t *testing.T) test {
			return test{
				client: ac,
				r1:     acme.NewError(acme.ErrorMalformedType, "malformed request"),
				rc1:    400,
				err:    errors.New("The request message was malformed"),
			}
		},
		"fail/getAccountOrders-error": func(t *testing.T) test {
			return test{
				client: ac,
				r1:     []byte{},
				rc1:    200,
				r2:     acme.NewError(acme.ErrorMalformedType, "malformed request"),
				rc2:    400,
				err:    errors.New("The request message was malformed"),
			}
		},
		"fail/bad-accountOrders": func(t *testing.T) test {
			return test{
				client: ac,
				r1:     []byte{},
				rc1:    200,
				r2:     "foo",
				rc2:    200,
				err:    errors.New("error reading http://127.0.0.1"),
			}
		},
		"ok": func(t *testing.T) test {
			return test{
				client: ac,
				r1:     []byte{},
				rc1:    200,
				r2:     orders,
				rc2:    200,
			}
		},
	}

	expectedNonce := "abc123"

	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)

			i := 0
			srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				assert.Equals(t, "step-http-client/1.0", req.Header.Get("User-Agent")) // check default User-Agent header

				w.Header().Set("Replay-Nonce", expectedNonce)
				if i == 0 {
					render.JSONStatus(w, tc.r1, tc.rc1)
					i++
					return
				}

				// validate jws request protected headers and body
				body, err := io.ReadAll(req.Body)
				assert.FatalError(t, err)
				jws, err := jose.ParseJWS(string(body))
				assert.FatalError(t, err)
				hdr := jws.Signatures[0].Protected

				assert.Equals(t, hdr.Nonce, expectedNonce)
				jwsURL, ok := hdr.ExtraHeaders["url"].(string)
				assert.Fatal(t, ok)
				assert.Equals(t, jwsURL, ac.acc.OrdersURL)
				assert.Equals(t, hdr.KeyID, ac.kid)

				payload, err := jws.Verify(ac.Key.Public())
				assert.FatalError(t, err)
				assert.Equals(t, len(payload), 0)

				render.JSONStatus(w, tc.r2, tc.rc2)
			})

			if res, err := tc.client.GetAccountOrders(); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, res, orders)
				}
			}
		})
	}
}

func TestACMEClient_GetCertificate(t *testing.T) {
	type test struct {
		r1, r2    interface{}
		certBytes []byte
		rc1, rc2  int
		err       error
	}

	srv := httptest.NewServer(nil)
	defer srv.Close()

	dir := acmeAPI.Directory{
		NewNonce: srv.URL + "/foo",
	}
	// Retrieve transport from options.
	o := new(clientOptions)
	assert.FatalError(t, o.apply([]ClientOption{WithTransport(http.DefaultTransport)}))
	tr, err := o.getTransport(srv.URL)
	assert.FatalError(t, err)
	jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
	assert.FatalError(t, err)
	leaf, err := pemutil.ReadCertificate("../authority/testdata/certs/foo.crt")
	assert.FatalError(t, err)
	leafb := pem.EncodeToMemory(&pem.Block{
		Type:  "Certificate",
		Bytes: leaf.Raw,
	})
	//nolint:gocritic
	certBytes := append(leafb, leafb...)
	certBytes = append(certBytes, leafb...)
	ac := &ACMEClient{
		client: &http.Client{
			Transport: tr,
		},
		dirLoc: srv.URL,
		dir:    &dir,
		Key:    jwk,
		kid:    "foobar",
		acc: &acme.Account{
			Contact:   []string{"max", "mariano"},
			Status:    "valid",
			OrdersURL: srv.URL + "/orders-url",
		},
	}

	tests := map[string]func(t *testing.T) test{
		"fail/client-post": func(t *testing.T) test {
			return test{
				r1:  acme.NewError(acme.ErrorMalformedType, "malformed request"),
				rc1: 400,
				err: errors.New("The request message was malformed"),
			}
		},
		"fail/getAccountOrders-error": func(t *testing.T) test {
			return test{
				r1:  []byte{},
				rc1: 200,
				r2:  acme.NewError(acme.ErrorMalformedType, "malformed request"),
				rc2: 400,
				err: errors.New("The request message was malformed"),
			}
		},
		"fail/bad-certificate": func(t *testing.T) test {
			return test{
				r1:  []byte{},
				rc1: 200,
				r2:  "foo",
				rc2: 200,
				err: errors.New("failed to parse any certificates from response"),
			}
		},
		"ok": func(t *testing.T) test {
			return test{
				r1:        []byte{},
				rc1:       200,
				certBytes: certBytes,
			}
		},
	}

	expectedNonce := "abc123"
	url := srv.URL + "/cert/foo"

	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)

			i := 0
			srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				assert.Equals(t, "step-http-client/1.0", req.Header.Get("User-Agent")) // check default User-Agent header

				w.Header().Set("Replay-Nonce", expectedNonce)
				if i == 0 {
					render.JSONStatus(w, tc.r1, tc.rc1)
					i++
					return
				}

				// validate jws request protected headers and body
				body, err := io.ReadAll(req.Body)
				assert.FatalError(t, err)
				jws, err := jose.ParseJWS(string(body))
				assert.FatalError(t, err)
				hdr := jws.Signatures[0].Protected

				assert.Equals(t, hdr.Nonce, expectedNonce)
				jwsURL, ok := hdr.ExtraHeaders["url"].(string)
				assert.Fatal(t, ok)
				assert.Equals(t, jwsURL, url)
				assert.Equals(t, hdr.KeyID, ac.kid)

				payload, err := jws.Verify(ac.Key.Public())
				assert.FatalError(t, err)
				assert.Equals(t, len(payload), 0)

				if tc.certBytes != nil {
					w.Write(tc.certBytes)
				} else {
					render.JSONStatus(w, tc.r2, tc.rc2)
				}
			})

			if crt, chain, err := ac.GetCertificate(url); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, crt, leaf)
					assert.Equals(t, chain, []*x509.Certificate{leaf, leaf})
				}
			}
		})
	}
}
